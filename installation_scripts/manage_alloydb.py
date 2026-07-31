#!/usr/bin/env python3
"""
AlloyDB Database Manager for Security Operations Detection Reports

This script manages AlloyDB/PostgreSQL operations including schema initialization,
ingestion of harvested detection reports, vector embeddings with Vertex AI pgvector,
hybrid full-text & semantic vector search, and database administration.
"""

import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

app = typer.Typer(
    add_completion=False,
    help="Manage AlloyDB/PostgreSQL database and pgvector embeddings for Google SecOps Detection Reports.",
)
console = Console()

# Predefined Multi-Modal Similarity Scoring Profiles for SOC Workflows
SIMILARITY_PROFILES: dict[str, dict[str, Any]] = {
    "balanced": {
        "name": "Balanced Alert Triage",
        "description": "Standard multi-modal blend across all 5 dimensions for routine triage and verdict checking.",
        "weights": {
            "semantic": 0.35,
            "entity": 0.30,
            "ttp": 0.20,
            "flow": 0.10,
            "time": 0.05,
        },
    },
    "threat-hunt": {
        "name": "Threat Actor & Campaign Hunting",
        "description": "Biases for shared MITRE TTPs and semantic attack tradecraft across multiple or disparate hosts.",
        "weights": {
            "ttp": 0.45,
            "semantic": 0.35,
            "flow": 0.10,
            "time": 0.05,
            "entity": 0.05,
        },
    },
    "compromise-pivot": {
        "name": "Compromise Blast Radius & Lateral Movement",
        "description": "Biases heavily for compromised hosts/users/IPs and temporal proximity to detect lateral movement.",
        "weights": {
            "entity": 0.45,
            "time": 0.30,
            "semantic": 0.15,
            "flow": 0.05,
            "ttp": 0.05,
        },
    },
    "false-positive": {
        "name": "False Positive Triage & Precedent",
        "description": "Biases for exact entity matches, binary hashes, and matching detection rules to identify recurring benign noise.",
        "weights": {
            "entity": 0.40,
            "ttp": 0.25,
            "semantic": 0.20,
            "flow": 0.10,
            "time": 0.05,
        },
    },
    "semantic": {
        "name": "Semantic & Behavioral Concept Discovery",
        "description": "Biases for dense vector cosine similarity to discover conceptually related attacks regardless of specific entities.",
        "weights": {
            "semantic": 0.60,
            "flow": 0.15,
            "ttp": 0.15,
            "entity": 0.05,
            "time": 0.05,
        },
    },
}


class AlloyDBManager:
    """Manages connection, schema setup, ingestion, and vector embeddings for AlloyDB/PostgreSQL."""

    def __init__(self, env_file: Path | None = None):
        self.env_file = env_file or Path(".env")
        self.env_vars = self._load_env_vars()
        self.project_root = Path.cwd()

        self.host = self.env_vars.get("ALLOYDB_HOST", "localhost")
        self.port = int(self.env_vars.get("ALLOYDB_PORT", "5432"))
        self.database = self.env_vars.get("ALLOYDB_DATABASE", "secops")
        self.user = self.env_vars.get("ALLOYDB_USER", "postgres")
        self.password = self.env_vars.get("ALLOYDB_PASSWORD", "password")
        self.instance_uri = self.env_vars.get("ALLOYDB_INSTANCE_URI")
        self.sslmode = self.env_vars.get("ALLOYDB_SSLMODE", "prefer")
        self.investigations_dir = self.project_root / "investigations"

        # GCP & Vertex AI settings
        self.project_id = self.env_vars.get("GCP_PROJECT_ID", "secops-demo-env")
        self.location = self.env_vars.get("GCP_LOCATION", "us-central1")
        self.sa_path = (
            self.env_vars.get("SECOPS_SA_PATH")
            or self.env_vars.get("CHRONICLE_SERVICE_ACCOUNT_PATH")
            or self.env_vars.get("GOOGLE_APPLICATION_CREDENTIALS")
        )
        self._vertexai_initialized = False
        self._embedding_model = None

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def _init_vertex_ai(self) -> None:
        """Initialize Vertex AI for text-embedding-004."""
        if self._vertexai_initialized:
            return

        if self.sa_path and os.path.exists(self.sa_path):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.sa_path

        try:
            import vertexai
            from vertexai.language_models import TextEmbeddingModel

            vertexai.init(project=self.project_id, location=self.location)
            self._embedding_model = TextEmbeddingModel.from_pretrained(
                "text-embedding-004"
            )
            self._vertexai_initialized = True
        except Exception as e:
            console.print(
                f"[red]Failed to initialize Vertex AI embedding model: {e}[/red]"
            )
            raise

    def get_embedding(
        self, text: str, task_type: str = "RETRIEVAL_QUERY"
    ) -> list[float]:
        """Generate a 768-dimensional embedding for a single text query."""
        self._init_vertex_ai()
        from vertexai.language_models import TextEmbeddingInput

        # Truncate text safely to 3500 characters (~800 tokens)
        truncated_text = text[:3500]
        inputs = [TextEmbeddingInput(truncated_text, task_type)]
        embeddings = self._embedding_model.get_embeddings(inputs)
        return embeddings[0].values

    def get_embeddings_batch(
        self,
        texts: list[str],
        task_type: str = "RETRIEVAL_DOCUMENT",
        chunk_size: int = 10,
    ) -> list[list[float]]:
        """Generate 768-dimensional embeddings for documents with automatic sub-batching and fallback."""
        self._init_vertex_ai()
        from vertexai.language_models import TextEmbeddingInput

        all_embeddings: list[list[float]] = []

        # Process in safe chunks of up to 10 texts to never exceed Vertex AI batch token limit
        for i in range(0, len(texts), chunk_size):
            chunk = texts[i : i + chunk_size]
            inputs = [TextEmbeddingInput(t[:3500], task_type) for t in chunk]
            try:
                embs = self._embedding_model.get_embeddings(inputs)
                all_embeddings.extend([e.values for e in embs])
            except Exception as batch_err:
                # Fall back to single-item generation if a chunk exceeds limits
                console.print(
                    f"[yellow]Chunk batching notice ({batch_err}), falling back to single items...[/yellow]"
                )
                for item_text in chunk:
                    try:
                        single_input = [TextEmbeddingInput(item_text[:2500], task_type)]
                        single_emb = self._embedding_model.get_embeddings(single_input)
                        all_embeddings.append(single_emb[0].values)
                    except Exception as single_err:
                        console.print(
                            f"[red]Error embedding document: {single_err}[/red]"
                        )
                        all_embeddings.append([0.0] * 768)

        return all_embeddings

    def get_connection(self, dbname: str | None = None) -> Any:
        """Create and return a psycopg database connection."""
        if psycopg is None:
            raise RuntimeError(
                "psycopg is not installed. Install via: pip install 'psycopg[binary]'"
            )

        target_db = dbname or self.database

        # If AlloyDB instance URI is specified and connector is explicitly enabled, use google-cloud-alloydb-connector
        use_connector = os.environ.get("ALLOYDB_USE_CONNECTOR", "False").lower() in (
            "true",
            "1",
            "yes",
        )
        if self.instance_uri and use_connector:
            try:
                from google.cloud.alloydb.connector import Connector

                connector = Connector()
                conn = connector.connect(
                    self.instance_uri,
                    "psycopg",
                    user=self.user,
                    password=self.password,
                    db=target_db,
                    autocommit=False,
                )
                return conn
            except Exception as e:
                console.print(
                    f"[yellow]AlloyDB Connector failed ({e}), falling back to direct connection...[/yellow]"
                )

        conn_params = {
            "host": self.host,
            "port": self.port,
            "dbname": target_db,
            "user": self.user,
            "password": self.password,
            "sslmode": self.sslmode,
            "autocommit": False,
        }
        return psycopg.connect(**conn_params)

    def test_connection(self) -> bool:
        """Test connectivity to the AlloyDB/PostgreSQL database."""
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute("SELECT version() AS ver, current_database() AS db;")
                    row = cur.fetchone()
                    if row:
                        console.print("[green]Connection successful![/green]")
                        console.print(f"Database: [bold]{row['db']}[/bold]")
                        console.print(f"Server Version: {row['ver']}")
                        return True
            return False
        except Exception as e:
            console.print(f"[red]Database connection failed: {e}[/red]")
            return False

    def ensure_database_exists(self) -> None:
        """Ensure the target database exists; create it if connecting to maintenance DB."""
        try:
            with self.get_connection(dbname="postgres") as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM pg_database WHERE datname = %s;",
                        (self.database,),
                    )
                    if not cur.fetchone():
                        console.print(
                            f"[blue]Database '{self.database}' does not exist. Creating...[/blue]"
                        )
                        db_clean = re.sub(r"[^a-zA-Z0-9_]", "", self.database)
                        cur.execute(f'CREATE DATABASE "{db_clean}";')
                        console.print(
                            f"[green]Database '{db_clean}' created successfully.[/green]"
                        )
        except Exception as e:
            console.print(f"[yellow]Database verification notice: {e}[/yellow]")

    def init_schema(self, recreate: bool = False) -> None:
        """Initialize relational tables, JSONB structures, vector extension, and indexes."""
        self.ensure_database_exists()

        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # 1. Enable extensions (uuid-ossp, pg_trgm, vector)
                for ext in ["uuid-ossp", "pg_trgm", "vector"]:
                    try:
                        cur.execute(f'CREATE EXTENSION IF NOT EXISTS "{ext}";')
                    except Exception as e:
                        conn.rollback()
                        console.print(
                            f"[yellow]Notice on extension '{ext}': {e}[/yellow]"
                        )

                if recreate:
                    console.print(
                        "[yellow]Dropping existing detection reports tables...[/yellow]"
                    )
                    cur.execute("DROP TABLE IF EXISTS detection_entities CASCADE;")
                    cur.execute("DROP TABLE IF EXISTS detection_alerts CASCADE;")
                    cur.execute("DROP TABLE IF EXISTS detection_reports CASCADE;")

                # 2. Main detection reports table with vector(768) embedding column
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS detection_reports (
                        id VARCHAR(64) PRIMARY KEY,
                        name TEXT,
                        display_name TEXT NOT NULL,
                        verdict VARCHAR(32) NOT NULL,
                        confidence VARCHAR(32),
                        status VARCHAR(64),
                        trigger_type VARCHAR(64),
                        start_time TIMESTAMPTZ,
                        end_time TIMESTAMPTZ,
                        publish_time TIMESTAMPTZ,
                        update_time TIMESTAMPTZ,
                        summary TEXT,
                        notebook_uri TEXT,
                        alert_ids TEXT[] DEFAULT '{}',
                        investigation_steps JSONB DEFAULT '[]',
                        next_steps JSONB DEFAULT '[]',
                        entities JSONB DEFAULT '[]',
                        markdown_report TEXT,
                        raw_json JSONB,
                        embedding vector(768),
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )

                # Ensure embedding column exists if table was already created
                try:
                    cur.execute(
                        "ALTER TABLE detection_reports ADD COLUMN IF NOT EXISTS embedding vector(768);"
                    )
                except Exception:
                    conn.rollback()

                # 3. Detection Alerts table (relational link)
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS detection_alerts (
                        id SERIAL PRIMARY KEY,
                        alert_id VARCHAR(128) NOT NULL,
                        investigation_id VARCHAR(64) REFERENCES detection_reports(id) ON DELETE CASCADE,
                        display_name TEXT,
                        severity VARCHAR(32),
                        rule_description TEXT,
                        mitre_tactics TEXT[] DEFAULT '{}',
                        mitre_techniques TEXT[] DEFAULT '{}',
                        raw_json JSONB,
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )

                # 4. Detection Entities table (relational link)
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS detection_entities (
                        id SERIAL PRIMARY KEY,
                        investigation_id VARCHAR(64) REFERENCES detection_reports(id) ON DELETE CASCADE,
                        entity_type VARCHAR(32) NOT NULL,
                        entity_value TEXT NOT NULL,
                        context TEXT,
                        threat_intel JSONB DEFAULT '{}',
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )

                # 5. Indexes for fast retrieval
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_reports_verdict ON detection_reports(verdict);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_reports_confidence ON detection_reports(confidence);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_reports_publish_time ON detection_reports(publish_time);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_reports_alert_ids ON detection_reports USING GIN(alert_ids);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_reports_entities ON detection_reports USING GIN(entities);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_reports_raw_json ON detection_reports USING GIN(raw_json);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_reports_fts ON detection_reports USING GIN(to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '')));"
                )

                # HNSW vector index for pgvector cosine distance
                try:
                    cur.execute(
                        """
                        CREATE INDEX IF NOT EXISTS idx_detection_reports_embedding_hnsw
                        ON detection_reports USING hnsw (embedding vector_cosine_ops);
                        """
                    )
                except Exception as e:
                    conn.rollback()
                    console.print(
                        f"[yellow]Notice on vector index creation: {e}[/yellow]"
                    )

                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_alerts_alert_id ON detection_alerts(alert_id);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_alerts_investigation_id ON detection_alerts(investigation_id);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_entities_val ON detection_entities(entity_type, entity_value);"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detection_entities_inv ON detection_entities(investigation_id);"
                )

                conn.commit()
                console.print(
                    "[green]AlloyDB schema, pgvector vector(768) column, and indexes successfully initialized.[/green]"
                )

    def parse_markdown_report(
        self, md_path: Path
    ) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
        """Parse markdown report to extract raw content, alerts, and enriched entities."""
        if not md_path.exists():
            return "", [], []

        content = md_path.read_text(encoding="utf-8")

        # Extract entities from markdown table: | `HOST` | `wins-d19` | Context |
        entities: list[dict[str, Any]] = []
        seen_entities: set[tuple[str, str]] = set()
        table_matches = re.findall(
            r"\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*([^|]+)\|", content
        )
        for etype, evalue, ctx in table_matches:
            etype_clean = etype.strip().upper()
            evalue_clean = evalue.strip()
            key = (etype_clean, evalue_clean)
            if key not in seen_entities:
                seen_entities.add(key)
                entities.append(
                    {
                        "type": etype_clean,
                        "value": evalue_clean,
                        "context": ctx.strip(),
                    }
                )

        # Extract alerts from markdown sections: ### Alert: `de_...` (Display Name)
        alerts: list[dict[str, Any]] = []
        alert_blocks = re.split(r"###\s*Alert:\s*", content)
        for block in alert_blocks[1:]:
            header_match = re.match(r"`([^`]+)`\s*(?:\(([^)]*)\))?", block)
            if header_match:
                alert_id = header_match.group(1).strip()
                alert_name = (header_match.group(2) or "").strip()

                sev_match = re.search(r"-\s*\*\*Severity\*\*:\s*`([^`]+)`", block)
                severity = sev_match.group(1).strip() if sev_match else None

                desc_match = re.search(
                    r"-\s*\*\*Rule Description\*\*:\s*([^\n]+)", block
                )
                rule_desc = desc_match.group(1).strip() if desc_match else None

                tactics = re.findall(r"tactic:([A-Za-z0-9_.-]+)", block)
                techniques = re.findall(r"technique:([A-Za-z0-9_.-]+)", block)

                alerts.append(
                    {
                        "id": alert_id,
                        "name": alert_name,
                        "severity": severity,
                        "rule_description": rule_desc,
                        "tactics": list(set(tactics)),
                        "techniques": list(set(techniques)),
                    }
                )

        return content, alerts, entities

    def _parse_timestamp(self, ts_str: str | None) -> datetime | None:
        """Parse ISO timestamp string to UTC datetime."""
        if not ts_str:
            return None
        try:
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            return dt.astimezone(UTC)
        except Exception:
            return None

    def construct_embedding_text(
        self,
        display_name: str,
        verdict: str,
        confidence: str | None,
        summary: str | None,
        next_steps: list[dict[str, Any]] | None,
        entities: list[dict[str, Any]] | None,
    ) -> str:
        """Construct a high-density textual representation for vector embedding."""
        parts = [
            f"Investigation Title: {display_name}",
            f"Verdict: {verdict} (Confidence: {confidence or 'N/A'})",
        ]
        if summary:
            parts.append(f"Summary & Threat Analysis:\n{summary}")

        if entities:
            ent_strs = [
                f"{e.get('type')}: {e.get('value')} ({e.get('context', '')})"
                for e in entities[:10]
            ]
            parts.append("Involved Entities:\n" + ", ".join(ent_strs))

        if next_steps:
            step_strs = [
                f"- {s.get('title', '')} ({s.get('type', '')})" for s in next_steps[:5]
            ]
            parts.append("Prescribed Next Steps:\n" + "\n".join(step_strs))

        return "\n\n".join(parts)

    def ingest(
        self,
        batch_size: int = 50,
        recreate: bool = False,
        generate_embeddings: bool = False,
    ) -> dict[str, int]:
        """Ingest all harvested detection reports from investigations/ into AlloyDB."""
        if recreate:
            self.init_schema(recreate=True)
        else:
            self.init_schema(recreate=False)

        json_files = sorted(
            [
                f
                for f in self.investigations_dir.glob("*.json")
                if f.name != "knowledge_graph.json"
            ]
        )

        if not json_files:
            console.print(
                f"[yellow]No investigation JSON files found in {self.investigations_dir}[/yellow]"
            )
            return {"reports": 0, "alerts": 0, "entities": 0}

        console.print(
            f"[blue]Starting ingestion of {len(json_files)} harvested detection reports into AlloyDB...[/blue]"
        )

        total_reports = 0
        total_alerts = 0
        total_entities = 0

        with self.get_connection() as conn:
            with conn.cursor() as cur:
                for idx, json_file in enumerate(json_files, 1):
                    try:
                        with open(json_file, encoding="utf-8") as f:
                            data = json.load(f)

                        inv_name = data.get("name", "")
                        inv_id = (
                            inv_name.split("/")[-1]
                            if "/" in inv_name
                            else json_file.stem
                        )

                        md_file = self.investigations_dir / f"{json_file.stem}.md"
                        md_content, md_alerts, md_entities = self.parse_markdown_report(
                            md_file
                        )

                        alert_ids = data.get("alerts", {}).get("ids", [])
                        for a in md_alerts:
                            if a["id"] not in alert_ids:
                                alert_ids.append(a["id"])

                        time_range = data.get("timeRange", {})
                        start_time = self._parse_timestamp(time_range.get("startTime"))
                        end_time = self._parse_timestamp(time_range.get("endTime"))
                        publish_time = self._parse_timestamp(data.get("publishTime"))
                        update_time = self._parse_timestamp(data.get("updateTime"))

                        cur.execute(
                            """
                            INSERT INTO detection_reports (
                                id, name, display_name, verdict, confidence, status,
                                trigger_type, start_time, end_time, publish_time, update_time,
                                summary, notebook_uri, alert_ids, investigation_steps,
                                next_steps, entities, markdown_report, raw_json, updated_at
                            ) VALUES (
                                %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s,
                                %s, %s, %s, %s,
                                %s, %s, %s, %s, CURRENT_TIMESTAMP
                            )
                            ON CONFLICT (id) DO UPDATE SET
                                name = EXCLUDED.name,
                                display_name = EXCLUDED.display_name,
                                verdict = EXCLUDED.verdict,
                                confidence = EXCLUDED.confidence,
                                status = EXCLUDED.status,
                                trigger_type = EXCLUDED.trigger_type,
                                start_time = EXCLUDED.start_time,
                                end_time = EXCLUDED.end_time,
                                publish_time = EXCLUDED.publish_time,
                                update_time = EXCLUDED.update_time,
                                summary = EXCLUDED.summary,
                                notebook_uri = EXCLUDED.notebook_uri,
                                alert_ids = EXCLUDED.alert_ids,
                                investigation_steps = EXCLUDED.investigation_steps,
                                next_steps = EXCLUDED.next_steps,
                                entities = EXCLUDED.entities,
                                markdown_report = EXCLUDED.markdown_report,
                                raw_json = EXCLUDED.raw_json,
                                updated_at = CURRENT_TIMESTAMP;
                            """,
                            (
                                inv_id,
                                data.get("name"),
                                data.get("displayName", "Unknown Investigation"),
                                data.get("verdict", "UNKNOWN"),
                                data.get("confidence"),
                                data.get("status"),
                                data.get("triggerType"),
                                start_time,
                                end_time,
                                publish_time,
                                update_time,
                                data.get("summary"),
                                data.get("notebook"),
                                alert_ids,
                                json.dumps(data.get("investigationSteps", [])),
                                json.dumps(data.get("nextSteps", [])),
                                json.dumps(md_entities),
                                md_content,
                                json.dumps(data),
                            ),
                        )
                        total_reports += 1

                        cur.execute(
                            "DELETE FROM detection_alerts WHERE investigation_id = %s;",
                            (inv_id,),
                        )
                        for a in md_alerts:
                            cur.execute(
                                """
                                INSERT INTO detection_alerts (
                                    alert_id, investigation_id, display_name, severity,
                                    rule_description, mitre_tactics, mitre_techniques, raw_json
                                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                                """,
                                (
                                    a["id"],
                                    inv_id,
                                    a.get("name"),
                                    a.get("severity"),
                                    a.get("rule_description"),
                                    a.get("tactics", []),
                                    a.get("techniques", []),
                                    json.dumps(a),
                                ),
                            )
                            total_alerts += 1

                        existing_alert_ids = {a["id"] for a in md_alerts}
                        for aid in alert_ids:
                            if aid not in existing_alert_ids:
                                cur.execute(
                                    """
                                    INSERT INTO detection_alerts (
                                        alert_id, investigation_id, display_name, raw_json
                                    ) VALUES (%s, %s, %s, %s);
                                    """,
                                    (
                                        aid,
                                        inv_id,
                                        data.get("displayName"),
                                        json.dumps({"id": aid}),
                                    ),
                                )
                                total_alerts += 1

                        cur.execute(
                            "DELETE FROM detection_entities WHERE investigation_id = %s;",
                            (inv_id,),
                        )
                        for ent in md_entities:
                            cur.execute(
                                """
                                INSERT INTO detection_entities (
                                    investigation_id, entity_type, entity_value, context, threat_intel
                                ) VALUES (%s, %s, %s, %s, %s);
                                """,
                                (
                                    inv_id,
                                    ent.get("type", "UNKNOWN"),
                                    ent.get("value", ""),
                                    ent.get("context"),
                                    json.dumps({}),
                                ),
                            )
                            total_entities += 1

                        if idx % batch_size == 0:
                            conn.commit()
                            console.print(
                                f"  Processed {idx}/{len(json_files)} reports..."
                            )

                    except Exception as e:
                        console.print(
                            f"[red]Error ingesting {json_file.name}: {e}[/red]"
                        )

                conn.commit()

        if generate_embeddings:
            self.embed_reports()

        stats = {
            "reports": total_reports,
            "alerts": total_alerts,
            "entities": total_entities,
        }
        console.print(
            Panel.fit(
                f"[bold green]Ingestion complete![/bold green]\n"
                f"Detection Reports Ingested: [bold]{total_reports}[/bold]\n"
                f"Associated Alerts Linked: [bold]{total_alerts}[/bold]\n"
                f"Extracted Entities Linked: [bold]{total_entities}[/bold]",
                title="AlloyDB Ingestion Summary",
                border_style="green",
            )
        )
        return stats

    def embed_reports(self, force: bool = False, batch_size: int = 25) -> int:
        """Generate Vertex AI vector embeddings for reports and store them in AlloyDB."""
        console.print(
            "[blue]Generating vector embeddings for detection reports using text-embedding-004...[/blue]"
        )

        with self.get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                try:
                    cur.execute('CREATE EXTENSION IF NOT EXISTS "vector";')
                    cur.execute(
                        "ALTER TABLE detection_reports ADD COLUMN IF NOT EXISTS embedding vector(768);"
                    )
                    conn.commit()
                except Exception as ext_err:
                    conn.rollback()
                    console.print(f"[yellow]Notice on vector setup: {ext_err}[/yellow]")

                where_clause = "WHERE embedding IS NULL" if not force else ""
                cur.execute(
                    f"""
                    SELECT id, display_name, verdict, confidence, summary, next_steps, entities
                    FROM detection_reports
                    {where_clause}
                    ORDER BY id;
                    """  # noqa: S608
                )
                reports_to_embed = cur.fetchall()

                if not reports_to_embed:
                    console.print(
                        "[green]All detection reports already have embeddings.[/green]"
                    )
                    return 0

                console.print(
                    f"Found [bold]{len(reports_to_embed)}[/bold] reports to embed. Processing in batches of {batch_size}..."
                )

                total_embedded = 0
                for i in range(0, len(reports_to_embed), batch_size):
                    batch = reports_to_embed[i : i + batch_size]
                    batch_texts = [
                        self.construct_embedding_text(
                            r["display_name"],
                            r["verdict"],
                            r["confidence"],
                            r["summary"],
                            r["next_steps"],
                            r["entities"],
                        )
                        for r in batch
                    ]

                    embeddings = self.get_embeddings_batch(
                        batch_texts, task_type="RETRIEVAL_DOCUMENT"
                    )

                    for r, emb in zip(batch, embeddings, strict=False):
                        cur.execute(
                            """
                            UPDATE detection_reports
                            SET embedding = %s::vector, updated_at = CURRENT_TIMESTAMP
                            WHERE id = %s;
                            """,
                            (emb, r["id"]),
                        )
                        total_embedded += 1

                    conn.commit()
                    console.print(
                        f"  Embedded {total_embedded}/{len(reports_to_embed)} reports..."
                    )

                # Ensure HNSW cosine index is up to date
                try:
                    cur.execute(
                        """
                        CREATE INDEX IF NOT EXISTS idx_detection_reports_embedding_hnsw
                        ON detection_reports USING hnsw (embedding vector_cosine_ops);
                        """
                    )
                    conn.commit()
                except Exception as e:
                    console.print(f"[yellow]Notice on HNSW index: {e}[/yellow]")

        console.print(
            f"[bold green]Successfully embedded {total_embedded} detection reports with 768-dim vectors.[/bold green]"
        )
        return total_embedded

    def search(
        self,
        query: str | None = None,
        semantic: bool = False,
        verdict: str | None = None,
        confidence: str | None = None,
        entity: str | None = None,
        alert_id: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Search detection reports in AlloyDB using full-text or semantic vector similarity."""
        with self.get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                where_clauses: list[str] = []
                params: list[Any] = []

                if verdict:
                    where_clauses.append("verdict = %s")
                    params.append(verdict.upper())

                if confidence:
                    where_clauses.append("confidence = %s")
                    params.append(confidence.upper())

                if alert_id:
                    where_clauses.append("%s = ANY(alert_ids)")
                    params.append(alert_id)

                if entity:
                    where_clauses.append(
                        """id IN (
                            SELECT investigation_id FROM detection_entities
                            WHERE entity_value ILIKE %s
                        )"""
                    )
                    params.append(f"%{entity}%")

                # Semantic vector search mode
                if query and semantic:
                    query_emb = self.get_embedding(query, task_type="RETRIEVAL_QUERY")
                    where_clauses.append("embedding IS NOT NULL")
                    where_sql = (
                        ("WHERE " + " AND ".join(where_clauses))
                        if where_clauses
                        else ""
                    )

                    sql = f"""
                        SELECT
                            id, display_name, verdict, confidence, status,
                            publish_time, summary, alert_ids,
                            jsonb_array_length(entities) AS entities_count,
                            1 - (embedding <=> %s::vector) AS similarity_score
                        FROM detection_reports
                        {where_sql}
                        ORDER BY embedding <=> %s::vector ASC
                        LIMIT %s;
                    """  # noqa: S608
                    full_params = [query_emb] + params + [query_emb, limit]
                    cur.execute(sql, tuple(full_params))
                    return list(cur.fetchall())

                # Standard Full-Text Search
                if query:
                    where_clauses.append(
                        """(
                            to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '') || ' ' || coalesce(markdown_report, ''))
                            @@ plainto_tsquery('english', %s)
                            OR display_name ILIKE %s
                            OR summary ILIKE %s
                            OR id ILIKE %s
                        )"""
                    )
                    like_query = f"%{query}%"
                    params.extend([query, like_query, like_query, like_query])

                where_sql = (
                    ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
                )

                sql = f"""
                    SELECT
                        id, display_name, verdict, confidence, status,
                        publish_time, summary, alert_ids,
                        jsonb_array_length(entities) AS entities_count,
                        NULL AS similarity_score
                    FROM detection_reports
                    {where_sql}
                    ORDER BY publish_time DESC NULLS LAST
                    LIMIT %s;
                """  # noqa: S608
                params.append(limit)

                cur.execute(sql, tuple(params))
                return list(cur.fetchall())

    def find_similar(
        self,
        investigation_id: str,
        limit: int = 5,
        profile: str = "balanced",
        weights: dict[str, float] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Find most similar investigations to a target investigation using multi-modal scoring:
        1. Semantic Vector Cosine Similarity (pgvector text-embedding-004)
        2. Weighted Entity Overlap (Inverse Document Frequency weighted Jaccard)
        3. Behavioral TTP Overlap (MITRE ATT&CK techniques & tactics)
        4. Investigation Flow Similarity (Execution steps)
        5. Temporal Proximity (Exponential time decay)

        Supported Profiles:
        - 'balanced': Standard triage across all dimensions (default)
        - 'threat-hunt': Heavy TTP and semantic bias to hunt tradecraft across multiple hosts
        - 'compromise-pivot': Heavy entity and temporal bias to trace host compromise and lateral movement
        - 'false-positive': Heavy entity and detection rule bias to identify recurring benign noise
        - 'semantic': Heavy vector embedding bias for conceptual behavioral discovery
        """
        import math

        norm_profile = profile.lower().replace("_", "-")
        profile_def = SIMILARITY_PROFILES.get(
            norm_profile, SIMILARITY_PROFILES["balanced"]
        )
        base_weights = dict(profile_def["weights"])

        if weights:
            for k, val in weights.items():
                if val is not None:
                    base_weights[k] = val

        # Normalize weights so they sum to 1.0
        total_w = sum(base_weights.values())
        w = (
            {k: v / total_w for k, v in base_weights.items()}
            if total_w > 0
            else base_weights
        )

        with self.get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                # 1. Fetch the target investigation
                cur.execute(
                    """
                    SELECT id, display_name, verdict, confidence, status, publish_time,
                           summary, alert_ids, investigation_steps, entities, embedding
                    FROM detection_reports
                    WHERE id = %s OR id LIKE %s
                    LIMIT 1;
                    """,
                    (investigation_id, f"%{investigation_id}%"),
                )
                target = cur.fetchone()
                if not target:
                    return []

                target_id = target["id"]

                # 2. Fetch target's alerts & MITRE TTPs
                cur.execute(
                    """
                    SELECT alert_id, display_name, severity, mitre_tactics, mitre_techniques
                    FROM detection_alerts
                    WHERE investigation_id = %s;
                    """,
                    (target_id,),
                )
                target_alerts = cur.fetchall()
                target_tactics = set()
                target_techniques = set()
                for a in target_alerts:
                    for tac in a.get("mitre_tactics") or []:
                        target_tactics.add(tac)
                    for tech in a.get("mitre_techniques") or []:
                        target_techniques.add(tech)

                # 3. Fetch target's entities
                cur.execute(
                    """
                    SELECT entity_type, entity_value, context
                    FROM detection_entities
                    WHERE investigation_id = %s;
                    """,
                    (target_id,),
                )
                target_entities = cur.fetchall()
                target_ent_map = {e["entity_value"]: e for e in target_entities}
                target_ent_vals = set(target_ent_map.keys())

                # 4. Fetch IDF weights for all entities in the database
                cur.execute("SELECT COUNT(*) AS total FROM detection_reports;")
                total_reports = cur.fetchone()["total"]

                cur.execute(
                    """
                    SELECT entity_value, COUNT(DISTINCT investigation_id) AS doc_freq
                    FROM detection_entities
                    GROUP BY entity_value;
                    """
                )
                entity_idf = {}
                for row in cur.fetchall():
                    df = row["doc_freq"]
                    entity_idf[row["entity_value"]] = (
                        math.log((total_reports + 1.0) / (df + 1.0)) + 1.0
                    )

                # 5. Stage 1: Candidate Generation (Vector KNN + Entity Join)
                candidates_set = set()

                # Branch A: Top 25 Nearest Vector Neighbors via HNSW
                if target.get("embedding") is not None:
                    cur.execute(
                        """
                        SELECT id
                        FROM detection_reports
                        WHERE id != %s AND embedding IS NOT NULL
                        ORDER BY embedding <=> %s::vector ASC
                        LIMIT 25;
                        """,
                        (target_id, target["embedding"]),
                    )
                    for r in cur.fetchall():
                        candidates_set.add(r["id"])

                # Branch B: Top 25 Entity Sharing Candidates
                if target_ent_vals:
                    cur.execute(
                        """
                        SELECT DISTINCT investigation_id
                        FROM detection_entities
                        WHERE entity_value = ANY(%s) AND investigation_id != %s
                        LIMIT 25;
                        """,
                        (list(target_ent_vals), target_id),
                    )
                    for r in cur.fetchall():
                        candidates_set.add(r["investigation_id"])

                if not candidates_set:
                    cur.execute(
                        "SELECT id FROM detection_reports WHERE id != %s ORDER BY publish_time DESC LIMIT 25;",
                        (target_id,),
                    )
                    for r in cur.fetchall():
                        candidates_set.add(r["id"])

                # 6. Stage 2: Detailed Re-ranking of Candidates
                candidate_ids = list(candidates_set)
                cur.execute(
                    """
                    SELECT
                        r.id, r.display_name, r.verdict, r.confidence, r.status,
                        r.publish_time, r.summary, r.alert_ids, r.investigation_steps,
                        r.entities,
                        CASE WHEN r.embedding IS NOT NULL AND %s::vector IS NOT NULL
                             THEN 1 - (r.embedding <=> %s::vector)
                             ELSE 0.0
                        END AS semantic_score
                    FROM detection_reports r
                    WHERE r.id = ANY(%s);
                    """,
                    (target.get("embedding"), target.get("embedding"), candidate_ids),
                )
                candidate_rows = cur.fetchall()

                # Fetch alerts & entities for all candidates in bulk
                cur.execute(
                    """
                    SELECT investigation_id, alert_id, display_name, severity, mitre_tactics, mitre_techniques
                    FROM detection_alerts
                    WHERE investigation_id = ANY(%s);
                    """,
                    (candidate_ids,),
                )
                cand_alerts_rows = cur.fetchall()
                cand_alerts_by_inv = {}
                for a in cand_alerts_rows:
                    cand_alerts_by_inv.setdefault(a["investigation_id"], []).append(a)

                cur.execute(
                    """
                    SELECT investigation_id, entity_type, entity_value, context
                    FROM detection_entities
                    WHERE investigation_id = ANY(%s);
                    """,
                    (candidate_ids,),
                )
                cand_entities_rows = cur.fetchall()
                cand_entities_by_inv = {}
                for e in cand_entities_rows:
                    cand_entities_by_inv.setdefault(e["investigation_id"], []).append(e)

                # Target steps fingerprint
                target_steps = target.get("investigation_steps") or []
                target_step_fingerprints = set()
                for s in target_steps:
                    src_type = s.get("sourceMetadata", {}).get("sourceType", "")
                    summary_word = s.get("analysisSummary", "")[:30]
                    target_step_fingerprints.add(f"{src_type}:{summary_word}")

                target_time = target.get("publish_time")

                results = []
                for cand in candidate_rows:
                    cid = cand["id"]
                    # 1. Semantic Similarity
                    s_semantic = max(0.0, float(cand.get("semantic_score") or 0.0))

                    # 2. Weighted Entity Overlap (IDF Jaccard)
                    cand_ents = cand_entities_by_inv.get(cid, [])
                    cand_ent_map = {e["entity_value"]: e for e in cand_ents}
                    cand_ent_vals = set(cand_ent_map.keys())

                    shared_ents = target_ent_vals.intersection(cand_ent_vals)
                    union_ents = target_ent_vals.union(cand_ent_vals)

                    if union_ents:
                        shared_idf_sum = sum(
                            entity_idf.get(v, 1.0) for v in shared_ents
                        )
                        union_idf_sum = sum(entity_idf.get(v, 1.0) for v in union_ents)
                        s_entity = (
                            shared_idf_sum / union_idf_sum if union_idf_sum > 0 else 0.0
                        )
                    else:
                        s_entity = 0.0

                    # 3. Behavioral TTP Similarity
                    cand_alerts = cand_alerts_by_inv.get(cid, [])
                    cand_tactics = set()
                    cand_techniques = set()
                    for a in cand_alerts:
                        for tac in a.get("mitre_tactics") or []:
                            cand_tactics.add(tac)
                        for tech in a.get("mitre_techniques") or []:
                            cand_techniques.add(tech)

                    shared_tech = target_techniques.intersection(cand_techniques)
                    union_tech = target_techniques.union(cand_techniques)
                    tech_jaccard = (
                        len(shared_tech) / len(union_tech) if union_tech else 0.0
                    )

                    shared_tac = target_tactics.intersection(cand_tactics)
                    union_tac = target_tactics.union(cand_tactics)
                    tac_jaccard = len(shared_tac) / len(union_tac) if union_tac else 0.0

                    if union_tech or union_tac:
                        s_ttp = (0.7 * tech_jaccard) + (0.3 * tac_jaccard)
                    else:
                        s_ttp = (
                            1.0
                            if cand["display_name"].lower()
                            == target["display_name"].lower()
                            else 0.0
                        )

                    # 4. Flow Similarity
                    cand_steps = cand.get("investigation_steps") or []
                    cand_step_fps = set()
                    for s in cand_steps:
                        src_type = s.get("sourceMetadata", {}).get("sourceType", "")
                        summary_word = s.get("analysisSummary", "")[:30]
                        cand_step_fps.add(f"{src_type}:{summary_word}")

                    shared_fps = target_step_fingerprints.intersection(cand_step_fps)
                    union_fps = target_step_fingerprints.union(cand_step_fps)
                    s_flow = len(shared_fps) / len(union_fps) if union_fps else 0.0

                    # 5. Temporal Proximity (decay tau = 14 days)
                    cand_time = cand.get("publish_time")
                    if target_time and cand_time:
                        delta_days = (
                            abs((target_time - cand_time).total_seconds()) / 86400.0
                        )
                        s_time = math.exp(-delta_days / 14.0)
                    else:
                        s_time = 0.5

                    # Composite Score
                    composite = (
                        w["semantic"] * s_semantic
                        + w["entity"] * s_entity
                        + w["ttp"] * s_ttp
                        + w["flow"] * s_flow
                        + w["time"] * s_time
                    )

                    shared_entities_info = [
                        {
                            "type": target_ent_map[val].get("entity_type", "UNKNOWN"),
                            "value": val,
                            "context": target_ent_map[val].get("context", ""),
                        }
                        for val in shared_ents
                    ]

                    results.append(
                        {
                            "id": cid,
                            "display_name": cand["display_name"],
                            "verdict": cand["verdict"],
                            "confidence": cand["confidence"],
                            "status": cand["status"],
                            "publish_time": cand["publish_time"],
                            "summary": cand["summary"],
                            "composite_score": round(composite, 4),
                            "breakdown": {
                                "semantic": round(s_semantic, 4),
                                "entity": round(s_entity, 4),
                                "ttp": round(s_ttp, 4),
                                "flow": round(s_flow, 4),
                                "time": round(s_time, 4),
                            },
                            "shared_entities": shared_entities_info,
                            "shared_techniques": sorted(shared_tech),
                            "shared_tactics": sorted(shared_tac),
                        }
                    )

                results.sort(key=lambda x: x["composite_score"], reverse=True)
                return results[:limit]

    def _synthesize_ai_narrative(
        self,
        target: dict[str, Any],
        target_alerts: list[dict[str, Any]],
        target_entities: list[dict[str, Any]],
        similar_matches: list[dict[str, Any]],
        profile_def: dict[str, Any],
    ) -> str:
        """Call Vertex AI Gemini to generate deep security narrative explaining why the reports matched."""
        if self.sa_path and os.path.exists(self.sa_path):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.sa_path

        import vertexai
        from vertexai.generative_models import GenerativeModel

        vertexai.init(project=self.project_id, location=self.location)
        model = GenerativeModel("gemini-2.5-flash")

        target_summary = {
            "id": target["id"],
            "title": target["display_name"],
            "verdict": target["verdict"],
            "confidence": target["confidence"],
            "summary": target.get("summary", ""),
            "alerts": [
                {
                    "name": a["display_name"],
                    "tactics": a.get("mitre_tactics"),
                    "techniques": a.get("mitre_techniques"),
                    "description": a.get("rule_description"),
                }
                for a in target_alerts
            ],
            "entities": [
                f"{e['entity_type']}:{e['entity_value']}" for e in target_entities[:10]
            ],
        }

        matches_summary = []
        for idx, m in enumerate(similar_matches, 1):
            matches_summary.append(
                {
                    "rank": idx,
                    "id": m["id"],
                    "title": m["display_name"],
                    "verdict": m["verdict"],
                    "confidence": m["confidence"],
                    "composite_score": m["composite_score"],
                    "sub_scores": m["breakdown"],
                    "shared_entities": [
                        f"{e['type']}:{e['value']}" for e in m["shared_entities"]
                    ],
                    "shared_techniques": m["shared_techniques"],
                    "shared_tactics": m["shared_tactics"],
                    "summary": (m.get("summary") or "")[:350],
                }
            )

        prompt = f"""You are a Principal Security Operations & Threat Intelligence Analyst.
Analyze the target security investigation and its top similar historical investigations retrieved from Google SecOps / AlloyDB under the '{profile_def['name']}' profile ({profile_def['description']}).

CRITICAL INSTRUCTIONS:
- Never use emojis anywhere in your response.
- Provide objective, highly analytical security insights.
- Write clear markdown subsections explaining:
  1. Executive Threat & Campaign Correlation (explain why these investigations matched from a threat actor tradecraft, binary/script usage, and attack methodology perspective).
  2. Entity & Infrastructure Overlap (explain shared infrastructure, accounts, hosts, or tools versus isolated activity).
  3. Historical Precedent & Verdict Analysis (contrast the verdicts such as FALSE_POSITIVE vs TRUE_POSITIVE and explain why prior instances were classified that way).
  4. Actionable SOC Recommendations (concrete triage steps, containment actions, or detection rule tuning suggestions).

TARGET INVESTIGATION:
{json.dumps(target_summary, indent=2)}

SIMILAR HISTORICAL MATCHES:
{json.dumps(matches_summary, indent=2)}

Generate the synthesis in clean Markdown format with headers.
"""
        response = model.generate_content(prompt)
        return response.text.strip()

    def _render_similarity_markdown(
        self,
        target: dict[str, Any],
        target_alerts: list[dict[str, Any]],
        target_entities: list[dict[str, Any]],
        similar_matches: list[dict[str, Any]],
        profile_def: dict[str, Any],
        ai_narrative: str,
        file_path: Path,
        timestamp: str,
    ) -> str:
        """Render complete Markdown document conforming to Open Knowledge Format."""
        abs_uri = f"file://{file_path.resolve()}"
        source_tool = (
            "Vertex AI Gemini 2.5 Flash + AlloyDB Multi-Modal Engine"
            if ai_narrative
            else "AlloyDB Multi-Modal Similarity Engine"
        )

        frontmatter = f"""---
type: "Evaluation Report"
title: "Investigation Similarity Report: {target['display_name']}"
description: "Multi-modal similarity analysis for investigation {target['id']} using AlloyDB pgvector and {profile_def['name']} scoring profile."
resource: "{abs_uri}"
timestamp: "{timestamp}"
provenance:
  source_type: "python_generated"
  source_tool: "{source_tool}"
  timestamp: "{timestamp}"
---
"""

        sections = [frontmatter]
        sections.append(
            f"# Investigation Similarity Report: {target['display_name']}\n"
        )

        pw = profile_def["weights"]
        weights_str = (
            f"Semantic: {pw['semantic']*100:.0f}%, "
            f"Entity: {pw['entity']*100:.0f}%, "
            f"TTP: {pw['ttp']*100:.0f}%, "
            f"Flow: {pw['flow']*100:.0f}%, "
            f"Time: {pw['time']*100:.0f}%"
        )
        sections.append(
            f"> **Scoring Profile:** `{profile_def['name']}` ({profile_def['description']})\n"
            f"> **Weight Distribution:** {weights_str}\n"
        )

        tactics = sorted(
            {t for a in target_alerts for t in (a.get("mitre_tactics") or [])}
        )
        techniques = sorted(
            {t for a in target_alerts for t in (a.get("mitre_techniques") or [])}
        )
        ent_strs = [
            f"`{e['entity_type']}:{e['entity_value']}`" for e in target_entities[:8]
        ]
        if len(target_entities) > 8:
            ent_strs.append(f"+{len(target_entities) - 8} more")

        sections.append("## Target Investigation Overview\n")
        sections.append("| Attribute | Value |")
        sections.append("| :--- | :--- |")
        sections.append(f"| **Investigation ID** | `{target['id']}` |")
        sections.append(f"| **Display Name** | {target['display_name']} |")
        sections.append(
            f"| **Verdict** | `{target['verdict']}` ({target.get('confidence') or 'N/A'}) |"
        )
        sections.append(
            f"| **Published Time** | {target.get('publish_time') or 'N/A'} |"
        )
        sections.append(f"| **MITRE Tactics** | {', '.join(tactics) or 'None'} |")
        sections.append(f"| **MITRE Techniques** | {', '.join(techniques) or 'None'} |")
        sections.append(f"| **Key Entities** | {', '.join(ent_strs) or 'None'} |\n")

        if target.get("summary"):
            sections.append("### Target Investigation Summary\n")
            sections.append(f"{target['summary']}\n")

        if ai_narrative:
            sections.append(
                "## Threat Actor Tradecraft & Campaign Analysis (AI Synthesis)\n"
            )
            sections.append(f"{ai_narrative}\n")

        sections.append("## Top Similar Historical Investigations\n")
        sections.append(
            "| Rank | Investigation ID | Display Name | Verdict | Composite Score | Sub-Score Breakdown (Sem / Ent / TTP / Flow / Time) | Shared Telemetry |"
        )
        sections.append("| :---: | :--- | :--- | :--- | :---: | :---: | :--- |")

        for idx, m in enumerate(similar_matches, 1):
            bd = m["breakdown"]
            bd_str = f"{bd['semantic']:.2f} / {bd['entity']:.2f} / {bd['ttp']:.2f} / {bd['flow']:.2f} / {bd['time']:.2f}"
            ents_preview = ", ".join(
                [f"`{e['type']}:{e['value']}`" for e in m["shared_entities"][:2]]
            )
            if len(m["shared_entities"]) > 2:
                ents_preview += f" (+{len(m['shared_entities']) - 2})"
            techs = ", ".join(m["shared_techniques"])
            shared_info = []
            if ents_preview:
                shared_info.append(f"Ent: {ents_preview}")
            if techs:
                shared_info.append(f"TTP: {techs}")
            shared_str = "<br>".join(shared_info) or "None"

            sections.append(
                f"| {idx} | [`{m['id'][:8]}...`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/{m['id']}.md) | {m['display_name']} | `{m['verdict']}` | **{m['composite_score']:.4f}** | `{bd_str}` | {shared_str} |"
            )

        sections.append("")

        sections.append("## Detailed Match Breakdown\n")
        for idx, m in enumerate(similar_matches, 1):
            sections.append(f"### Match #{idx}: {m['display_name']} (`{m['id']}`)\n")
            sections.append(
                f"- **Verdict:** `{m['verdict']}` (Confidence: `{m['confidence']}`)"
            )
            sections.append(f"- **Composite Score:** **{m['composite_score']:.4f}**")
            sections.append(
                f"- **Semantic Vector Similarity:** `{m['breakdown']['semantic']:.4f}`"
            )
            sections.append(
                f"- **Entity Overlap Score:** `{m['breakdown']['entity']:.4f}`"
            )
            sections.append(f"- **MITRE TTP Overlap:** `{m['breakdown']['ttp']:.4f}`")
            sections.append(f"- **Flow Steps Overlap:** `{m['breakdown']['flow']:.4f}`")
            sections.append(
                f"- **Temporal Decay Factor:** `{m['breakdown']['time']:.4f}`\n"
            )

            if m["shared_entities"]:
                sections.append("**Shared Entities:**")
                for e in m["shared_entities"]:
                    sections.append(
                        f"- `[{e['type']}]` `{e['value']}` — {e['context']}"
                    )
                sections.append("")

            if m["shared_techniques"]:
                sections.append(
                    f"- **Shared Techniques:** {', '.join(m['shared_techniques'])}"
                )
            if m["shared_tactics"]:
                sections.append(
                    f"- **Shared Tactics:** {', '.join(m['shared_tactics'])}\n"
                )

            if m.get("summary"):
                sections.append("**Investigation Summary:**")
                sections.append(f"> {m['summary']}\n")

        return "\n".join(sections)

    def generate_similarity_report(
        self,
        investigation_id: str,
        limit: int = 5,
        profile: str = "threat-hunt",
        use_ai: bool = True,
        output_file: Path | None = None,
    ) -> tuple[str, Path]:
        """
        Generate a Markdown investigation similarity report using a hybrid deterministic
        table template with optional Gemini AI threat narrative synthesis.
        """
        norm_profile = profile.lower().replace("_", "-")
        profile_def = SIMILARITY_PROFILES.get(
            norm_profile, SIMILARITY_PROFILES["balanced"]
        )

        with self.get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, display_name, verdict, confidence, status, publish_time,
                           summary, alert_ids, investigation_steps, entities
                    FROM detection_reports
                    WHERE id = %s OR id LIKE %s
                    LIMIT 1;
                    """,
                    (investigation_id, f"%{investigation_id}%"),
                )
                target = cur.fetchone()
                if not target:
                    raise ValueError(
                        f"Investigation '{investigation_id}' not found in AlloyDB."
                    )

                target_id = target["id"]

                cur.execute(
                    """
                    SELECT alert_id, display_name, severity, mitre_tactics, mitre_techniques, rule_description
                    FROM detection_alerts
                    WHERE investigation_id = %s;
                    """,
                    (target_id,),
                )
                target_alerts = cur.fetchall()

                cur.execute(
                    """
                    SELECT entity_type, entity_value, context
                    FROM detection_entities
                    WHERE investigation_id = %s;
                    """,
                    (target_id,),
                )
                target_entities = cur.fetchall()

        similar_matches = self.find_similar(
            investigation_id=target_id,
            limit=limit,
            profile=norm_profile,
        )

        ai_narrative = ""
        if use_ai:
            try:
                ai_narrative = self._synthesize_ai_narrative(
                    target=target,
                    target_alerts=target_alerts,
                    target_entities=target_entities,
                    similar_matches=similar_matches,
                    profile_def=profile_def,
                )
            except Exception as ai_err:
                console.print(
                    f"[yellow]AI narrative synthesis notice ({ai_err}), falling back to structured template...[/yellow]"
                )
                ai_narrative = ""

        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        dest_file = output_file or (
            self.project_root
            / "investigations"
            / "similarity_reports"
            / f"similarity_{target_id}_{norm_profile}.md"
        )
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        md_content = self._render_similarity_markdown(
            target=target,
            target_alerts=target_alerts,
            target_entities=target_entities,
            similar_matches=similar_matches,
            profile_def=profile_def,
            ai_narrative=ai_narrative,
            file_path=dest_file,
            timestamp=now_iso,
        )

        dest_file.write_text(md_content, encoding="utf-8")
        return md_content, dest_file

    def get_info(self) -> dict[str, Any]:
        """Fetch statistics, metadata, and vector status from AlloyDB."""
        with self.get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT COUNT(*) AS total_reports FROM detection_reports;")
                total_reports = cur.fetchone()["total_reports"]

                cur.execute(
                    "SELECT COUNT(*) AS total_embedded FROM detection_reports WHERE embedding IS NOT NULL;"
                )
                total_embedded = cur.fetchone()["total_embedded"]

                cur.execute("SELECT COUNT(*) AS total_alerts FROM detection_alerts;")
                total_alerts = cur.fetchone()["total_alerts"]

                cur.execute(
                    "SELECT COUNT(*) AS total_entities FROM detection_entities;"
                )
                total_entities = cur.fetchone()["total_entities"]

                cur.execute(
                    """
                    SELECT verdict, COUNT(*) AS count
                    FROM detection_reports
                    GROUP BY verdict
                    ORDER BY count DESC;
                    """
                )
                verdicts = {row["verdict"]: row["count"] for row in cur.fetchall()}

                cur.execute(
                    """
                    SELECT coalesce(confidence, 'N/A') AS confidence, COUNT(*) AS count
                    FROM detection_reports
                    GROUP BY confidence
                    ORDER BY count DESC;
                    """
                )
                confidences = {
                    row["confidence"]: row["count"] for row in cur.fetchall()
                }

                cur.execute(
                    """
                    SELECT pg_size_pretty(pg_total_relation_size('detection_reports')) AS reports_size,
                           pg_size_pretty(pg_database_size(current_database())) AS db_size;
                    """
                )
                size_row = cur.fetchone()

                return {
                    "total_reports": total_reports,
                    "total_embedded": total_embedded,
                    "total_alerts": total_alerts,
                    "total_entities": total_entities,
                    "verdicts": verdicts,
                    "confidences": confidences,
                    "reports_size": size_row["reports_size"] if size_row else "N/A",
                    "db_size": size_row["db_size"] if size_row else "N/A",
                }

    def clear(self) -> None:
        """Truncate all detection report tables in AlloyDB."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE detection_entities CASCADE;")
                cur.execute("TRUNCATE TABLE detection_alerts CASCADE;")
                cur.execute("TRUNCATE TABLE detection_reports CASCADE;")
                conn.commit()
                console.print(
                    "[yellow]All detection reports, alerts, and entities cleared from AlloyDB.[/yellow]"
                )


# ============================================================================
# Typer CLI Commands
# ============================================================================


@app.command("test-connection")
def test_connection_cmd(
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Test connection to the AlloyDB/PostgreSQL database."""
    manager = AlloyDBManager(env_file=env_file)
    success = manager.test_connection()
    if not success:
        raise typer.Exit(code=1)


@app.command("init-schema")
def init_schema_cmd(
    recreate: Annotated[
        bool,
        typer.Option(
            "--recreate",
            help="Drop existing tables and recreate schema from scratch.",
        ),
    ] = False,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Initialize AlloyDB tables, pgvector extensions, and indexes."""
    manager = AlloyDBManager(env_file=env_file)
    manager.init_schema(recreate=recreate)


@app.command("ingest")
def ingest_cmd(
    recreate: Annotated[
        bool,
        typer.Option(
            "--recreate",
            help="Recreate database schema before ingestion.",
        ),
    ] = False,
    embed: Annotated[
        bool,
        typer.Option(
            "--embed",
            help="Generate vector embeddings immediately following ingestion.",
        ),
    ] = False,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            "-b",
            help="Number of reports per commit batch.",
        ),
    ] = 50,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Ingest harvested detection reports from investigations/ into AlloyDB."""
    manager = AlloyDBManager(env_file=env_file)
    manager.ingest(batch_size=batch_size, recreate=recreate, generate_embeddings=embed)


@app.command("embed")
def embed_cmd(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force re-generation of embeddings for all reports.",
        ),
    ] = False,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            "-b",
            help="Number of reports per embedding batch.",
        ),
    ] = 25,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Generate Vertex AI 768-dim vector embeddings for reports in AlloyDB."""
    manager = AlloyDBManager(env_file=env_file)
    manager.embed_reports(force=force, batch_size=batch_size)


@app.command("search")
def search_cmd(
    query: Annotated[
        str | None,
        typer.Argument(
            help="Search text query across reports (keyword or semantic).",
        ),
    ] = None,
    semantic: Annotated[
        bool,
        typer.Option(
            "--semantic",
            "-s",
            help="Use vector cosine similarity search via text-embedding-004.",
        ),
    ] = False,
    verdict: Annotated[
        str | None,
        typer.Option(
            "--verdict",
            "-v",
            help="Filter by verdict (TRUE_POSITIVE or FALSE_POSITIVE).",
        ),
    ] = None,
    confidence: Annotated[
        str | None,
        typer.Option(
            "--confidence",
            "-c",
            help="Filter by confidence (HIGH_CONFIDENCE or LOW_CONFIDENCE).",
        ),
    ] = None,
    entity: Annotated[
        str | None,
        typer.Option(
            "--entity",
            help="Filter by entity value (hostname, user, ip, file hash).",
        ),
    ] = None,
    alert_id: Annotated[
        str | None,
        typer.Option(
            "--alert-id",
            "-a",
            help="Filter by alert ID.",
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            "-l",
            help="Maximum results to return.",
        ),
    ] = 5,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Search harvested detection reports in AlloyDB using full-text or semantic search."""
    manager = AlloyDBManager(env_file=env_file)
    results = manager.search(
        query=query,
        semantic=semantic,
        verdict=verdict,
        confidence=confidence,
        entity=entity,
        alert_id=alert_id,
        limit=limit,
    )

    if not results:
        console.print(
            "[yellow]No matching detection reports found in AlloyDB.[/yellow]"
        )
        return

    mode_label = "Semantic Vector Search" if semantic else "Full-Text Search"
    table = Table(
        title=f"AlloyDB Detection Reports ({mode_label}, {len(results)} matches)",
        box=box.ROUNDED,
    )
    table.add_column("Investigation ID", style="cyan", no_wrap=True)
    table.add_column("Display Name", style="bold white")
    table.add_column("Verdict", style="magenta")
    table.add_column("Confidence", style="blue")
    if semantic:
        table.add_column("Similarity", justify="right", style="bold yellow")
    table.add_column("Entities", justify="right", style="green")
    table.add_column("Summary Preview", style="dim")

    for row in results:
        summary_preview = (row["summary"] or "").replace("\n", " ")[:90] + "..."
        row_cells = [
            row["id"],
            row["display_name"],
            row["verdict"],
            row["confidence"] or "N/A",
        ]
        if semantic:
            score = row.get("similarity_score")
            score_str = f"{score:.4f}" if score is not None else "N/A"
            row_cells.append(score_str)
        row_cells.extend([str(row["entities_count"]), summary_preview])
        table.add_row(*row_cells)

    console.print(table)


@app.command("find-similar")
def find_similar_cmd(
    investigation_id: Annotated[
        str,
        typer.Argument(
            help="Target investigation ID (UUID or substring) to compare against.",
        ),
    ],
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            "-p",
            help="Scoring profile: 'balanced', 'threat-hunt', 'compromise-pivot', 'false-positive', 'semantic'.",
        ),
    ] = "balanced",
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            "-l",
            help="Maximum similar reports to return.",
        ),
    ] = 5,
    explain: Annotated[
        bool,
        typer.Option(
            "--explain",
            help="Show detailed explainability breakdown for each match.",
        ),
    ] = False,
    semantic_weight: Annotated[
        float | None,
        typer.Option(
            "--semantic-weight",
            help="Override weight for semantic vector similarity.",
        ),
    ] = None,
    entity_weight: Annotated[
        float | None,
        typer.Option(
            "--entity-weight",
            help="Override weight for IDF-weighted entity overlap.",
        ),
    ] = None,
    ttp_weight: Annotated[
        float | None,
        typer.Option(
            "--ttp-weight",
            help="Override weight for MITRE ATT&CK TTP overlap.",
        ),
    ] = None,
    flow_weight: Annotated[
        float | None,
        typer.Option(
            "--flow-weight",
            help="Override weight for investigation flow similarity.",
        ),
    ] = None,
    time_weight: Annotated[
        float | None,
        typer.Option(
            "--time-weight",
            help="Override weight for temporal proximity decay.",
        ),
    ] = None,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Find similar investigation reports using multi-modal composite scoring with specialized profiles."""
    manager = AlloyDBManager(env_file=env_file)
    custom_weights = {
        "semantic": semantic_weight,
        "entity": entity_weight,
        "ttp": ttp_weight,
        "flow": flow_weight,
        "time": time_weight,
    }
    # Filter out None values so profile weights apply
    custom_weights = {k: v for k, v in custom_weights.items() if v is not None}

    results = manager.find_similar(
        investigation_id=investigation_id,
        limit=limit,
        profile=profile,
        weights=custom_weights or None,
    )

    if not results:
        console.print(
            f"[yellow]Investigation '{investigation_id}' not found in AlloyDB or no candidates available.[/yellow]"
        )
        return

    norm_profile = profile.lower().replace("_", "-")
    p_info = SIMILARITY_PROFILES.get(norm_profile, SIMILARITY_PROFILES["balanced"])
    console.print(
        f"[bold blue]Active Profile:[/bold blue] [bold green]{p_info['name']}[/bold green] "
        f"([dim]{p_info['description']}[/dim])\n"
    )

    table = Table(
        title=f"Multi-Modal Similar Investigations for Target '{investigation_id}' ({p_info['name']})",
        box=box.ROUNDED,
    )
    table.add_column("Rank", justify="right", style="dim")
    table.add_column("Investigation ID", style="cyan", no_wrap=True)
    table.add_column("Display Name", style="bold white")
    table.add_column("Verdict", style="magenta")
    table.add_column("Composite", justify="right", style="bold yellow")
    table.add_column("Breakdown (Sem / Ent / TTP / Flow / Time)", style="dim")
    table.add_column("Shared Entities & Techniques", style="green")

    for idx, r in enumerate(results, 1):
        bd = r["breakdown"]
        bd_str = f"{bd['semantic']:.2f} / {bd['entity']:.2f} / {bd['ttp']:.2f} / {bd['flow']:.2f} / {bd['time']:.2f}"

        ent_summary = ", ".join(
            [f"{e['type']}:{e['value']}" for e in r["shared_entities"][:3]]
        )
        if len(r["shared_entities"]) > 3:
            ent_summary += f" (+{len(r['shared_entities']) - 3} more)"

        tech_summary = ", ".join(r["shared_techniques"])
        shared_summary = []
        if ent_summary:
            shared_summary.append(f"Ent: {ent_summary}")
        if tech_summary:
            shared_summary.append(f"TTP: {tech_summary}")
        shared_str = " | ".join(shared_summary) or "None"

        table.add_row(
            str(idx),
            r["id"],
            r["display_name"],
            f"{r['verdict']} ({r['confidence'] or 'N/A'})",
            f"{r['composite_score']:.4f}",
            bd_str,
            shared_str,
        )

    console.print(table)

    if explain:
        effective_weights = {**p_info["weights"], **custom_weights}
        total_ew = sum(effective_weights.values())
        if total_ew > 0:
            effective_weights = {k: v / total_ew for k, v in effective_weights.items()}

        console.print("\n[bold cyan]Detailed Explainability Breakdown:[/bold cyan]\n")
        for idx, r in enumerate(results, 1):
            console.print(
                Panel.fit(
                    f"[bold white]Rank {idx}: {r['display_name']}[/bold white] (`{r['id']}`)\n"
                    f"Verdict: [magenta]{r['verdict']}[/magenta] (Confidence: {r['confidence']})\n"
                    f"Composite Similarity Score: [bold yellow]{r['composite_score']:.4f}[/bold yellow]\n\n"
                    f"[bold]Sub-Score Breakdown:[/bold]\n"
                    f"  - Semantic Vector Cosine: [cyan]{r['breakdown']['semantic']:.4f}[/cyan] (Weight: {effective_weights['semantic'] * 100:.0f}%)\n"
                    f"  - Weighted Entity Overlap: [cyan]{r['breakdown']['entity']:.4f}[/cyan] (Weight: {effective_weights['entity'] * 100:.0f}%)\n"
                    f"  - Behavioral MITRE TTPs: [cyan]{r['breakdown']['ttp']:.4f}[/cyan] (Weight: {effective_weights['ttp'] * 100:.0f}%)\n"
                    f"  - Investigation Flow Steps: [cyan]{r['breakdown']['flow']:.4f}[/cyan] (Weight: {effective_weights['flow'] * 100:.0f}%)\n"
                    f"  - Temporal Campaign Decay: [cyan]{r['breakdown']['time']:.4f}[/cyan] (Weight: {effective_weights['time'] * 100:.0f}%)\n\n"
                    f"[bold]Shared Entities ({len(r['shared_entities'])}):[/bold]\n"
                    + "\n".join(
                        [
                            f"  - `[{e['type']}]` {e['value']} ({e['context']})"
                            for e in r["shared_entities"]
                        ]
                    )
                    + (
                        f"\n\n[bold]Shared MITRE Techniques:[/bold] {', '.join(r['shared_techniques']) or 'None'}"
                    )
                    + (
                        f"\n[bold]Shared MITRE Tactics:[/bold] {', '.join(r['shared_tactics']) or 'None'}"
                    )
                    + f"\n\n[bold]Summary Analysis:[/bold]\n{(r['summary'] or '')[:250]}...",
                    title=f"Match #{idx} Details",
                    border_style="cyan",
                )
            )


@app.command("info")
def info_cmd(
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Display statistics, vector status, and summary of reports stored in AlloyDB."""
    manager = AlloyDBManager(env_file=env_file)
    try:
        stats = manager.get_info()
    except Exception as e:
        console.print(f"[red]Failed to get AlloyDB info: {e}[/red]")
        raise typer.Exit(code=1)

    table = Table(title="AlloyDB Detection Reports Grounding Stats", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold green")

    table.add_row("Total Detection Reports", str(stats["total_reports"]))
    total = stats["total_reports"]
    emb_count = stats["total_embedded"]
    pct = (emb_count / total * 100) if total > 0 else 0
    table.add_row("Vector Embeddings (768-dim)", f"{emb_count}/{total} ({pct:.1f}%)")
    table.add_row("Total Linked Alerts", str(stats["total_alerts"]))
    table.add_row("Total Linked Entities", str(stats["total_entities"]))
    table.add_row("Reports Table Size", str(stats["reports_size"]))
    table.add_row("Database Total Size", str(stats["db_size"]))

    verdict_str = ", ".join([f"{k}: {v}" for k, v in stats["verdicts"].items()])
    table.add_row("Verdict Breakdown", verdict_str or "None")

    conf_str = ", ".join([f"{k}: {v}" for k, v in stats["confidences"].items()])
    table.add_row("Confidence Breakdown", conf_str or "None")

    console.print(table)


@app.command("profiles")
def list_profiles_cmd():
    """List all predefined similarity scoring profiles and their weight distributions."""
    table = Table(
        title="Multi-Modal Similarity Scoring Profiles for AlloyDB",
        box=box.ROUNDED,
    )
    table.add_column("Profile Key", style="bold cyan")
    table.add_column("Profile Name", style="bold white")
    table.add_column("Description", style="white")
    table.add_column("Semantic (Sem)", justify="right", style="yellow")
    table.add_column("Entity (Ent)", justify="right", style="green")
    table.add_column("TTP (MITRE)", justify="right", style="magenta")
    table.add_column("Flow (Steps)", justify="right", style="blue")
    table.add_column("Time (Decay)", justify="right", style="cyan")

    for key, p in SIMILARITY_PROFILES.items():
        w = p["weights"]
        table.add_row(
            key,
            p["name"],
            p["description"],
            f"{w['semantic'] * 100:.0f}%",
            f"{w['entity'] * 100:.0f}%",
            f"{w['ttp'] * 100:.0f}%",
            f"{w['flow'] * 100:.0f}%",
            f"{w['time'] * 100:.0f}%",
        )

    console.print(table)


@app.command("report")
def generate_report_cmd(
    investigation_id: Annotated[
        str,
        typer.Argument(
            help="Target investigation ID (UUID or substring) to analyze.",
        ),
    ],
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            "-p",
            help="Scoring profile: 'balanced', 'threat-hunt', 'compromise-pivot', 'false-positive', 'semantic'.",
        ),
    ] = "threat-hunt",
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            "-l",
            help="Maximum similar reports to compare against.",
        ),
    ] = 5,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai/--no-ai",
            help="Enable Gemini AI threat intelligence synthesis in the report.",
        ),
    ] = True,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Path to save the generated Markdown report.",
        ),
    ] = None,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Generate a Markdown investigation similarity report with optional Gemini AI threat synthesis."""
    manager = AlloyDBManager(env_file=env_file)
    try:
        console.print(
            f"[blue]Generating similarity report for '{investigation_id}' using profile '{profile}' (AI: {ai})...[/blue]"
        )
        md_content, saved_path = manager.generate_similarity_report(
            investigation_id=investigation_id,
            limit=limit,
            profile=profile,
            use_ai=ai,
            output_file=output,
        )
        console.print(
            Panel.fit(
                f"[bold green]Similarity Report Generated Successfully![/bold green]\n"
                f"Report Path: [cyan]{saved_path}[/cyan]\n"
                f"Target Investigation: [bold]{investigation_id}[/bold]\n"
                f"Profile: [magenta]{profile}[/magenta]\n"
                f"AI Synthesis: [yellow]{'Enabled (Vertex AI Gemini)' if ai else 'Disabled (Template Only)'}[/yellow]",
                title="Report Generation",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(f"[red]Error generating similarity report: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("clear")
def clear_cmd(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Skip confirmation prompt before clearing data.",
        ),
    ] = False,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            "-e",
            help="Path to .env configuration file.",
            exists=True,
        ),
    ] = Path(".env"),
):
    """Clear all detection reports, alerts, and entities from AlloyDB."""
    if not force:
        confirm = typer.confirm(
            "Are you sure you want to clear all detection reports from AlloyDB?"
        )
        if not confirm:
            console.print("[yellow]Clear operation cancelled.[/yellow]")
            return

    manager = AlloyDBManager(env_file=env_file)
    manager.clear()


@app.command("start")
def start_local_container():
    """Start a local PostgreSQL/pgvector container via Podman for local development."""
    console.print(
        "[blue]Starting local AlloyDB/PostgreSQL container via Podman...[/blue]"
    )
    cmd = [
        "podman",
        "run",
        "-d",
        "--name",
        "alloydb_soc",
        "-p",
        "5432:5432",
        "-e",
        "POSTGRES_USER=postgres",
        "-e",
        "POSTGRES_PASSWORD=password",
        "-e",
        "POSTGRES_DB=secops",
        "-v",
        "alloydb_data:/var/lib/postgresql/data:Z",
        "pgvector/pgvector:pg16",
    ]
    try:
        subprocess.run(cmd, check=True)
        console.print(
            "[green]Local AlloyDB/PostgreSQL container 'alloydb_soc' started on port 5432.[/green]"
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to start local container: {e}[/red]")


@app.command("stop")
def stop_local_container():
    """Stop and remove the local PostgreSQL/AlloyDB container."""
    console.print("[yellow]Stopping local container 'alloydb_soc'...[/yellow]")
    try:
        subprocess.run(["podman", "stop", "alloydb_soc"], check=True)
        subprocess.run(["podman", "rm", "alloydb_soc"], check=True)
        console.print(
            "[green]Local container 'alloydb_soc' stopped and removed.[/green]"
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error stopping container: {e}[/red]")


if __name__ == "__main__":
    app()
