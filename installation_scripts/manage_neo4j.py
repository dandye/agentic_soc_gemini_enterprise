#!/usr/bin/env python3
"""
Neo4j Management CLI for Security Operations Knowledge Graph

This script handles database connections, graph clearing, and ingestion
of nodes and edges from the investigations/knowledge_graph.json file.
"""

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from neo4j import GraphDatabase, exceptions


app = typer.Typer(
    add_completion=False,
    help="Manage Neo4j Graph Database for the Google MCP Security Agent.",
)


class Neo4jManager:
    """Manages connection, schema setup, and ingestion for Neo4j."""

    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_root = Path.cwd()

        self.uri = self.env_vars.get("NEO4J_URI", "bolt://localhost:7687")
        self.user = self.env_vars.get("NEO4J_USER", "neo4j")
        self.password = self.env_vars.get("NEO4J_PASSWORD", "password")
        self.graph_path = self.project_root / "investigations" / "knowledge_graph.json"

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def get_driver(self) -> GraphDatabase:
        """Initialize and return the Neo4j driver."""
        return GraphDatabase.driver(self.uri, auth=(self.user, self.password))

    def test_connection(self) -> bool:
        """Test connection to the Neo4j database."""
        try:
            with self.get_driver() as driver:
                driver.verify_connectivity()
            return True
        except exceptions.ServiceUnavailable as e:
            typer.echo(f"Neo4j Service Unavailable: {e}", err=True)
            return False
        except exceptions.AuthError as e:
            typer.echo(f"Neo4j Auth Error: {e}", err=True)
            return False
        except Exception as e:
            typer.echo(f"Unexpected connection error: {e}", err=True)
            return False

    def clear_database(self) -> None:
        """Delete all nodes and relationships from the database."""
        typer.echo("Clearing all data from Neo4j...")
        query = "MATCH (n) DETACH DELETE n"
        with self.get_driver() as driver:
            with driver.session() as session:
                session.run(query)
        typer.echo("Database cleared successfully.")

    def create_constraints(self) -> None:
        """Create uniqueness constraints for fast lookups and clean merges."""
        labels = [
            "Investigation",
            "Alert",
            "Case",
            "Host",
            "User",
            "File",
            "Domain",
            "NetworkAddress",
        ]
        with self.get_driver() as driver:
            with driver.session() as session:
                for label in labels:
                    # Neo4j Cypher constraints differ slightly by version,
                    # but CREATE CONSTRAINT IF NOT EXISTS is widely supported.
                    prop = (
                        "name"
                        if label in ["Host", "User", "File", "Domain", "NetworkAddress"]
                        else "id"
                    )
                    query = f"CREATE CONSTRAINT {label.lower()}_id_unique IF NOT EXISTS FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
                    try:
                        session.run(query)
                    except Exception as e:
                        typer.echo(
                            f"Warning: Could not create constraint for {label}: {e}"
                        )

    def ingest_graph(self) -> None:
        """Load, parse, and upload the knowledge graph to Neo4j in batches."""
        if not self.graph_path.exists():
            typer.echo(
                f"Error: Knowledge graph file not found at {self.graph_path}", err=True
            )
            raise typer.Exit(code=1)

        typer.echo(f"Reading knowledge graph from {self.graph_path}...")
        with open(self.graph_path) as f:
            data = json.load(f)

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        typer.echo(f"Found {len(nodes)} nodes and {len(edges)} edges to ingest.")

        # Ensure uniqueness constraints are set up
        self.create_constraints()

        # Ingest nodes in batches
        typer.echo("Ingesting nodes...")
        batch_size = 500
        with self.get_driver() as driver:
            with driver.session() as session:
                for i in range(0, len(nodes), batch_size):
                    batch = nodes[i : i + batch_size]
                    # We can use a simpler approach without apoc if apoc is not installed:
                    # Since labels are dynamic, we group nodes by label and run label-specific MERGE queries.
                    grouped_nodes = {}
                    for node in batch:
                        lbl = node.get("label", "Entity")
                        # standard labels like 'network address' with spaces should be stripped or camel-cased
                        lbl_clean = "".join(
                            x.capitalize() for x in lbl.replace(" ", "_").split("_")
                        )
                        grouped_nodes.setdefault(lbl_clean, []).append(node)

                    for label_clean, label_nodes in grouped_nodes.items():
                        # Determine unique identifier property name
                        prop_name = (
                            "name"
                            if label_clean
                            in ["Host", "User", "File", "Domain", "NetworkAddress"]
                            else "id"
                        )

                        # cypher query
                        cypher = f"""
                        UNWIND $nodes AS node_data
                        MERGE (n:{label_clean} {{{prop_name}: node_data.id}})
                        SET n += node_data.properties
                        """
                        # We pass node_data.id into name/id property appropriately.
                        # We must map the 'id' field in properties to the correct slot.
                        nodes_payload = []
                        for n in label_nodes:
                            nid = n["id"]
                            # For user/host nodes, the ID is like "user:frank.kolzig" or "host:WRK-SHASEK"
                            # We want to store the actual name without the prefix "user:" or "host:" in properties
                            clean_id = nid.split(":", 1)[1] if ":" in nid else nid

                            props = n.get("properties", {})
                            if prop_name == "name" and "name" not in props:
                                props["name"] = clean_id
                            elif prop_name == "id" and "id" not in props:
                                props["id"] = clean_id

                            nodes_payload.append({"id": clean_id, "properties": props})

                        session.run(cypher, nodes=nodes_payload)

                    typer.echo(
                        f"  Ingested {min(i + batch_size, len(nodes))}/{len(nodes)} nodes"
                    )

        # Ingest edges in batches
        typer.echo("Ingesting edges...")
        with self.get_driver() as driver:
            with driver.session() as session:
                for i in range(0, len(edges), batch_size):
                    batch = edges[i : i + batch_size]

                    # Group edges by type to do batch relationship creation
                    grouped_edges = {}
                    for edge in batch:
                        etype = edge.get("type", "INVOLVES")
                        grouped_edges.setdefault(etype, []).append(edge)

                    for etype_clean, etype_edges in grouped_edges.items():
                        payload = []
                        for edge in etype_edges:
                            src_id = edge["source"]
                            tgt_id = edge["target"]

                            # Parse labels from source/target prefixes (e.g. "user:frank" -> label User, id frank)
                            src_lbl = "Entity"
                            src_clean_id = src_id
                            if ":" in src_id:
                                prefix, src_clean_id = src_id.split(":", 1)
                                src_lbl = "".join(
                                    x.capitalize()
                                    for x in prefix.replace(" ", "_").split("_")
                                )

                            tgt_lbl = "Entity"
                            tgt_clean_id = tgt_id
                            if ":" in tgt_id:
                                prefix, tgt_clean_id = tgt_id.split(":", 1)
                                tgt_lbl = "".join(
                                    x.capitalize()
                                    for x in prefix.replace(" ", "_").split("_")
                                )

                            payload.append(
                                {
                                    "src_id": src_clean_id,
                                    "src_lbl": src_lbl,
                                    "tgt_id": tgt_clean_id,
                                    "tgt_lbl": tgt_lbl,
                                }
                            )

                        # In Cypher, dynamic labels on MERGE are not supported directly in parameter,
                        # so we run match-by-match or use a helper query. Since they might be heterogeneous,
                        # we can group them by (src_lbl, tgt_lbl) combinations.
                        lbl_groups = {}
                        for edge_data in payload:
                            key = (edge_data["src_lbl"], edge_data["tgt_lbl"])
                            lbl_groups.setdefault(key, []).append(edge_data)

                        for (src_lbl, tgt_lbl), group_edges in lbl_groups.items():
                            src_prop = (
                                "name"
                                if src_lbl
                                in ["Host", "User", "File", "Domain", "NetworkAddress"]
                                else "id"
                            )
                            tgt_prop = (
                                "name"
                                if tgt_lbl
                                in ["Host", "User", "File", "Domain", "NetworkAddress"]
                                else "id"
                            )

                            cypher = f"""
                            UNWIND $relationships AS rel
                            MATCH (s:{src_lbl} {{{src_prop}: rel.src_id}})
                            MATCH (t:{tgt_lbl} {{{tgt_prop}: rel.tgt_id}})
                            MERGE (s)-[r:{etype_clean}]->(t)
                            """
                            session.run(cypher, relationships=group_edges)

                    typer.echo(
                        f"  Ingested {min(i + batch_size, len(edges))}/{len(edges)} edges"
                    )

        typer.echo("Knowledge graph ingestion complete.")


@app.command("test-connection")
def test_conn(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Test connection to the Neo4j database."""
    manager = Neo4jManager(env_file)
    if manager.test_connection():
        typer.echo("SUCCESS: Connected to Neo4j successfully!")
    else:
        typer.echo("FAILURE: Failed to connect to Neo4j.", err=True)
        raise typer.Exit(code=1)


@app.command("clear")
def clear_db(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Force clearing without confirmation")
    ] = False,
) -> None:
    """Clear the entire Neo4j database."""
    if not force:
        confirm = typer.confirm("Are you sure you want to delete all data in Neo4j?")
        if not confirm:
            typer.echo("Operation cancelled.")
            raise typer.Exit()
    manager = Neo4jManager(env_file)
    manager.clear_database()


@app.command("ingest")
def ingest_data(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Ingest the local knowledge_graph.json file into Neo4j."""
    manager = Neo4jManager(env_file)
    if not manager.test_connection():
        typer.echo("Error: Neo4j is not reachable. Ingestion aborted.", err=True)
        raise typer.Exit(code=1)
    manager.ingest_graph()


@app.command("recalc")
def recalc_graph(
    dir: Annotated[
        str, typer.Option(help="Directory containing harvested JSONs.")
    ] = "investigations",
) -> None:
    """Recalculate the SOC Threat Graph from harvested JSON telemetry."""
    import subprocess

    typer.echo(f"Recalculating graph from {dir}...")
    script_path = Path(__file__).parent / "recalc_graph.py"
    cmd = ["python", str(script_path), "--dir", dir]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        typer.echo(result.stdout)
        typer.echo("SUCCESS: Graph recalculated successfully!")
    else:
        typer.echo("FAILURE: Failed to recalculate graph.", err=True)
        typer.echo(result.stderr, err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
