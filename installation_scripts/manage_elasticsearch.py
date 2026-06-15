#!/usr/bin/env python3
"""
Elasticsearch Index Manager for Runbooks

This script manages Elasticsearch operations including listing, creating,
and deleting indices, and indexing local Markdown runbooks from submodules.
"""

import hashlib
import os
import re
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from elasticsearch import Elasticsearch, NotFoundError


app = typer.Typer(
    add_completion=False,
    help="Manage Elasticsearch index for the Google MCP Security Agent.",
)

# Patterns to EXCLUDE (cruft)
EXCLUDE_PATTERNS = [
    "**/soar_integrations/**",
    "**/soar_integrations",
    "**/SuperClaude_Framework/**",
    "**/SuperClaude/**",
    "**/reports/**",
    "**/mcp-security/docs/servers/**",
    "**/mcp-security/server/**",
    "**/mcp-security/run-with-google-adk/**",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "CONTRIBUTING",
    "LICENSE",
    "LICENSE.md",
    "CHANGELOG.md",
    "ROADMAP.md",
    "SECURITY.md",
    "MANIFEST.in",
    "VERSION",
    "README.md",
    "readme.md",
    "SETUP_CLAUDE.md",
    "SUPERCLAUDE_INTEGRATION_SUMMARY.md",
    "LLMS.md",
    "LLMS-THESAURUS.md",
    "LLMS-SITEMAP.md",
    "CLAUDE.md",
    "GEMINI.md",
    "EXAMPLE_PROMPTS.md",
    "pyproject.toml",
    "setup.py",
    "uv.lock",
    "requirements*.txt",
    "Makefile",
    "*.sh",
    ".*/**",
    ".github/**",
    ".claude/**",
    ".clinerules/**",
    ".gemini/**",
    "**/tests/**",
]


# Paths relative to the submodule root
INCLUDE_DIRECTORIES = [
    "rules_bank/run_books",
    "rules_bank/personas",
    "rules_bank/run_books/common_steps",
    "rules_bank/run_books/irps",
    "rules_bank/run_books/guidelines",
    "rules-bank/run_books",
    "rules-bank/personas",
    "rules-bank/run_books/common_steps",
    "rules-bank/run_books/irps",
    "rules-bank/run_books/guidelines",
    "rules-bank/atomic_runbooks",
    "rules-bank/ai",
    "rules-bank/multi_agent",
    "rules-bank/tools",
]


class ElasticsearchManager:
    """Manages Elasticsearch index and synchronization of runbooks."""

    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_root = Path.cwd()

        self.es_url = self.env_vars.get("ELASTICSEARCH_URL", "http://localhost:9200")
        self.es_api_key = self.env_vars.get("ELASTICSEARCH_API_KEY")
        self.es_user = self.env_vars.get("ELASTICSEARCH_USER")
        self.es_password = self.env_vars.get("ELASTICSEARCH_PASSWORD")
        self.index_name = self.env_vars.get(
            "ELASTICSEARCH_INDEX", "agentic-soc-runbooks"
        )

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def get_client(self) -> Elasticsearch:
        """Initialize and return the Elasticsearch client."""
        # Disable certificate verification warnings for self-signed certificates
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        client_kwargs = {"verify_certs": False, "ssl_show_warn": False}

        if self.es_api_key:
            return Elasticsearch(self.es_url, api_key=self.es_api_key, **client_kwargs)
        elif self.es_user and self.es_password:
            return Elasticsearch(
                self.es_url,
                basic_auth=(self.es_user, self.es_password),
                **client_kwargs,
            )
        else:
            return Elasticsearch(self.es_url, **client_kwargs)

    def _should_exclude(self, file_path: Path) -> bool:
        """Check if a file should be excluded based on patterns."""
        rel_path = file_path.relative_to(self.project_root)
        str_path = str(rel_path)
        name = file_path.name

        for pattern in EXCLUDE_PATTERNS:
            if not pattern.startswith("*"):
                if name == pattern:
                    return True
        for pattern in EXCLUDE_PATTERNS:
            if "**" in pattern or "*" in pattern:
                import fnmatch

                pattern_parts = pattern.replace("**", "*").split("/")
                path_parts = str_path.split("/")
                for i, part in enumerate(pattern_parts):
                    if part == "*":
                        continue
                    if "*" in part:
                        if any(fnmatch.fnmatch(p, part) for p in path_parts):
                            if pattern.endswith("/**") or pattern.endswith("/*"):
                                return True
                    elif part in path_parts:
                        if pattern.endswith("/**"):
                            return True

        if (
            "soar_integrations" in str_path
            or "SuperClaude" in str_path
            or "/reports/" in str_path
            or str_path.startswith("reports/")
        ):
            return True

        # Do not exclude the external folder itself since our files live under external/ submodules,
        # but exclude other subdirectories inside external that are not runbooks.
        if str_path.startswith("external/"):
            if not (
                str_path.startswith("external/ai-runbooks/")
                or str_path.startswith("external/adk_runbooks/")
            ):
                return True
        if "/external/mcp-security/" in str_path or str_path.startswith(
            "external/mcp-security"
        ):
            return True

        return False

    def _is_in_include_directory(self, file_path: Path, submodule_dir: str) -> bool:
        """Check if file is in an explicitly included directory relative to its submodule."""
        # Find path relative to external/submodule
        submodule_path = self.project_root / "external" / submodule_dir
        try:
            rel_submodule = str(file_path.relative_to(submodule_path))
            for inc_dir in INCLUDE_DIRECTORIES:
                if rel_submodule.startswith(inc_dir):
                    return True
        except ValueError:
            pass
        return False

    def get_runbook_files(self) -> list[Path]:
        """Scan submodules inside external/ and return files to index."""
        files = []
        for submodule_dir in ["ai-runbooks", "adk_runbooks"]:
            source_path = self.project_root / "external" / submodule_dir
            if source_path.exists():
                # Get md and txt files
                found_files = list(source_path.rglob("*.md")) + list(
                    source_path.rglob("*.txt")
                )
                for file_path in found_files:
                    if self._should_exclude(file_path):
                        continue
                    if self._is_in_include_directory(file_path, submodule_dir):
                        files.append(file_path)

        # Scan harvested_investigations/
        harvested_path = self.project_root / "harvested_investigations"
        if harvested_path.exists():
            for file_path in harvested_path.rglob("*.md"):
                if not self._should_exclude(file_path):
                    files.append(file_path)

        return sorted(set(files))

    def chunk_document(
        self, content: str, max_chunk_size: int = 3000, overlap: int = 300
    ) -> list[dict]:
        """Split a Markdown document into section-aware chunks."""
        # Split document by markdown headings
        sections = re.split(r"(^|\n)(?=#[#\s])", content)
        chunks = []
        current_chunk = ""
        current_title = "Untitled"

        for section in sections:
            if not section.strip():
                continue

            # If section starts with a heading, extract title
            match = re.match(r"^(#+)\s+(.+)", section.strip())
            if match:
                if current_chunk.strip():
                    chunks.append(
                        {"title": current_title, "content": current_chunk.strip()}
                    )
                    current_chunk = ""
                current_title = match.group(2).strip()

            # If section is small, add to current chunk or create new one
            if len(current_chunk) + len(section) < max_chunk_size:
                current_chunk += "\n\n" + section
            else:
                if current_chunk.strip():
                    chunks.append(
                        {"title": current_title, "content": current_chunk.strip()}
                    )

                # If the single section exceeds max_chunk_size, split by paragraph
                if len(section) > max_chunk_size:
                    paragraphs = section.split("\n\n")
                    temp_chunk = ""
                    for para in paragraphs:
                        if len(temp_chunk) + len(para) < max_chunk_size:
                            temp_chunk += "\n\n" + para
                        else:
                            if temp_chunk.strip():
                                chunks.append(
                                    {
                                        "title": current_title,
                                        "content": temp_chunk.strip(),
                                    }
                                )
                            temp_chunk = para
                    if temp_chunk.strip():
                        chunks.append(
                            {"title": current_title, "content": temp_chunk.strip()}
                        )
                    current_chunk = ""
                else:
                    current_chunk = section

        if current_chunk.strip():
            chunks.append({"title": current_title, "content": current_chunk.strip()})

        return chunks

    def recreate_index(self) -> None:
        """Create or recreate the Elasticsearch index with mappings."""
        client = self.get_client()
        try:
            if client.indices.exists(index=self.index_name):
                typer.echo(f"Deleting existing index '{self.index_name}'...")
                client.indices.delete(index=self.index_name)
        except NotFoundError:
            pass

        mappings = {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "title": {"type": "text", "analyzer": "standard"},
                    "doc_name": {"type": "keyword"},
                    "doc_path": {"type": "keyword"},
                    "content": {"type": "text", "analyzer": "standard"},
                    "chunk_index": {"type": "integer"},
                }
            },
        }

        typer.echo(f"Creating index '{self.index_name}'...")
        client.indices.create(index=self.index_name, body=mappings)
        typer.secho(
            f"Index '{self.index_name}' created successfully.", fg=typer.colors.GREEN
        )

    def sync_to_elasticsearch(self, recreate: bool = False) -> None:
        """Sync runbook files to Elasticsearch."""
        client = self.get_client()

        if recreate or not client.indices.exists(index=self.index_name):
            self.recreate_index()

        runbooks = self.get_runbook_files()
        typer.echo(
            f"Found {len(runbooks)} runbooks matching include folders. Indexing..."
        )

        indexed_chunks = 0
        for file_path in runbooks:
            rel_path = file_path.relative_to(self.project_root)
            try:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                typer.secho(f"Error reading file {rel_path}: {e}", fg=typer.colors.RED)
                continue

            chunks = self.chunk_document(content)
            for idx, chunk in enumerate(chunks):
                # Calculate a stable unique ID for the chunk
                chunk_id = hashlib.sha256(f"{rel_path}#{idx}".encode()).hexdigest()

                doc = {
                    "title": chunk["title"],
                    "doc_name": file_path.name,
                    "doc_path": str(rel_path),
                    "content": chunk["content"],
                    "chunk_index": idx,
                }

                client.index(index=self.index_name, id=chunk_id, document=doc)
                indexed_chunks += 1

        client.indices.refresh(index=self.index_name)
        typer.secho(
            f"Successfully synced {len(runbooks)} files ({indexed_chunks} chunks) to Elasticsearch.",
            fg=typer.colors.GREEN,
        )


@app.command()
def create(
    env_file: Annotated[Path, typer.Option(help="Path to .env file")] = Path(".env")
):
    """Recreate the Elasticsearch index (deletes existing data)."""
    manager = ElasticsearchManager(env_file)
    manager.recreate_index()


@app.command()
def sync(
    recreate: Annotated[
        bool, typer.Option("--recreate", help="Recreate index before syncing")
    ] = False,
    env_file: Annotated[Path, typer.Option(help="Path to .env file")] = Path(".env"),
):
    """Sync local runbooks into Elasticsearch."""
    manager = ElasticsearchManager(env_file)
    manager.sync_to_elasticsearch(recreate)


@app.command()
def search(
    query: str,
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max results")] = 3,
    env_file: Annotated[Path, typer.Option(help="Path to .env file")] = Path(".env"),
):
    """Search the runbooks index in Elasticsearch."""
    manager = ElasticsearchManager(env_file)
    client = manager.get_client()

    body = {
        "query": {"multi_match": {"query": query, "fields": ["title^2", "content"]}},
        "size": limit,
    }

    try:
        res = client.search(index=manager.index_name, body=body)
        hits = res["hits"]["hits"]
        typer.echo(
            f"Found {res['hits']['total']['value']} matches (showing top {len(hits)}):"
        )
        for hit in hits:
            source = hit["_source"]
            score = hit["_score"]
            typer.secho(
                f"\n[Score: {score:.4f}] {source['title']} ({source['doc_path']} - Chunk {source['chunk_index']})",
                fg=typer.colors.CYAN,
            )
            typer.echo("-" * 80)
            # Print a snippet of the content
            content_snippet = source["content"][:300].replace("\n", " ") + "..."
            typer.echo(content_snippet)
    except Exception as e:
        typer.secho(f"Search failed: {e}", fg=typer.colors.RED)


@app.command()
def info(
    env_file: Annotated[Path, typer.Option(help="Path to .env file")] = Path(".env")
):
    """Show details about the Elasticsearch index."""
    manager = ElasticsearchManager(env_file)
    client = manager.get_client()
    try:
        stats = client.indices.stats(index=manager.index_name)
        doc_count = stats["_all"]["primaries"]["docs"]["count"]
        size_bytes = stats["_all"]["primaries"]["store"]["size_in_bytes"]
        typer.echo(f"Index Name: {manager.index_name}")
        typer.echo(f"Document Count (chunks): {doc_count}")
        typer.echo(f"Storage Size: {size_bytes / 1024 / 1024:.2f} MB")
    except Exception as e:
        typer.secho(
            f"Index '{manager.index_name}' does not exist or error: {e}",
            fg=typer.colors.RED,
        )


if __name__ == "__main__":
    app()
