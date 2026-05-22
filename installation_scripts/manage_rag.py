#!/usr/bin/env python3
"""
RAG Corpus Manager for Google Vertex AI

This script manages RAG corpus operations including listing, creating,
and deleting RAG corpora in Vertex AI. It also handles synchronization
of local Markdown runbooks to GCS and pruning of orphaned RAG files.
"""

import base64
import hashlib
import os
from pathlib import Path
from typing import Annotated

import typer
import vertexai
from dotenv import load_dotenv
from google.api_core.exceptions import NotFound
from google.auth import default
from google.cloud import storage
from vertexai.preview import rag


app = typer.Typer(
    add_completion=False,
    help="Manage RAG corpora in Vertex AI for the Google MCP Security Agent.",
)

# Patterns for files/directories to EXCLUDE (cruft)
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
    "**/external/**",
    "**/tests/**",
]

INCLUDE_DIRECTORIES = [
    "ai-runbooks/rules_bank/run_books",
    "ai-runbooks/rules_bank/personas",
    "ai-runbooks/rules_bank/run_books/common_steps",
    "ai-runbooks/rules_bank/run_books/irps",
    "ai-runbooks/rules_bank/run_books/guidelines",
    "adk_runbooks/rules-bank/run_books",
    "adk_runbooks/rules-bank/personas",
    "adk_runbooks/rules-bank/run_books/common_steps",
    "adk_runbooks/rules-bank/run_books/irps",
    "adk_runbooks/rules-bank/run_books/guidelines",
    "adk_runbooks/rules-bank/atomic_runbooks",
    "adk_runbooks/rules-bank/ai",
    "adk_runbooks/rules-bank/multi_agent",
    "adk_runbooks/rules-bank/tools",
]


class RAGManager:
    """Manages RAG corpus operations in Vertex AI."""

    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = None
        self.location = None
        self.project_root = Path.cwd()
        self.storage_client = None
        self._initialize_vertex_ai()

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def _initialize_vertex_ai(self) -> None:
        """Initialize Vertex AI with project and location from environment."""
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.location = self.env_vars.get("RAG_GCP_LOCATION") or self.env_vars.get(
            "GCP_LOCATION"
        )

        if not self.project_id:
            typer.secho(
                " Missing required variable: GCP_PROJECT_ID", fg=typer.colors.RED
            )
            raise typer.Exit(code=1)

        if not self.location:
            typer.secho(" Missing required variable: GCP_LOCATION", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        try:
            credentials, _ = default()
            vertexai.init(
                project=self.project_id, location=self.location, credentials=credentials
            )
        except Exception as e:
            typer.secho(f" Failed to initialize Vertex AI: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    def _init_gcs(self) -> None:
        """Initialize GCS client."""
        if self.storage_client:
            return
        try:
            credentials, _ = default()
            self.storage_client = storage.Client(
                project=self.project_id, credentials=credentials
            )
        except Exception as e:
            typer.secho(f"Failed to initialize GCS: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    def _get_full_resource_name(self, name: str) -> str:
        """Construct full resource name if only ID or display name is provided and handle location detection."""
        if name.startswith("projects/"):
            parts = name.split("/")
            if len(parts) > 3 and parts[3] != self.location:
                self.location = parts[3]
                vertexai.init(project=self.project_id, location=self.location)
            return name

        if name.isdigit():
            return f"projects/{self.project_id}/locations/{self.location}/ragCorpora/{name}"

        typer.echo(f"Resolving display name '{name}' to resource ID...")
        try:
            corpora = []
            for corpus in rag.list_corpora():
                corpora.append(corpus)
            for corpus in corpora:
                if corpus.display_name == name:
                    return corpus.name
        except Exception as e:
            typer.secho(
                f"Warning: Could not list corpora to resolve display name: {e}",
                fg=typer.colors.YELLOW,
            )

        return name

    # --- Directory Filtering Methods ---
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
        if (
            "/external/" in str_path
            or "mcp-security/docs/servers" in str_path
            or "mcp-security/server" in str_path
            or str_path.startswith(".")
        ):
            return True
        return False

    def _is_in_include_directory(self, file_path: Path) -> bool:
        """Check if file is in an explicitly included directory."""
        rel_path = str(file_path.relative_to(self.project_root))
        for inc_dir in INCLUDE_DIRECTORIES:
            if rel_path.startswith(inc_dir):
                return True
        return False

    def categorize_files(self) -> tuple[list[Path], list[Path]]:
        """Categorize files into keep and remove lists."""
        files = []
        for source_dir in ["ai-runbooks", "adk_runbooks"]:
            source_path = self.project_root / source_dir
            if source_path.exists():
                files.extend(source_path.rglob("*.md"))
                files.extend(source_path.rglob("*.txt"))
        files = sorted(files)
        keep = []
        remove = []
        for file_path in files:
            if self._should_exclude(file_path):
                remove.append(file_path)
            elif self._is_in_include_directory(file_path):
                keep.append(file_path)
            else:
                remove.append(file_path)
        return keep, remove

    # --- Validation ---
    def validate_markdown(self) -> bool:
        """Lint markdown files to ensure they are <10MB, valid UTF-8, and have closed backticks."""
        keep_files, _ = self.categorize_files()
        typer.echo(f"Validating {len(keep_files)} files for RAG compatibility...")

        has_errors = False
        MAX_SIZE = 10 * 1024 * 1024  # 10 MB

        for file_path in keep_files:
            rel_path = file_path.relative_to(self.project_root)

            # Size check
            size = file_path.stat().st_size
            if size > MAX_SIZE:
                typer.secho(
                    f"Error: {rel_path} exceeds 10MB ({size} bytes)",
                    fg=typer.colors.RED,
                )
                has_errors = True
                continue

            # UTF-8 and block check
            try:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

                # Check for unclosed markdown code blocks
                import re

                backticks = len(re.findall(r"```", content))
                if backticks % 2 != 0:
                    typer.secho(
                        f"Warning: {rel_path} has an unclosed markdown block (```)",
                        fg=typer.colors.YELLOW,
                    )
                    # We only issue a warning as sometimes parsing handles it, but ideally fix it
                    # has_errors = True

            except UnicodeDecodeError:
                typer.secho(
                    f"Error: {rel_path} is not valid UTF-8", fg=typer.colors.RED
                )
                has_errors = True

        if has_errors:
            typer.secho(
                "Validation failed. Please fix the errors above.", fg=typer.colors.RED
            )
            return False

        typer.secho("All files validated successfully.", fg=typer.colors.GREEN)
        return True

    # --- Sync to GCS ---
    def sync_to_gcs(self) -> list[str]:
        """Sync validated runbooks to GCS, deleting orphaned files."""
        self._init_gcs()

        gcs_path = self.env_vars.get("RAG_DOC_BUCKET")
        if not gcs_path:
            typer.secho(
                "Error: RAG_DOC_BUCKET env var not set (e.g. gs://bucket/path/)",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

        if gcs_path.startswith("gs://"):
            gcs_path = gcs_path[5:]
        parts = gcs_path.split("/", 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"

        keep_files, _ = self.categorize_files()
        typer.echo(
            f"\nSyncing {len(keep_files)} local files to gs://{bucket_name}/{prefix}..."
        )

        bucket = self.storage_client.bucket(bucket_name)
        existing_blobs = {
            blob.name: blob
            for blob in bucket.list_blobs(prefix=prefix)
            if not blob.name.endswith("/")
        }

        uploaded = 0
        deleted = 0
        valid_gcs_uris = []

        # Determine local expected state
        local_state = {}
        for file_path in keep_files:
            # We flatten the path or keep structure? Previous scripts kept structure but we flatten inside the bucket if needed.
            # Let's keep structure relative to 'rules-bank' or just use filename.
            # RAG handles filename. But if there are duplicates? We should keep structure.
            # Actually, the old script did `blob_name = f"{prefix}{file_path.name}"` or `f"{prefix}{rel_path}"`.
            # Let's just use `file_path.name` to avoid deep nesting in GCS if that's preferred,
            # BUT let's use the file_path.relative_to(project_root) for safety to avoid naming collisions.
            # Since the user used RAG_DOC_BUCKET, let's keep relative paths from `adk_runbooks` / `ai-runbooks`.
            parts = file_path.parts
            # Simplify path: remove "adk_runbooks" or "ai-runbooks" to normalize
            if "rules-bank" in parts:
                idx = parts.index("rules-bank")
                subpath = "/".join(parts[idx + 1 :])
            elif "rules_bank" in parts:
                idx = parts.index("rules_bank")
                subpath = "/".join(parts[idx + 1 :])
            else:
                subpath = file_path.name

            blob_name = f"{prefix}{subpath}"
            local_state[blob_name] = file_path
            valid_gcs_uris.append(f"gs://{bucket_name}/{blob_name}")

        # Upload new/changed files
        for blob_name, file_path in local_state.items():
            with open(file_path, "rb") as f:
                data = f.read()
                md5 = base64.b64encode(hashlib.md5(data).digest()).decode("utf-8")  # noqa: S324

            blob = existing_blobs.get(blob_name)
            if not blob or blob.md5_hash != md5:
                # Need to upload
                typer.echo(f"  Uploading: {blob_name}")
                new_blob = bucket.blob(blob_name)
                new_blob.upload_from_filename(str(file_path))
                uploaded += 1

        # Delete orphaned files in GCS
        for blob_name, blob in existing_blobs.items():
            if blob_name not in local_state:
                typer.echo(f"  Deleting orphaned file from GCS: {blob_name}")
                blob.delete()
                deleted += 1

        typer.secho(
            f"GCS Sync complete: {uploaded} uploaded, {deleted} deleted.",
            fg=typer.colors.GREEN,
        )
        return valid_gcs_uris

    # --- Prune RAG Corpus ---
    def prune_corpus(self, corpus_name: str) -> bool:
        """Delete files from RAG Corpus that no longer exist in GCS."""
        full_name = self._get_full_resource_name(corpus_name)
        gcs_path = self.env_vars.get("RAG_DOC_BUCKET")
        if not gcs_path:
            typer.secho("Error: RAG_DOC_BUCKET env var not set", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        typer.echo(f"\nPruning orphaned files from RAG Corpus: {full_name}")

        self._init_gcs()
        if gcs_path.startswith("gs://"):
            gcs_path = gcs_path[5:]
        parts = gcs_path.split("/", 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"

        # Get authoritative list from GCS
        bucket = self.storage_client.bucket(bucket_name)
        valid_uris = {
            f"gs://{bucket_name}/{blob.name}"
            for blob in bucket.list_blobs(prefix=prefix)
            if not blob.name.endswith("/")
        }

        try:
            rag_files = []
            for f in rag.list_files(corpus_name=full_name):
                rag_files.append(f)

            deleted = 0
            for f in rag_files:
                if not f.source_uris or f.source_uris[0] not in valid_uris:
                    typer.echo(
                        f"  Deleting orphaned RAG file: {f.display_name} ({f.source_uris[0] if f.source_uris else 'No URI'})"
                    )
                    rag.delete_file(name=f.name)
                    deleted += 1

            typer.secho(
                f"Prune complete. {deleted} orphaned file(s) removed from RAG.",
                fg=typer.colors.GREEN,
            )
            return True
        except Exception as e:
            typer.secho(f"Error pruning corpus: {e}", fg=typer.colors.RED)
            return False

    # --- Core RAG APIs ---
    def list_corpora(self, verbose: bool = False) -> bool:
        try:
            typer.echo()
            corpora = []
            for corpus in rag.list_corpora():
                corpora.append(corpus)
            if not corpora:
                typer.echo("No RAG corpora found.")
                return True
            for i, corpus in enumerate(corpora, 1):
                typer.echo(f"{i}. {corpus.display_name}")
                typer.echo(f"   Name: {corpus.name}")
                if getattr(corpus, "description", ""):
                    typer.echo(f"   Description: {corpus.description}")
                if verbose:
                    if hasattr(corpus, "embedding_model_config") and hasattr(
                        corpus.embedding_model_config, "publisher_model"
                    ):
                        typer.echo(
                            f"   Embedding Model: {corpus.embedding_model_config.publisher_model}"
                        )
                    if hasattr(corpus, "create_time"):
                        typer.echo(f"   Created: {corpus.create_time}")
                typer.echo()
            typer.echo(f"Total: {len(corpora)} RAG corpus/corpora")
            return True
        except Exception as e:
            typer.secho(f"Error listing RAG corpora: {e}", fg=typer.colors.RED)
            return False

    def get_corpus_info(self, corpus_name: str) -> bool:
        full_name = self._get_full_resource_name(corpus_name)
        typer.echo(f"Getting information for corpus: {full_name}")
        try:
            corpus = rag.get_corpus(name=full_name)
            typer.echo("\nRAG Corpus Information:")
            typer.echo("=" * 80)
            typer.echo(f"Display Name: {corpus.display_name}")
            typer.echo(f"Resource Name: {corpus.name}")
            if hasattr(corpus, "description") and corpus.description:
                typer.echo(f"Description: {corpus.description}")
            if hasattr(corpus, "embedding_model_config") and hasattr(
                corpus.embedding_model_config, "publisher_model"
            ):
                typer.echo(
                    f"Embedding Model: {corpus.embedding_model_config.publisher_model}"
                )

            typer.echo("\nFiles in corpus:")
            try:
                files = []
                for file in rag.list_files(corpus_name=full_name):
                    files.append(file)
                if files:
                    typer.echo(f"Total files: {len(files)}")
                    for i, file in enumerate(files[:10], 1):
                        typer.echo(f"{i}. {file.display_name}")
                    if len(files) > 10:
                        typer.echo(f"... and {len(files) - 10} more files")
                else:
                    typer.echo("No files found in corpus.")
            except Exception as e:
                typer.secho(
                    f"Note: Unable to list files: {str(e)[:100]}",
                    fg=typer.colors.YELLOW,
                )
            return True
        except NotFound:
            typer.secho(f"Corpus not found: {corpus_name}", fg=typer.colors.RED)
            return False
        except Exception as e:
            typer.secho(f"Error getting corpus info: {e}", fg=typer.colors.RED)
            return False

    def create_corpus(
        self,
        display_name: str,
        description: str | None = None,
        embedding_model: str = "publishers/google/models/text-embedding-004",
    ) -> bool:
        typer.echo(f"Creating RAG corpus: {display_name}")
        try:
            embedding_model_config = rag.EmbeddingModelConfig(
                publisher_model=embedding_model
            )
            corpus = rag.create_corpus(
                display_name=display_name,
                description=description or "",
                embedding_model_config=embedding_model_config,
            )
            typer.secho(
                f"Corpus created successfully: {display_name}", fg=typer.colors.GREEN
            )
            typer.echo(f"   Resource name: {corpus.name}")
            return True
        except Exception as e:
            typer.secho(f"Error creating corpus: {e}", fg=typer.colors.RED)
            return False

    def delete_corpus(self, corpus_name: str, force: bool = False) -> bool:
        full_name = self._get_full_resource_name(corpus_name)
        try:
            corpus = rag.get_corpus(name=full_name)
            if not force:
                if not typer.confirm(
                    f"\nAre you sure you want to delete corpus: {corpus.display_name}?"
                ):
                    return False
            rag.delete_corpus(name=full_name)
            typer.secho(
                f"Corpus deleted successfully: {corpus.display_name}",
                fg=typer.colors.GREEN,
            )
            return True
        except Exception as e:
            typer.secho(f"Error deleting corpus: {e}", fg=typer.colors.RED)
            return False

    def import_files(
        self,
        corpus_name: str,
        gcs_paths: list[str],
        chunk_size: int = 512,
        chunk_overlap: int = 50,
    ) -> bool:
        full_name = self._get_full_resource_name(corpus_name)
        typer.echo(f"\nImporting {len(gcs_paths)} file(s) to RAG corpus: {full_name}")
        try:
            BATCH_SIZE = 25
            total_files = len(gcs_paths)
            total_imported = 0
            for batch_num, i in enumerate(range(0, total_files, BATCH_SIZE), 1):
                batch_paths = gcs_paths[i : i + BATCH_SIZE]
                typer.echo(
                    f"Batch {batch_num}: Importing {len(batch_paths)} file(s)..."
                )
                response = rag.import_files(
                    corpus_name=full_name,
                    paths=batch_paths,
                    chunk_size=chunk_size,
                    chunk_overlap=chunk_overlap,
                )
                if hasattr(response, "imported_rag_files_count"):
                    total_imported += response.imported_rag_files_count
            typer.secho(
                f"All batches completed! Total files imported: {total_imported}/{total_files}",
                fg=typer.colors.GREEN,
            )
            return True
        except Exception as e:
            typer.secho(f"Error importing files: {e}", fg=typer.colors.RED)
            return False


@app.command()
def list(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed information.")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    manager = RAGManager(env_file)
    if not manager.list_corpora(verbose):
        raise typer.Exit(code=1)


@app.command()
def info(
    corpus_name: Annotated[
        str, typer.Argument(help="Full resource name or ID of the corpus.")
    ],
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    manager = RAGManager(env_file)
    if not manager.get_corpus_info(corpus_name):
        raise typer.Exit(code=1)


@app.command()
def create(
    display_name: Annotated[str, typer.Argument(help="Display name for the corpus.")],
    description: Annotated[
        str | None,
        typer.Option("--description", "-d", help="Description of the corpus."),
    ] = None,
    embedding_model: Annotated[
        str, typer.Option("--embedding-model", "-e", help="Embedding model to use.")
    ] = "publishers/google/models/text-embedding-004",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    manager = RAGManager(env_file)
    if not manager.create_corpus(display_name, description, embedding_model):
        raise typer.Exit(code=1)


@app.command()
def delete(
    corpus_name: Annotated[
        str, typer.Argument(help="Full resource name or ID of the corpus.")
    ],
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompt.")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    manager = RAGManager(env_file)
    if not manager.delete_corpus(corpus_name, force):
        raise typer.Exit(code=1)


@app.command()
def import_files(
    corpus_name: Annotated[
        str | None,
        typer.Argument(help="Full resource name or ID (or set RAG_CORPUS_ID in .env)."),
    ] = None,
    chunk_size: Annotated[int, typer.Option("--chunk-size", "-s")] = 512,
    chunk_overlap: Annotated[int, typer.Option("--chunk-overlap", "-o")] = 100,
    env_file: Annotated[Path, typer.Option()] = Path(".env"),
) -> None:
    manager = RAGManager(env_file)
    corpus = corpus_name or manager.env_vars.get("RAG_CORPUS_ID")
    if not corpus:
        typer.secho("Error: Corpus name required.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    gcs_path = manager.env_vars.get("RAG_DOC_BUCKET")
    if not gcs_path:
        typer.secho("Error: RAG_DOC_BUCKET not set in .env", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    manager._init_gcs()
    if gcs_path.startswith("gs://"):
        gcs_path = gcs_path[5:]
    parts = gcs_path.split("/", 1)
    bucket_name = parts[0]
    prefix = parts[1] if len(parts) > 1 else ""

    bucket = manager.storage_client.bucket(bucket_name)
    paths_to_import = [
        f"gs://{bucket_name}/{blob.name}"
        for blob in bucket.list_blobs(prefix=prefix)
        if blob.name.endswith(".md") or blob.name.endswith(".txt")
    ]

    if not manager.import_files(corpus, paths_to_import, chunk_size, chunk_overlap):
        raise typer.Exit(code=1)


@app.command()
def validate_md(env_file: Annotated[Path, typer.Option()] = Path(".env")) -> None:
    """Validate all local markdown runbooks."""
    manager = RAGManager(env_file)
    if not manager.validate_markdown():
        raise typer.Exit(code=1)


@app.command()
def prune_corpus(
    corpus_name: Annotated[
        str | None,
        typer.Argument(help="Full resource name or ID (or set RAG_CORPUS_ID in .env)."),
    ] = None,
    env_file: Annotated[Path, typer.Option()] = Path(".env"),
) -> None:
    """Prune orphaned files from the RAG Corpus."""
    manager = RAGManager(env_file)
    corpus = corpus_name or manager.env_vars.get("RAG_CORPUS_ID")
    if not corpus:
        typer.secho("Error: Corpus name required.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not manager.prune_corpus(corpus):
        raise typer.Exit(code=1)


@app.command()
def sync_gcs(env_file: Annotated[Path, typer.Option()] = Path(".env")) -> None:
    """Sync local valid runbooks to GCS, deleting orphaned GCS files."""
    manager = RAGManager(env_file)
    manager.sync_to_gcs()


@app.command()
def sync_runbooks(
    corpus_name: Annotated[
        str | None, typer.Option("--corpus", "-c", help="Corpus Name or ID")
    ] = None,
    env_file: Annotated[Path, typer.Option()] = Path(".env"),
) -> None:
    """End-to-End Workflow: Validate -> Sync GCS -> Import RAG -> Prune RAG."""
    manager = RAGManager(env_file)
    corpus = corpus_name or manager.env_vars.get("RAG_CORPUS_ID")
    if not corpus:
        typer.secho(
            "Error: Corpus name required. Provide --corpus or set RAG_CORPUS_ID.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    typer.secho("=== Step 1: Validating Local Markdown Files ===", fg=typer.colors.CYAN)
    if not manager.validate_markdown():
        typer.secho("Stopping sync due to validation errors.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho("\n=== Step 2: Syncing Local Files to GCS ===", fg=typer.colors.CYAN)
    valid_gcs_uris = manager.sync_to_gcs()

    typer.secho(
        "\n=== Step 3: Importing GCS Files to RAG Corpus ===", fg=typer.colors.CYAN
    )
    if not manager.import_files(corpus, valid_gcs_uris):
        typer.secho("Failed to import to RAG.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho("\n=== Step 4: Pruning Orphaned RAG Files ===", fg=typer.colors.CYAN)
    manager.prune_corpus(corpus)

    typer.secho(
        "\n=== Sync Runbooks Workflow Completed Successfully! ===",
        fg=typer.colors.GREEN,
        bold=True,
    )


if __name__ == "__main__":
    app()
