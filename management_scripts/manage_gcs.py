#!/usr/bin/env python3
"""
Google Cloud Storage Manager for RAG Corpus Imports

This script manages GCS operations for uploading local files
to be imported into Vertex AI RAG corpora.
"""

import builtins
import mimetypes
import os
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from google.auth import default
from google.cloud import storage
from google.cloud.exceptions import Conflict, NotFound


app = typer.Typer(
    add_completion=False,
    help="Manage Google Cloud Storage for RAG corpus imports.",
)


class GCSManager:
    """Manages Google Cloud Storage operations for RAG imports."""

    # RAG supported file extensions
    SUPPORTED_EXTENSIONS = {".pdf", ".txt", ".md", ".html", ".json", ".csv", ".tsv"}
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB limit for RAG

    def __init__(self, env_file: Path):
        """
        Initialize the GCS manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = None
        self.location = None
        self.default_bucket = None
        self.storage_client = None
        self._initialize_gcs()

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def _initialize_gcs(self) -> None:
        """Initialize GCS client and configuration."""
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.location = self.env_vars.get("GCP_LOCATION", "us-central1")
        self.default_bucket = self.env_vars.get("GCS_DEFAULT_BUCKET")

        if not self.project_id:
            typer.secho(
                " Missing required variable: GCP_PROJECT_ID",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

        try:
            credentials, _ = default()
            self.storage_client = storage.Client(
                project=self.project_id, credentials=credentials
            )
        except Exception as e:
            typer.secho(f" Failed to initialize GCS client: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    def _get_or_create_bucket(self, bucket_name: str | None = None) -> storage.Bucket:
        """
        Get existing bucket or create if it doesn't exist.

        Args:
            bucket_name: Name of the bucket. If None, uses default bucket.

        Returns:
            storage.Bucket object

        Raises:
            ValueError: If no bucket name is provided and no default is set
        """
        name = bucket_name or self.default_bucket
        if not name:
            raise ValueError("No bucket name provided and GCS_DEFAULT_BUCKET not set")

        try:
            bucket = self.storage_client.get_bucket(name)
            return bucket
        except NotFound:
            typer.echo(f"Bucket '{name}' not found. Creating...")
            try:
                bucket = self.storage_client.create_bucket(name, location=self.location)
                typer.secho(
                    f"Bucket '{name}' created successfully.", fg=typer.colors.GREEN
                )
                return bucket
            except Exception as e:
                typer.secho(f"Error creating bucket '{name}': {e}", fg=typer.colors.RED)
                raise

    def validate_file(self, file_path: Path) -> tuple[bool, str]:
        """
        Validate a file for RAG import.

        Args:
            file_path: Path to the file to validate

        Returns:
            Tuple of (is_valid, message)
        """
        # Check file exists
        if not file_path.exists():
            return False, f"File not found: {file_path}"

        # Check if it's a file (not directory)
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"

        # Check file extension
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return False, (
                f"Unsupported file type: {file_path.suffix}. "
                f"Supported types: {', '.join(sorted(self.SUPPORTED_EXTENSIONS))}"
            )

        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            size_mb = file_size / (1024 * 1024)
            return False, (
                f"File too large: {size_mb:.2f}MB (max 500MB). "
                f"Please split or compress the file."
            )

        return True, "Valid"

    def upload_file(
        self,
        file_path: Path,
        bucket_name: str | None = None,
        gcs_path: str | None = None,
        overwrite: bool = False,
    ) -> str:
        """
        Upload a single file to GCS.

        Args:
            file_path: Local path to the file
            bucket_name: Target bucket name
            gcs_path: Path within the bucket (if None, uses filename)
            overwrite: Whether to overwrite existing files

        Returns:
            GCS URI of the uploaded file (gs://bucket/path)

        Raises:
            ValueError: If file validation fails
            FileExistsError: If file exists and overwrite is False
        """
        # Validate file first
        is_valid, message = self.validate_file(file_path)
        if not is_valid:
            raise ValueError(message)

        # Get or create bucket
        bucket = self._get_or_create_bucket(bucket_name)

        # Determine blob name
        blob_name = gcs_path or file_path.name

        # Check if file already exists
        blob = bucket.blob(blob_name)
        if blob.exists() and not overwrite:
            raise FileExistsError(
                f"File already exists: gs://{bucket.name}/{blob_name}. "
                "Use --overwrite to replace it."
            )

        # Upload the file
        try:
            typer.echo(
                f"Uploading {file_path.name} to gs://{bucket.name}/{blob_name}..."
            )

            # Set content type
            content_type, _ = mimetypes.guess_type(str(file_path))
            if content_type:
                blob.content_type = content_type

            # Upload with progress
            blob.upload_from_filename(str(file_path))

            gcs_uri = f"gs://{bucket.name}/{blob_name}"
            typer.secho(f"Upload successful: {gcs_uri}", fg=typer.colors.GREEN)
            return gcs_uri

        except Exception as e:
            typer.secho(f"Error uploading file: {e}", fg=typer.colors.RED)
            raise

    def upload_files(
        self,
        file_paths: list[Path],
        bucket_name: str | None = None,
        gcs_path_prefix: str | None = None,
        overwrite: bool = False,
    ) -> list[str]:
        """
        Upload multiple files to GCS.

        Args:
            file_paths: List of local file paths
            bucket_name: Target bucket name
            gcs_path_prefix: Prefix for all uploaded files
            overwrite: Whether to overwrite existing files

        Returns:
            List of GCS URIs for uploaded files
        """
        uploaded_uris = []
        failed_files = []

        typer.echo(f"\nUploading {len(file_paths)} file(s)...")
        typer.echo()

        for i, file_path in enumerate(file_paths, 1):
            typer.echo(f"[{i}/{len(file_paths)}] {file_path.name}")

            try:
                # Construct GCS path if prefix is provided
                gcs_path = None
                if gcs_path_prefix:
                    gcs_path = f"{gcs_path_prefix.rstrip('/')}/{file_path.name}"

                uri = self.upload_file(file_path, bucket_name, gcs_path, overwrite)
                uploaded_uris.append(uri)

            except Exception as e:
                typer.secho(f"  Failed: {e}", fg=typer.colors.YELLOW)
                failed_files.append(file_path.name)

            typer.echo()

        # Summary
        typer.echo("=" * 80)
        typer.secho(
            f"Successfully uploaded: {len(uploaded_uris)}/{len(file_paths)}",
            fg=typer.colors.GREEN,
        )
        if failed_files:
            typer.secho(f"Failed uploads: {len(failed_files)}", fg=typer.colors.YELLOW)
            for filename in failed_files:
                typer.echo(f"  - {filename}")

        return uploaded_uris

    def list_buckets(self, verbose: bool = False) -> bool:
        """
        List all buckets in the project.

        Args:
            verbose: Show detailed information for each bucket

        Returns:
            True if successful, False otherwise
        """
        try:
            # Iterate directly over the iterator to avoid conversion issues
            buckets = []
            for bucket in self.storage_client.list_buckets():
                buckets.append(bucket)

            if not buckets:
                typer.echo("No buckets found in project.")
                return True

            typer.echo()
            for i, bucket in enumerate(buckets, 1):
                typer.echo(f"{i}. {bucket.name}")

                if verbose:
                    typer.echo(f"   Location: {bucket.location}")
                    typer.echo(f"   Storage Class: {bucket.storage_class}")
                    if bucket.time_created:
                        typer.echo(f"   Created: {bucket.time_created}")
                typer.echo()

            typer.echo(f"Total: {len(buckets)} bucket(s)")
            return True

        except Exception as e:
            typer.secho(f"Error listing buckets: {e}", fg=typer.colors.RED)
            return False

    def list_files(
        self,
        bucket_name: str | None = None,
        prefix: str | None = None,
        verbose: bool = False,
    ) -> bool:
        """
        List files in a GCS bucket.

        Args:
            bucket_name: Name of the bucket. If None, uses default bucket.
            prefix: Filter by prefix/path
            verbose: Show detailed file information

        Returns:
            True if successful, False otherwise
        """
        try:
            bucket = self._get_or_create_bucket(bucket_name)

            typer.echo(f"\nFiles in bucket: {bucket.name}")
            if prefix:
                typer.echo(f"Prefix: {prefix}")
            typer.echo()

            # Iterate directly over the iterator to avoid conversion issues
            blobs = []
            for blob in bucket.list_blobs(prefix=prefix):
                blobs.append(blob)

            if not blobs:
                typer.echo("No files found.")
                return True

            for i, blob in enumerate(blobs, 1):
                typer.echo(f"{i}. {blob.name}")

                if verbose:
                    size_mb = blob.size / (1024 * 1024)
                    typer.echo(f"   Size: {size_mb:.2f} MB")
                    typer.echo(f"   Content Type: {blob.content_type}")
                    if blob.updated:
                        typer.echo(f"   Updated: {blob.updated}")
                    typer.echo(f"   URI: gs://{bucket.name}/{blob.name}")

                typer.echo()

            typer.echo(f"Total: {len(blobs)} file(s)")
            return True

        except NotFound:
            typer.secho(f"Bucket not found: {bucket_name}", fg=typer.colors.RED)
            return False
        except Exception as e:
            typer.secho(f"Error listing files: {e}", fg=typer.colors.RED)
            return False

    def delete_file(
        self, gcs_uri: str, force: bool = False, dry_run: bool = False
    ) -> bool:
        """
        Delete a file from GCS.

        Args:
            gcs_uri: GCS URI (gs://bucket/path/to/file)
            force: Skip confirmation prompt
            dry_run: Show what would be deleted without actually deleting

        Returns:
            True if successful, False otherwise
        """
        # Parse GCS URI
        if not gcs_uri.startswith("gs://"):
            typer.secho("Error: URI must start with 'gs://'", fg=typer.colors.RED)
            return False

        uri_parts = gcs_uri[5:].split("/", 1)
        if len(uri_parts) != 2:
            typer.secho(
                "Error: Invalid GCS URI format. Use: gs://bucket/path/to/file",
                fg=typer.colors.RED,
            )
            return False

        bucket_name, blob_name = uri_parts

        try:
            bucket = self.storage_client.get_bucket(bucket_name)
            blob = bucket.blob(blob_name)

            if not blob.exists():
                typer.secho(f"File not found: {gcs_uri}", fg=typer.colors.YELLOW)
                return False

            # Show what will be deleted
            typer.echo(f"\nFile to delete: {gcs_uri}")
            if blob.size:
                size_mb = blob.size / (1024 * 1024)
                typer.echo(f"Size: {size_mb:.2f} MB")

            if dry_run:
                typer.echo("\n[DRY RUN] File would be deleted.")
                return True

            # Confirm deletion
            if not force:
                if not typer.confirm("\nAre you sure you want to delete this file?"):
                    typer.echo("Cancelled.")
                    return False

            # Delete the file
            blob.delete()
            typer.secho(
                f"\nFile deleted successfully: {gcs_uri}", fg=typer.colors.GREEN
            )
            return True

        except NotFound:
            typer.secho(f"Bucket not found: {bucket_name}", fg=typer.colors.RED)
            return False
        except Exception as e:
            typer.secho(f"Error deleting file: {e}", fg=typer.colors.RED)
            return False

    def delete_prefix(
        self, bucket_name: str, prefix: str, force: bool = False, dry_run: bool = False
    ) -> bool:
        """
        Delete all files with a given prefix.

        Args:
            bucket_name: Name of the bucket
            prefix: Prefix to match files for deletion
            force: Skip confirmation prompt
            dry_run: Show what would be deleted without actually deleting

        Returns:
            True if successful, False otherwise
        """
        try:
            bucket = self.storage_client.get_bucket(bucket_name)

            # Iterate directly over the iterator to avoid conversion issues
            blobs = []
            for blob in bucket.list_blobs(prefix=prefix):
                blobs.append(blob)

            if not blobs:
                typer.echo(f"No files found with prefix: {prefix}")
                return True

            # Show files to be deleted
            typer.echo(f"\nFiles to delete ({len(blobs)}):")
            for blob in blobs:
                typer.echo(f"  - gs://{bucket_name}/{blob.name}")

            if dry_run:
                typer.echo("\n[DRY RUN] Files would be deleted.")
                return True

            # Confirm deletion
            if not force:
                if not typer.confirm(
                    f"\nAre you sure you want to delete {len(blobs)} file(s)?"
                ):
                    typer.echo("Cancelled.")
                    return False

            # Delete files
            deleted_count = 0
            for blob in blobs:
                try:
                    blob.delete()
                    deleted_count += 1
                except Exception as e:
                    typer.secho(
                        f"Error deleting {blob.name}: {e}", fg=typer.colors.YELLOW
                    )

            typer.secho(
                f"\nDeleted {deleted_count}/{len(blobs)} file(s)", fg=typer.colors.GREEN
            )
            return True

        except NotFound:
            typer.secho(f"Bucket not found: {bucket_name}", fg=typer.colors.RED)
            return False
        except Exception as e:
            typer.secho(f"Error deleting files: {e}", fg=typer.colors.RED)
            return False

    def create_bucket(
        self,
        bucket_name: str,
        location: str | None = None,
        storage_class: str = "STANDARD",
    ) -> bool:
        """
        Create a new GCS bucket.

        Args:
            bucket_name: Name of the bucket to create
            location: Location for the bucket (defaults to self.location)
            storage_class: Storage class (STANDARD, NEARLINE, COLDLINE, ARCHIVE)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if bucket already exists
            try:
                existing_bucket = self.storage_client.get_bucket(bucket_name)
                typer.secho(
                    f"Bucket already exists: {bucket_name}", fg=typer.colors.YELLOW
                )
                typer.echo(f"Location: {existing_bucket.location}")
                typer.echo(f"Storage Class: {existing_bucket.storage_class}")
                return False
            except NotFound:
                pass  # Bucket doesn't exist, proceed with creation

            # Create the bucket
            bucket_location = location or self.location
            typer.echo(f"Creating bucket: {bucket_name}")
            typer.echo(f"Location: {bucket_location}")
            typer.echo(f"Storage Class: {storage_class}")

            bucket = self.storage_client.create_bucket(
                bucket_name, location=bucket_location
            )
            bucket.storage_class = storage_class
            bucket.patch()

            typer.secho(
                f"\nBucket created successfully: {bucket_name}", fg=typer.colors.GREEN
            )
            typer.echo(f"URI: gs://{bucket_name}")
            return True

        except Conflict:
            typer.secho(
                f"Bucket name already taken: {bucket_name}", fg=typer.colors.RED
            )
            typer.echo(
                "Bucket names must be globally unique across all Google Cloud projects."
            )
            return False
        except Exception as e:
            typer.secho(f"Error creating bucket: {e}", fg=typer.colors.RED)
            return False

    def get_bucket_info(self, bucket_name: str) -> bool:
        """
        Get detailed information about a bucket.

        Args:
            bucket_name: Name of the bucket

        Returns:
            True if successful, False otherwise
        """
        try:
            bucket = self.storage_client.get_bucket(bucket_name)

            typer.echo(f"\nBucket Information: {bucket_name}")
            typer.echo("=" * 80)
            typer.echo(f"Location: {bucket.location}")
            typer.echo(f"Storage Class: {bucket.storage_class}")
            typer.echo(f"Created: {bucket.time_created}")
            if bucket.labels:
                typer.echo(f"Labels: {bucket.labels}")

            # Count files
            blob_count = 0
            total_size = 0
            for blob in bucket.list_blobs():
                blob_count += 1
                total_size += blob.size

            typer.echo(f"\nFiles: {blob_count}")
            if total_size > 0:
                size_mb = total_size / (1024 * 1024)
                size_gb = total_size / (1024 * 1024 * 1024)
                if size_gb >= 1:
                    typer.echo(f"Total Size: {size_gb:.2f} GB")
                else:
                    typer.echo(f"Total Size: {size_mb:.2f} MB")

            return True

        except NotFound:
            typer.secho(f"Bucket not found: {bucket_name}", fg=typer.colors.RED)
            return False
        except Exception as e:
            typer.secho(f"Error getting bucket info: {e}", fg=typer.colors.RED)
            return False

    def generate_uris(
        self,
        bucket_name: str | None = None,
        prefix: str | None = None,
        output_file: Path | None = None,
    ) -> bool:
        """
        Generate GCS URIs for files in a bucket.

        Args:
            bucket_name: Name of the bucket
            prefix: Filter by prefix
            output_file: Optional file to write URIs to

        Returns:
            True if successful, False otherwise
        """
        try:
            bucket = self._get_or_create_bucket(bucket_name)
            blobs = list(bucket.list_blobs(prefix=prefix))

            if not blobs:
                typer.echo("No files found.")
                return True

            uris = [f"gs://{bucket.name}/{blob.name}" for blob in blobs]

            # Output URIs
            if output_file:
                output_file.write_text("\n".join(uris) + "\n")
                typer.secho(f"URIs written to: {output_file}", fg=typer.colors.GREEN)
                typer.echo(f"Total: {len(uris)} URI(s)")
            else:
                typer.echo("\nGCS URIs:")
                for uri in uris:
                    typer.echo(uri)
                typer.echo()
                typer.echo(f"Total: {len(uris)} URI(s)")

            return True

        except NotFound:
            typer.secho(f"Bucket not found: {bucket_name}", fg=typer.colors.RED)
            return False
        except Exception as e:
            typer.secho(f"Error generating URIs: {e}", fg=typer.colors.RED)
            return False


# CLI Commands


@app.command()
def upload(
    files: Annotated[
        list[Path], typer.Argument(help="Local files or directories to upload.")
    ],
    bucket: Annotated[
        str | None, typer.Option("--bucket", "-b", help="Target bucket name.")
    ] = None,
    path: Annotated[
        str | None, typer.Option("--path", "-p", help="Path prefix in bucket.")
    ] = None,
    recursive: Annotated[
        bool, typer.Option("--recursive", "-r", help="Recursively upload directories.")
    ] = False,
    preserve_structure: Annotated[
        bool,
        typer.Option(
            "--preserve-structure", help="Preserve directory structure in GCS."
        ),
    ] = False,
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Overwrite existing files.")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Upload local files to Google Cloud Storage."""
    manager = GCSManager(env_file)

    # Expand paths and validate
    file_paths = []
    base_dir = None

    for file_arg in files:
        if file_arg.is_dir():
            if not recursive:
                typer.secho(
                    f"Skipping directory (use --recursive to upload): {file_arg}",
                    fg=typer.colors.YELLOW,
                )
                continue

            # Set base directory for structure preservation
            if preserve_structure and base_dir is None:
                base_dir = file_arg.parent

            # Walk the directory tree
            for root, dirs, filenames in os.walk(file_arg):
                for filename in filenames:
                    file_path = Path(root) / filename
                    file_paths.append(file_path)
        elif file_arg.exists():
            file_paths.append(file_arg)
        else:
            typer.secho(f"File not found: {file_arg}", fg=typer.colors.YELLOW)

    if not file_paths:
        typer.secho("No valid files to upload.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    try:
        if len(file_paths) == 1 and not preserve_structure:
            # Single file upload
            manager.upload_file(file_paths[0], bucket, path, overwrite)
        else:
            # Batch upload with optional structure preservation
            if preserve_structure and base_dir:
                # Upload with preserved directory structure
                uploaded_uris = []
                failed_files = []

                typer.echo(
                    f"\nUploading {len(file_paths)} file(s) with preserved structure..."
                )
                typer.echo()

                for i, file_path in enumerate(file_paths, 1):
                    typer.echo(f"[{i}/{len(file_paths)}] {file_path}")

                    try:
                        # Calculate relative path from base directory
                        rel_path = file_path.relative_to(base_dir)
                        gcs_file_path = str(rel_path)

                        if path:
                            gcs_file_path = f"{path.rstrip('/')}/{gcs_file_path}"

                        uri = manager.upload_file(
                            file_path, bucket, gcs_file_path, overwrite
                        )
                        uploaded_uris.append(uri)
                    except Exception as e:
                        typer.secho(f"  Failed: {e}", fg=typer.colors.YELLOW)
                        failed_files.append(file_path.name)

                    typer.echo()

                # Summary
                typer.echo("=" * 80)
                typer.secho(
                    f"Successfully uploaded: {len(uploaded_uris)}/{len(file_paths)}",
                    fg=typer.colors.GREEN,
                )
                if failed_files:
                    typer.secho(
                        f"Failed uploads: {len(failed_files)}", fg=typer.colors.YELLOW
                    )
            else:
                # Batch upload without structure preservation
                manager.upload_files(file_paths, bucket, path, overwrite)
    except Exception as e:
        typer.secho(f"Upload failed: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


@app.command()
def list(
    bucket: Annotated[
        str | None,
        typer.Option("--bucket", "-b", help="Bucket name to list files from."),
    ] = None,
    prefix: Annotated[
        str | None, typer.Option("--prefix", "-p", help="Filter by prefix.")
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed information.")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """List buckets or files in a bucket."""
    manager = GCSManager(env_file)

    if bucket:
        # List files in bucket
        if not manager.list_files(bucket, prefix, verbose):
            raise typer.Exit(code=1)
    else:
        # List all buckets
        if not manager.list_buckets(verbose):
            raise typer.Exit(code=1)


@app.command()
def delete(
    uri: Annotated[
        str | None, typer.Argument(help="GCS URI to delete (gs://...).")
    ] = None,
    bucket: Annotated[
        str | None,
        typer.Option("--bucket", "-b", help="Bucket name (for prefix deletion)."),
    ] = None,
    prefix: Annotated[
        str | None,
        typer.Option("--prefix", "-p", help="Delete all files with this prefix."),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompt.")
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would be deleted without deleting."),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Delete files from Google Cloud Storage."""
    manager = GCSManager(env_file)

    if uri:
        # Delete single file
        if not manager.delete_file(uri, force, dry_run):
            raise typer.Exit(code=1)
    elif bucket and prefix:
        # Delete by prefix
        if not manager.delete_prefix(bucket, prefix, force, dry_run):
            raise typer.Exit(code=1)
    else:
        typer.secho(
            "Error: Provide either a URI or both --bucket and --prefix",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)


@app.command()
def validate(
    files: Annotated[
        builtins.list[Path], typer.Argument(help="Local files to validate.")
    ],
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Validate files for RAG import."""
    manager = GCSManager(env_file)

    typer.echo("\nValidating files for RAG import...")
    typer.echo()

    valid_count = 0
    invalid_count = 0

    for file_path in files:
        is_valid, message = manager.validate_file(file_path)

        if is_valid:
            typer.secho(f"✓ {file_path.name}: {message}", fg=typer.colors.GREEN)
            valid_count += 1
        else:
            typer.secho(f"✗ {file_path.name}: {message}", fg=typer.colors.RED)
            invalid_count += 1

    typer.echo()
    typer.echo(f"Valid: {valid_count}, Invalid: {invalid_count}")

    if invalid_count > 0:
        raise typer.Exit(code=1)


@app.command()
def uri(
    bucket: Annotated[str, typer.Option("--bucket", "-b", help="Bucket name.")],
    prefix: Annotated[
        str | None, typer.Option("--prefix", "-p", help="Filter by prefix.")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Output file for URIs.")
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Generate GCS URIs for files in a bucket."""
    manager = GCSManager(env_file)

    if not manager.generate_uris(bucket, prefix, output):
        raise typer.Exit(code=1)


@app.command("bucket-create")
def bucket_create(
    name: Annotated[str, typer.Argument(help="Bucket name to create.")],
    location: Annotated[
        str | None,
        typer.Option("--location", "-l", help="Bucket location (e.g., us-central1)."),
    ] = None,
    storage_class: Annotated[
        str,
        typer.Option(
            "--storage-class",
            "-s",
            help="Storage class (STANDARD, NEARLINE, COLDLINE, ARCHIVE).",
        ),
    ] = "STANDARD",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Create a new GCS bucket."""
    manager = GCSManager(env_file)

    if not manager.create_bucket(name, location, storage_class):
        raise typer.Exit(code=1)


@app.command()
def bucket_info(
    name: Annotated[str, typer.Argument(help="Bucket name.")],
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Get detailed information about a bucket."""
    manager = GCSManager(env_file)

    if not manager.get_bucket_info(name):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
