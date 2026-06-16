#!/usr/bin/env python3
"""
Knowledge Catalog Glossary Manager for Google Cloud Dataplex.

This script programmatically manages glossaries, terms, and synonym links
within Google Cloud Knowledge Catalog using direct authenticated REST API requests,
avoiding complex client library dependencies in restricted environments.
"""

import os
from typing import Annotated

import requests
import typer
from dotenv import load_dotenv
from google.auth import default
from google.auth.transport.requests import Request


# Initialize Typer App
app = typer.Typer(
    add_completion=False,
    help="Manage Knowledge Catalog Glossaries and Threat Actor Aliases in Google Cloud.",
)

# Load environment variables
load_dotenv()


class GlossaryManager:
    """Helper class to interact with the Dataplex Catalog/Glossary REST API."""

    def __init__(self, project_id: str, location: str):
        self.project_id = project_id
        self.location = location
        self.credentials, self.project_default = default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        self.refresh_token()
        self.project_number = self._get_project_number()

    def refresh_token(self):
        """Refreshes the Google OAuth credentials and returns the token."""
        if not self.credentials.valid:
            self.credentials.refresh(Request())
        return self.credentials.token

    def _get_headers(self) -> dict:
        """Helper to get authentication headers."""
        return {
            "Authorization": f"Bearer {self.refresh_token()}",
            "Content-Type": "application/json",
        }

    def _get_project_number(self) -> str:
        """Retrieves the project number using the Resource Manager API."""
        url = (
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.project_id}"
        )
        response = requests.get(url, headers=self._get_headers())
        if response.status_code == 200:
            return response.json().get("projectNumber", "")
        # Fall back to project ID if we can't fetch it, although number is preferred for entry links
        return self.project_id

    def create_glossary(
        self, glossary_id: str, display_name: str, description: str
    ) -> dict:
        """Creates a new Glossary resource in the Knowledge Catalog."""
        url = f"https://dataplex.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}/glossaries"
        params = {"glossaryId": glossary_id}
        payload = {
            "displayName": display_name,
            "description": description,
        }

        response = requests.post(
            url, headers=self._get_headers(), params=params, json=payload
        )
        if response.status_code in [200, 201]:
            return response.json()
        elif response.status_code == 409:
            print(f"Glossary '{glossary_id}' already exists.")
            return self.get_glossary(glossary_id)
        else:
            raise Exception(
                f"Failed to create glossary: {response.status_code} - {response.text}"
            )

    def get_glossary(self, glossary_id: str) -> dict:
        """Gets details of an existing glossary."""
        url = f"https://dataplex.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}/glossaries/{glossary_id}"
        response = requests.get(url, headers=self._get_headers())
        if response.status_code == 200:
            return response.json()
        raise Exception(
            f"Failed to fetch glossary: {response.status_code} - {response.text}"
        )

    def create_term(
        self, glossary_id: str, term_id: str, display_name: str, description: str
    ) -> dict:
        """Creates a new Term within a specific Glossary."""
        url = f"https://dataplex.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}/glossaries/{glossary_id}/terms"
        params = {"termId": term_id}
        payload = {
            "displayName": display_name,
            "description": description,
        }

        response = requests.post(
            url, headers=self._get_headers(), params=params, json=payload
        )
        if response.status_code in [200, 201]:
            return response.json()
        elif response.status_code == 409:
            print(f"Term '{term_id}' already exists in glossary '{glossary_id}'.")
            return self.get_term(glossary_id, term_id)
        else:
            raise Exception(
                f"Failed to create term: {response.status_code} - {response.text}"
            )

    def get_term(self, glossary_id: str, term_id: str) -> dict:
        """Gets details of an existing glossary term."""
        url = f"https://dataplex.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}/glossaries/{glossary_id}/terms/{term_id}"
        response = requests.get(url, headers=self._get_headers())
        if response.status_code == 200:
            return response.json()
        raise Exception(
            f"Failed to fetch term: {response.status_code} - {response.text}"
        )

    def link_synonyms(self, glossary_id: str, term1_id: str, term2_id: str) -> dict:
        """Creates a native synonym link between two glossary terms."""
        url = f"https://dataplex.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}/entryGroups/@dataplex/entryLinks"

        # Build unique, deterministic entry link ID
        entry_link_id = f"syn-{term1_id}-{term2_id}"

        # Build canonical resource names using project number
        term1_name = f"projects/{self.project_number}/locations/{self.location}/entryGroups/@dataplex/entries/projects/{self.project_number}/locations/{self.location}/glossaries/{glossary_id}/terms/{term1_id}"
        term2_name = f"projects/{self.project_number}/locations/{self.location}/entryGroups/@dataplex/entries/projects/{self.project_number}/locations/{self.location}/glossaries/{glossary_id}/terms/{term2_id}"

        params = {"entry_link_id": entry_link_id}
        payload = {
            "entry_link_type": "projects/dataplex-types/locations/global/entryLinkTypes/synonym",
            "entry_references": [
                {"name": term1_name, "type": "UNSPECIFIED"},
                {"name": term2_name, "type": "UNSPECIFIED"},
            ],
        }

        response = requests.post(
            url, headers=self._get_headers(), params=params, json=payload
        )
        if response.status_code in [200, 201]:
            return response.json()
        elif response.status_code == 409:
            print(f"Synonym link between '{term1_id}' and '{term2_id}' already exists.")
            return {}
        else:
            raise Exception(
                f"Failed to create synonym link: {response.status_code} - {response.text}"
            )


# --- CLI Commands ---


def _get_manager() -> GlossaryManager:
    """Helper to resolve project configuration and return a manager instance."""
    project_id = os.getenv("GCP_PROJECT_ID")
    location = os.getenv("GCP_LOCATION", "us-central1")
    if not project_id:
        print("Error: GCP_PROJECT_ID environment variable is not set.")
        raise typer.Exit(code=1)
    return GlossaryManager(project_id, location)


@app.command("create-catalog")
def create_catalog(
    glossary_id: Annotated[
        str, typer.Option(help="Unique ID for the Glossary.")
    ] = "secops-threat-intel",
    display_name: Annotated[
        str, typer.Option(help="Human-readable name for the Glossary.")
    ] = "SecOps Threat Intelligence",
    description: Annotated[
        str, typer.Option(help="Description of the Glossary.")
    ] = "Unified glossary for security operations threat intelligence, threat actors, and campaign terminology.",
):
    """Initializes the root Glossary in Knowledge Catalog."""
    manager = _get_manager()
    print(
        f"Initializing glossary '{glossary_id}' in project '{manager.project_id}' ({manager.location})..."
    )
    try:
        res = manager.create_glossary(glossary_id, display_name, description)
        print("Glossary initialized successfully:")
        print(f"  Name: {res.get('name')}")
        print(f"  Display Name: {res.get('displayName')}")
    except Exception as e:
        print(f"Error: {e}")
        raise typer.Exit(code=1)


@app.command("create-term")
def create_term(
    glossary_id: Annotated[
        str, typer.Option(help="Glossary ID.")
    ] = "secops-threat-intel",
    term_id: Annotated[
        str, typer.Argument(help="Unique ID for the term (e.g. 'apt29').")
    ] = ...,
    display_name: Annotated[
        str, typer.Option(help="Display name for the term.")
    ] = None,
    description: Annotated[str, typer.Option(help="Description of the term.")] = "",
):
    """Creates a new Term within the glossary."""
    manager = _get_manager()
    disp_name = display_name or term_id
    print(f"Creating term '{term_id}' under glossary '{glossary_id}'...")
    try:
        res = manager.create_term(glossary_id, term_id, disp_name, description)
        print("Term created successfully:")
        print(f"  Name: {res.get('name')}")
        print(f"  Display Name: {res.get('displayName')}")
    except Exception as e:
        print(f"Error: {e}")
        raise typer.Exit(code=1)


@app.command("link-synonyms")
def link_synonyms(
    glossary_id: Annotated[
        str, typer.Option(help="Glossary ID.")
    ] = "secops-threat-intel",
    term1: Annotated[str, typer.Argument(help="First term ID.")] = ...,
    term2: Annotated[str, typer.Argument(help="Second term ID.")] = ...,
):
    """Links two glossary terms as synonyms."""
    manager = _get_manager()
    print(f"Linking '{term1}' and '{term2}' as synonyms...")
    try:
        manager.link_synonyms(glossary_id, term1, term2)
        print("Synonym link established successfully.")
    except Exception as e:
        print(f"Error: {e}")
        raise typer.Exit(code=1)


@app.command("sync-actor")
def sync_actor(
    glossary_id: Annotated[
        str, typer.Option(help="Glossary ID.")
    ] = "secops-threat-intel",
    canonical_id: Annotated[
        str, typer.Argument(help="Canonical Threat Actor ID (e.g. 'apt29').")
    ] = ...,
    display_name: Annotated[
        str, typer.Option(help="Display name for the canonical actor.")
    ] = None,
    description: Annotated[
        str, typer.Option(help="Description of the canonical actor.")
    ] = "",
    aliases: Annotated[
        str, typer.Option(help="Comma-separated list of synonyms/aliases.")
    ] = "",
):
    """Synchronizes a canonical threat actor and all of its aliases as linked synonyms."""
    manager = _get_manager()

    # 1. Ensure the root glossary exists
    try:
        manager.create_glossary(
            glossary_id,
            "SecOps Threat Intelligence",
            "Unified glossary for security operations threat intelligence, threat actors, and campaign terminology.",
        )
    except Exception as e:
        print(f"Warning during glossary check: {e}")

    # 2. Create canonical term
    canon_disp = display_name or canonical_id.upper()
    print(f"\n[1/3] Ensuring canonical term '{canonical_id}' exists...")
    try:
        manager.create_term(glossary_id, canonical_id, canon_disp, description)
    except Exception as e:
        print(f"Error creating canonical term: {e}")
        raise typer.Exit(code=1)

    # 3. Create alias terms
    alias_list = [a.strip() for a in aliases.split(",") if a.strip()]
    if not alias_list:
        print("No aliases provided. Sync complete.")
        return

    print("\n[2/3] Ensuring alias terms exist...")
    for alias in alias_list:
        # Convert alias to a clean URL-friendly term ID
        alias_id = alias.lower().replace(" ", "-")
        print(f"  Ensuring alias term '{alias_id}' ('{alias}') exists...")
        try:
            manager.create_term(
                glossary_id,
                alias_id,
                alias,
                f"Synonym/Alias for canonical threat actor {canon_disp}.",
            )
        except Exception as e:
            print(f"  Warning creating alias term '{alias_id}': {e}")

    # 4. Link synonyms
    print("\n[3/3] Establishing synonym links...")
    for alias in alias_list:
        alias_id = alias.lower().replace(" ", "-")
        print(f"  Linking '{canonical_id}' <--> '{alias_id}'...")
        try:
            manager.link_synonyms(glossary_id, canonical_id, alias_id)
        except Exception as e:
            print(f"  Warning linking '{canonical_id}' and '{alias_id}': {e}")

    print("\nSync complete! All threat actor terms and synonym links are active.")


if __name__ == "__main__":
    app()
