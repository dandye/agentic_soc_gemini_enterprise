#!/usr/bin/env python3
import os
import re
import sys


# ANSI Reset and Format Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Curated Color Themes for CLI Help
THEMES = {
    "nord": {
        "name": "Nordic Frost (Ice Cyan & Arctic Blue)",
        "banner": "\033[38;5;38m",  # Frost Teal
        "group": "\033[1;38;5;81m",  # Crisp Ice Cyan
        "recipe": "\033[38;5;123m",  # Arctic Sky Blue
        "desc": "\033[38;5;249m",  # Cool Slate
        "example": "\033[38;5;222m",  # Polar Gold
        "highlight": "\033[38;5;111m",  # Glacier Blue
    },
    "ocean": {
        "name": "Google Ocean & Amber (Azure & Gold)",
        "banner": "\033[38;5;33m",  # Google Blue
        "group": "\033[1;38;5;75m",  # Azure / Cornflower Blue
        "recipe": "\033[38;5;214m",  # Warm Amber / Gold
        "desc": "\033[38;5;252m",  # Crisp Silver
        "example": "\033[38;5;114m",  # Emerald Green
        "highlight": "\033[38;5;81m",  # Sky Cyan
    },
    "tokyo": {
        "name": "Tokyo Night (Indigo & Mint)",
        "banner": "\033[38;5;69m",  # Soft Indigo / Azure
        "group": "\033[1;38;5;141m",  # Bold Lavender / Purple
        "recipe": "\033[38;5;116m",  # Crisp Mint Cyan
        "desc": "\033[38;5;250m",  # Neutral Slate / Off-White
        "example": "\033[38;5;215m",  # Warm Amber / Gold
        "highlight": "\033[38;5;117m",  # Sky Blue
    },
    "emerald": {
        "name": "Emerald & Spring Green",
        "banner": "\033[38;5;36m",  # Jade / Dark Emerald
        "group": "\033[1;38;5;79m",  # Spring Green
        "recipe": "\033[38;5;117m",  # Bright Cyan
        "desc": "\033[38;5;248m",  # Silver
        "example": "\033[38;5;220m",  # Sun Gold
        "highlight": "\033[38;5;158m",  # Pale Mint
    },
    "monokai": {
        "name": "Monokai Pro (Warm Gold & Cyan)",
        "banner": "\033[38;5;197m",  # Bright Pink / Rose
        "group": "\033[1;38;5;221m",  # Warm Yellow
        "recipe": "\033[38;5;81m",  # Bright Cyan
        "desc": "\033[38;5;250m",  # Off-white
        "example": "\033[38;5;149m",  # Lime Green
        "highlight": "\033[38;5;208m",  # Orange
    },
}

GROUPS = {
    "Setup & Environment": [
        "setup",
        "install",
        "clean",
        "lint",
        "format",
        "pre-commit",
        "check-env",
        "check-prereqs",
        "check-deploy",
        "check-integration",
    ],
    "Agent Engine Management (Vertex AI)": [
        "agent-engine-deploy",
        "agent-engine-update",
        "agent-engine-deploy-pro",
        "agent-engine-deploy-tier2",
        "agent-engine-deploy-threat-hunter",
        "agent-engine-deploy-cti-researcher",
        "agent-engine-deploy-detection-engineer",
        "agent-engine-deploy-alloydb",
        "agent-engine-deploy-and-delete",
        "agent-engine-test",
        "agent-engine-session-dump",
        "agent-engine-warmup",
        "agent-engine-list",
        "agent-engine-delete-by-index",
        "agent-engine-delete-by-resource",
        "agent-engine-create",
        "agent-engine-create-debug",
        "agent-engine-create-no-test",
        "agent-engine-logs",
        "agent-engine-redeploy",
    ],
    "Gemini Enterprise Agent Platform (GEAP)": [
        "gem-ent-register",
        "gem-ent-register-alloydb",
        "gem-ent-update",
        "gem-ent-verify",
        "gem-ent-delete",
        "gem-ent-url",
        "gem-ent-test",
        "gem-ent-datastore",
        "gem-ent-link-agent",
        "gem-ent-unlink-agent",
        "gem-ent-update-agent",
        "gem-ent-list-agents",
        "gem-ent-list-apps",
        "gem-ent-create-app",
        "gem-ent-redeploy",
    ],
    "AlloyDB Detection Reports Grounding": [
        "alloydb-test",
        "alloydb-init",
        "alloydb-ingest",
        "alloydb-embed",
        "alloydb-search",
        "alloydb-search-semantic",
        "alloydb-find-similar",
        "alloydb-report",
        "alloydb-profiles",
        "alloydb-info",
        "alloydb-clear",
        "alloydb-start",
        "alloydb-stop",
    ],
    "Neo4j Threat Graph Database": [
        "neo4j-test",
        "neo4j-ingest",
        "neo4j-recalc",
        "neo4j-sync",
        "neo4j-clear",
        "neo4j-start",
        "neo4j-stop",
        "neo4j-gce-deploy",
    ],
    "Elasticsearch Runbook Grounding": [
        "elastic-info",
        "elastic-create",
        "elastic-sync",
        "elastic-search",
    ],
    "Chronicle SIEM Telemetry & Harvesting": [
        "harvest",
        "harvest-investigations",
        "harvest-detections",
    ],
    "RAG Corpus & Runbook Sync": [
        "rag-list",
        "rag-info",
        "rag-create",
        "rag-delete",
        "rag-import",
        "sync-runbooks",
        "sync-runbooks-validate",
        "sync-runbooks-gcs",
        "sync-runbooks-prune",
    ],
    "Data Store & GCS Management": [
        "datastore-create",
        "datastore-list",
        "datastore-info",
        "datastore-delete",
        "gcs-upload",
        "gcs-list",
        "gcs-delete",
        "gcs-validate",
        "gcs-uri",
        "gcs-bucket-create",
        "gcs-bucket-info",
    ],
    "Evaluation, Benchmarks & Latency": [
        "eval",
        "eval-basic",
        "eval-cti",
        "eval-tier1",
        "eval-tier2",
        "test-eval-all",
        "test-eval-cti",
        "test-eval-detection",
        "test-eval-hunt",
        "test-eval-response",
        "test-eval",
        "test-compare",
        "profile-latency",
        "profile-latency-runs",
        "profile-latency-rag",
        "profile-latency-cti",
        "profile-latency-tier1",
        "parity-audit",
    ],
    "Agents CLI Submodule Wrappers": [
        "agents-cli",
        "agents-cli-eval",
        "agents-cli-dataset",
        "agents-cli-analyze",
        "agents-cli-optimize",
    ],
    "ChatOps Native Google Chat App": [
        "chatops-list",
        "chatops-test",
        "chatops-deploy-app",
        "chatops-create-queue",
        "chatops-registration-guide",
        "chatops-verify",
    ],
    "Security, IAM & OAuth": [
        "iam-setup",
        "iam-verify",
        "iam-list-roles",
        "secret-upload",
        "secret-upload-force",
        "secret-verify",
        "secret-sync",
        "secret-sync-force",
        "oauth-setup",
        "oauth-create-auth",
        "oauth-verify",
        "oauth-delete",
        "oauth-workflow",
    ],
    "Vertex AI & Models": [
        "vertex-ai-verify",
        "vertex-ai-enable-apis",
        "vertex-ai-quota",
        "models-list",
        "models-validate",
    ],
    "Gemini Enterprise User Licenses": [
        "licenses-list",
        "licenses-configs",
        "licenses-assign",
        "licenses-remove",
    ],
    "Composite Workflows": [
        "full-deploy-with-oauth",
        "redeploy-all",
        "status",
        "cleanup",
    ],
}


def parse_justfile(justfile_path):
    recipes = {}
    pending_desc = []

    # Match recipes (allowing spaces/arguments, but not ':' or '=' inside argument list structure until final ':')
    recipe_re = re.compile(r"^([a-zA-Z0-9_-]+)(?:\s+[^:]*)?:(?!=)")

    with open(justfile_path) as f:
        for line in f:
            line = line.rstrip("\r\n")

            # Match comment lines
            if line.startswith("#"):
                desc_line = line[1:].strip()
                # Clear pending description or skip if it is a section separator line
                if (
                    not desc_line
                    or desc_line.startswith("=")
                    or desc_line.startswith("-")
                    or desc_line.startswith("*")
                ):
                    pending_desc = []
                    continue
                pending_desc.append(desc_line)
            # Match recipe definitions
            else:
                match = recipe_re.match(line)
                if match:
                    recipe_name = match.group(1)
                    if pending_desc:
                        recipes[recipe_name] = " ".join(pending_desc)
                    else:
                        recipes[recipe_name] = ""
                    pending_desc = []
                elif not line.strip():
                    # Keep pending_desc across empty lines only if they are not followed by non-comments
                    pass
                else:
                    # Non-recipe, non-comment line, reset pending description
                    pending_desc = []

    return recipes


def print_help(justfile_path, theme_key="tokyo"):
    theme = THEMES.get(theme_key.lower(), THEMES["tokyo"])

    banner_color = theme["banner"]
    group_color = theme["group"]
    recipe_color = theme["recipe"]
    desc_color = theme["desc"]
    example_color = theme["example"]
    highlight_color = theme["highlight"]

    recipes = parse_justfile(justfile_path)

    print(
        f"\n{banner_color}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}"
    )
    print(
        f"{banner_color}║           Agentic SOC Gemini Enterprise Agent Platform Management            ║{RESET}"
    )
    print(
        f"{banner_color}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}\n"
    )

    # Track which recipes were displayed so we can print any leftover ones
    displayed = set()

    for group_name, recipe_list in GROUPS.items():
        # Only print group if at least one of its recipes exists in the parsed justfile
        group_recipes = [r for r in recipe_list if r in recipes]
        if not group_recipes:
            continue

        print(f"{group_color}◆ {group_name}{RESET}")
        for recipe in group_recipes:
            desc = recipes[recipe]
            # Print recipe name left-aligned with a fixed width, and description next to it
            print(f"  {recipe_color}{recipe:<32}{RESET} {desc_color}{desc}{RESET}")
            displayed.add(recipe)
        print()

    # Print any leftover recipes that weren't categorized (e.g. if they are added in the future)
    leftover = [r for r in recipes if r not in displayed and r != "default"]
    if leftover:
        print(f"{example_color}◆ Other Recipes{RESET}")
        for recipe in leftover:
            desc = recipes[recipe]
            print(f"  {recipe_color}{recipe:<32}{RESET} {desc_color}{desc}{RESET}")
        print()

    print(f"{BOLD}{highlight_color}Usage Examples:{RESET}")
    print(
        f"  {example_color}just setup{RESET}                              - Initialize project and install dependencies"
    )
    print(
        f"  {example_color}just agent-engine-deploy{RESET}                - Deploy the agent engine"
    )
    print(
        f"  {example_color}just agent-engine-test{RESET}                  - Test the deployed agent"
    )
    print(
        f"  {example_color}just gem-ent-register{RESET}                   - Register agent with Gemini Enterprise Agent Platform"
    )
    print(
        f"  {example_color}just force=true gem-ent-register{RESET}        - Force re-register agent with Gemini Enterprise Agent Platform"
    )
    print(
        f"  {example_color}just gem-ent-verify{RESET}                     - Check status and get URLs"
    )
    print()
    print(f"{BOLD}{highlight_color}Notes:{RESET}")
    print(
        f"  • Environment variables are loaded from {example_color}.env{RESET} file by default"
    )
    print(
        f"  • Use {example_color}env_file=path{RESET} to specify different environment file"
    )
    print(
        f"  • Use {example_color}v=1{RESET} for verbose output (shows script details)"
    )
    print(
        f"  • Use {example_color}force=true{RESET} with delete/register commands to skip confirmations"
    )
    print("  • See docs/DEPLOYMENT_WORKFLOW.md for detailed instructions")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: print_help.py <justfile_path> [theme]")
        sys.exit(1)

    theme_name = os.environ.get("JUST_THEME", "tokyo")
    if len(sys.argv) >= 3:
        theme_name = sys.argv[2]

    print_help(sys.argv[1], theme_key=theme_name)
