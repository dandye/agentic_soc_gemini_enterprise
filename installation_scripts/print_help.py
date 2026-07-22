#!/usr/bin/env python3
import re
import sys


# Colors for terminal styling
BLUE = "\033[1;34m"
GREEN = "\033[1;32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RESET = "\033[0m"
BOLD = "\033[1m"

GROUPS = {
    "Setup & Development": ["setup", "install", "clean", "lint", "format"],
    "Agent Engine Management": [
        "agent-engine-deploy",
        "agent-engine-update",
        "agent-engine-deploy-pro",
        "agent-engine-deploy-tier2",
        "agent-engine-deploy-and-delete",
        "agent-engine-test",
        "agent-engine-warmup",
        "agent-engine-list",
        "agent-engine-delete-by-index",
        "agent-engine-delete-by-resource",
        "agent-engine-create",
        "agent-engine-create-debug",
        "agent-engine-create-no-test",
    ],
    "Gemini Enterprise Agent Platform Management": [
        "agentspace-register",
        "agentspace-update",
        "agentspace-verify",
        "agentspace-delete",
        "agentspace-url",
        "agentspace-test",
        "agentspace-datastore",
        "agentspace-link-agent",
        "agentspace-unlink-agent",
        "agentspace-update-agent",
        "agentspace-list-agents",
        "agentspace-list-apps",
        "agentspace-create-app",
    ],
    "Data Store Management": [
        "datastore-create",
        "datastore-list",
        "datastore-info",
        "datastore-delete",
    ],
    "RAG Corpus Management": [
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
    "GCS Management": [
        "gcs-upload",
        "gcs-list",
        "gcs-delete",
        "gcs-validate",
        "gcs-uri",
        "gcs-bucket-create",
        "gcs-bucket-info",
    ],
    "Vertex AI & Models": [
        "vertex-ai-verify",
        "vertex-ai-enable-apis",
        "vertex-ai-quota",
        "models-list",
    ],
    "OAuth Management": [
        "oauth-setup",
        "oauth-create-auth",
        "oauth-verify",
        "oauth-delete",
    ],
    "Gemini Enterprise User Licenses": [
        "licenses-list",
        "licenses-assign",
        "licenses-remove",
    ],
    "Secret Manager": ["secret-upload", "secret-upload-force", "secret-verify"],
    "Validation & Verification": [
        "check-env",
        "check-prereqs",
        "check-deploy",
        "check-integration",
    ],
    "Workflows & Utilities": [
        "agent-engine-logs",
        "agent-engine-redeploy",
        "agentspace-redeploy",
        "redeploy-all",
        "oauth-workflow",
        "full-deploy-with-oauth",
        "status",
        "cleanup",
    ],
    "Evaluation & Latency": [
        "eval",
        "eval-basic",
        "eval-cti",
        "eval-tier1",
        "eval-multi",
        "profile-latency",
        "profile-latency-runs",
        "profile-latency-rag",
        "profile-latency-cti",
        "profile-latency-tier1",
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


def print_help(justfile_path):
    recipes = parse_justfile(justfile_path)

    print(
        f"\n{BLUE}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}"
    )
    print(
        f"{BLUE}║           Agentic SOC Gemini Enterprise Agent Platform Management            ║{RESET}"
    )
    print(
        f"{BLUE}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}\n"
    )

    # Track which recipes were displayed so we can print any leftover ones
    displayed = set()

    for group_name, recipe_list in GROUPS.items():
        # Only print group if at least one of its recipes exists in the parsed justfile
        group_recipes = [r for r in recipe_list if r in recipes]
        if not group_recipes:
            continue

        print(f"{BOLD}{GREEN}{group_name}{RESET}")
        for recipe in group_recipes:
            desc = recipes[recipe]
            # Print recipe name left-aligned with a fixed width, and description next to it
            print(f"  {CYAN}{recipe:<32}{RESET} {desc}")
            displayed.add(recipe)
        print()

    # Print any leftover recipes that weren't categorized (e.g. if they are added in the future)
    leftover = [r for r in recipes if r not in displayed and r != "default"]
    if leftover:
        print(f"{BOLD}{YELLOW}Other Recipes{RESET}")
        for recipe in leftover:
            desc = recipes[recipe]
            print(f"  {CYAN}{recipe:<32}{RESET} {desc}")
        print()

    print(f"{BOLD}Usage Examples:{RESET}")
    print(
        f"  {YELLOW}just setup{RESET}                              - Initialize project and install dependencies"
    )
    print(
        f"  {YELLOW}just agent-engine-deploy{RESET}                - Deploy the agent engine"
    )
    print(
        f"  {YELLOW}just agent-engine-test{RESET}                  - Test the deployed agent"
    )
    print(
        f"  {YELLOW}just agentspace-register{RESET}                - Register agent with Gemini Enterprise Agent Platform"
    )
    print(
        f"  {YELLOW}just force=true agentspace-register{RESET}     - Force re-register agent with Gemini Enterprise Agent Platform"
    )
    print(
        f"  {YELLOW}just agentspace-verify{RESET}                  - Check status and get URLs"
    )
    print()
    print(f"{BOLD}Notes:{RESET}")
    print(
        f"  • Environment variables are loaded from {YELLOW}.env{RESET} file by default"
    )
    print(f"  • Use {YELLOW}env_file=path{RESET} to specify different environment file")
    print(f"  • Use {YELLOW}v=1{RESET} for verbose output (shows script details)")
    print(
        f"  • Use {YELLOW}force=true{RESET} with delete/register commands to skip confirmations"
    )
    print("  • See docs/DEPLOYMENT_WORKFLOW.md for detailed instructions")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: print_help.py <justfile_path>")
        sys.exit(1)
    print_help(sys.argv[1])
