import re
from pathlib import Path


def fix_legacy_template(file_path):
    print(f"Processing {file_path}...")
    with open(file_path) as f:
        content = f.read()

    # Ensure all required imports are present
    required_imports = [
        "import os",
        "from pathlib import Path",
        "from dotenv import load_dotenv",
        "from card_client import send_card, generate_action_url",
    ]

    # Strip any existing messy imports of these specific items to clean up
    for imp in required_imports:
        content = content.replace(f"{imp}\n", "")
        content = content.replace(imp, "")

    # Re-insert cleanly at the top
    content = "\n".join(required_imports) + "\n" + content

    # 2. Update get_card signature
    # Use a robust replacement that handles existing or missing arguments
    content = re.sub(
        r"def get_card\(([^)]*)\):",
        r"def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):",
        content,
    )

    # 3. Handle buttons by searching for all example.com patterns
    def replace_url(match):
        action_name = match.group(1).replace("_", " ").title()
        return f'generate_action_url("{action_name}", session_id=session_id, agent_engine_id=agent_engine_id, user_id=user_id)'

    # Replace hardcoded URLs in onClick blocks (handles http/https/f-strings)
    content = re.sub(
        r'\"url\": f?\"https?://example\.com/[^?]+\?action=([^&"]+)[^"]*\"',
        lambda m: f'"url": {replace_url(m)}',
        content,
    )

    # Also handle simpler example.com/action formats
    content = re.sub(
        r'\"url\": f?\"https?://example\.com/([^"]+)\"',
        lambda m: f'"url": {replace_url(m)}',
        content,
    )

    # 4. Standardize the if __name__ == "__main__" block
    manual_test_block = """
if __name__ == "__main__":
    # Load environment for manual testing
    load_dotenv(Path(__file__).parent.parent.parent.parent / ".env")

    session_id = os.getenv("CHATOPS_TEST_SESSION_ID", "test-session")
    agent_id = os.getenv("AGENT_ENGINE_RESOURCE_NAME", "test-agent")

    # Send the card
    card = get_card(
        session_id=session_id,
        agent_engine_id=agent_id,
        user_id="vais-query-reasoning-engine"
    )
    send_card(card)
"""
    # Remove any existing main block or partial main block and replace
    if 'if __name__ == "__main__":' in content:
        content = re.sub(
            r'if __name__ == "__main__":.*', manual_test_block, content, flags=re.DOTALL
        )
    else:
        content = content.strip() + "\n" + manual_test_block

    with open(file_path, "w") as f:
        f.write(content)


legacy_cards = [
    "brute_force_alert.py",
    "bulk_deletion_verification.py",
    "forensics_evidence_ready.py",
    "impossible_travel_alert.py",
    "ioc_enrichment_card.py",
    "malware_sandbox_report.py",
    "mfa_api_key_alert.py",
    "phishing_report_summary.py",
    "shadow_it_discovery.py",
    "temp_admin_request.py",
    "vulnerability_patch_approval.py",
]

chatops_dir = Path(
    "/Users/dandye/Projects/agentic_agent_soc_managerspace__worktrees/google_sandy__main/agent_soc_manager/tools/chatops"
)

for card in legacy_cards:
    card_path = chatops_dir / card
    if card_path.exists():
        fix_legacy_template(card_path)
    else:
        print(f"Warning: {card} not found")

print("All legacy cards modernized with clean imports!")
