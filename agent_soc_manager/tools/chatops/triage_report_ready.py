import datetime
import os
from pathlib import Path

from dotenv import load_dotenv
from google.cloud import storage
from google.oauth2 import service_account

from soc_agent.tools.chatops.card_client import generate_action_url, send_card


def get_presigned_url(case_id: str) -> str:
    """Generates a secure temporary link to download the PDF report from GCS."""
    bucket_name = os.environ.get("GCP_ARTIFACT_BUCKET", "")
    if bucket_name.startswith("gs://"):
        bucket_name = bucket_name[5:]
    if not bucket_name:
        return ""

    try:
        sa_path = os.environ.get("SECOPS_SA_PATH") or os.environ.get(
            "CHRONICLE_SERVICE_ACCOUNT_PATH"
        )
        if sa_path and os.path.exists(sa_path):
            credentials = service_account.Credentials.from_service_account_file(sa_path)
            client = storage.Client(credentials=credentials)
        else:
            client = storage.Client()

        bucket = client.bucket(bucket_name)
        blob = bucket.blob(f"archive/{case_id}_triage_report.pdf")

        # Fallback to demo PDF only if testing (not in production)
        if not blob.exists() and (
            "TEST" in case_id.upper() or "DEMO" in case_id.upper()
        ):
            print(
                f"Report for {case_id} not found. Falling back to demo INC-2024 report."
            )
            blob = bucket.blob("archive/INC-2024_triage_report.pdf")

        if sa_path and os.path.exists(sa_path):
            # Key file is available, we can sign directly
            return blob.generate_signed_url(
                version="v4",
                expiration=datetime.timedelta(hours=24),
                method="GET",
            )
        else:
            # Determine ambient service account automatically to authorize the signature
            sa_email = client.get_service_account_email()
            return blob.generate_signed_url(
                version="v4",
                expiration=datetime.timedelta(hours=24),
                method="GET",
                service_account_email=sa_email,
            )
    except Exception as e:
        print(f"Failed to generate signed URL: {e}")
        # Secure fallback requiring user's own GCP auth
        return f"https://console.cloud.google.com/storage/browser/_details/{bucket_name}/archive/{case_id}_triage_report.pdf"


def get_card(
    session_id: str = None,
    agent_engine_id: str = None,
    user_id: str = None,
    case_id: str = "INC-2024",
    report_summary: str = "12 Hosts Triage / 4 Malicious Findings",
    **kwargs,
):
    """
    ChatOps Card: triage_report_ready
    Provides a download link for the initial triage report.
    """

    download_url = get_presigned_url(case_id) or "#"

    acknowledge_url = generate_action_url(
        "Acknowledge and Close",
        session_id=session_id,
        agent_engine_id=agent_engine_id,
        user_id=user_id,
    )

    return {
        "cardsV2": [
            {
                "cardId": "triage-report",
                "card": {
                    "header": {
                        "title": "Triage Report Ready",
                        "subtitle": f"Analysis complete for {case_id}",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/description/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "Scan Coverage",
                                        "text": report_summary,
                                        "startIcon": {
                                            "materialIcon": {"name": "analytics"}
                                        },
                                    }
                                },
                                {
                                    "decoratedText": {
                                        "topLabel": "Time to Generate",
                                        "text": "2 minutes, 14 seconds",
                                        "startIcon": {
                                            "materialIcon": {"name": "timer"}
                                        },
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Download Full PDF",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": download_url}
                                                },
                                            },
                                            {
                                                "text": "Acknowledge",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.6,
                                                    "blue": 0.1,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": acknowledge_url}
                                                },
                                            },
                                        ]
                                    }
                                },
                            ]
                        }
                    ],
                },
            }
        ]
    }


if __name__ == "__main__":
    # Load environment for manual testing
    load_dotenv(Path(__file__).parent.parent.parent.parent / ".env")

    session_id = os.getenv("CHATOPS_TEST_SESSION_ID", "test-session")
    agent_id = os.getenv("AGENT_ENGINE_RESOURCE_NAME", "test-agent")

    # Send the card
    card = get_card(
        session_id=session_id,
        agent_engine_id=agent_id,
        user_id="vais-query-reasoning-engine",
    )
    send_card(card)
