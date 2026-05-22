import os
from pathlib import Path

from dotenv import load_dotenv

from soc_agent.tools.chatops.card_client import generate_action_url, send_card


def get_card(
    session_id: str = None,
    agent_engine_id: str = None,
    user_id: str = None,
    user_email: str = "User",
    location: str = "Unknown Location",
    arrival_time: str = "Unknown Time",
    **kwargs,
):
    """
    ChatOps Card: traveler_confirmation
    Sent to a traveler to confirm an impossible travel alert and provide context.
    """

    # Generate secure action URLs
    confirm_url = generate_action_url(
        "Safe - I am traveling",
        session_id=session_id,
        agent_engine_id=agent_engine_id,
        user_id=user_id,
    )

    report_url = generate_action_url(
        "Report Unauthorized Activity",
        session_id=session_id,
        agent_engine_id=agent_engine_id,
        user_id=user_id,
    )

    return {
        "cardsV2": [
            {
                "cardId": "traveler-confirm",
                "card": {
                    "header": {
                        "title": f"Security Check: Are you traveling, {user_email}?",
                        "subtitle": f"Recent login activity from {location}",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/security/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "header": "Login Details",
                            "collapsible": False,
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "Location",
                                        "text": location,
                                        "startIcon": {
                                            "materialIcon": {"name": "public"}
                                        },
                                    }
                                },
                                {
                                    "decoratedText": {
                                        "topLabel": "Time",
                                        "text": arrival_time,
                                        "startIcon": {
                                            "materialIcon": {"name": "schedule"}
                                        },
                                    }
                                },
                            ],
                        },
                        {
                            "widgets": [
                                {
                                    "textParagraph": {
                                        "text": "We noticed a login from a location that seems far from your usual activity. Please confirm if this was you."
                                    }
                                },
                                {
                                    "textInput": {
                                        "name": "travel_notes",
                                        "label": "Optional matching notes (e.g. Flight #, VPN use)",
                                        "type": "SINGLE_LINE",
                                        "placeholderText": "Was using a VPN / On vacation...",
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Yes, this was me",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.6,
                                                    "blue": 0.1,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": confirm_url}
                                                },
                                            },
                                            {
                                                "text": "No, report this",
                                                "color": {
                                                    "red": 0.8,
                                                    "green": 0,
                                                    "blue": 0,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": report_url}
                                                },
                                            },
                                        ]
                                    }
                                },
                            ]
                        },
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
