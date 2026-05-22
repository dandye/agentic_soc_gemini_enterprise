import os
from pathlib import Path

from card_client import generate_action_url, send_card
from dotenv import load_dotenv


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    """
    ChatOps Card: impossible_travel_verification
    Sent to a user when two distant logins occur, often caused by VPN use.
    Includes a text box for the user to explain (e.g., 'Using corporate VPN').
    """

    # Generate secure action URLs
    confirm_url = generate_action_url(
        "Safe - It's me (VPN/Travel)",
        session_id=session_id,
        agent_engine_id=agent_engine_id,
        user_id=user_id,
    )

    suspicious_url = generate_action_url(
        "Suspicious - Not me",
        session_id=session_id,
        agent_engine_id=agent_engine_id,
        user_id=user_id,
    )

    return {
        "cardsV2": [
            {
                "cardId": "travel-verify",
                "card": {
                    "header": {
                        "title": "Impossible Travel Verification",
                        "subtitle": "Two logins detected from distant locations",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/vpn_lock/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "columns": {
                                        "columnItems": [
                                            {
                                                "horizontalSizeStyle": "FILL_AVAILABLE_SPACE",
                                                "widgets": [
                                                    {
                                                        "decoratedText": {
                                                            "topLabel": "Location A",
                                                            "text": "New York, USA",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "home"
                                                                }
                                                            },
                                                        }
                                                    }
                                                ],
                                            },
                                            {
                                                "horizontalSizeStyle": "FILL_AVAILABLE_SPACE",
                                                "widgets": [
                                                    {
                                                        "decoratedText": {
                                                            "topLabel": "Location B",
                                                            "text": "Frankfurt, Germany",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "flight_land"
                                                                }
                                                            },
                                                        }
                                                    }
                                                ],
                                            },
                                        ]
                                    }
                                },
                                {
                                    "textParagraph": {
                                        "text": "These logins occurred within 30 minutes of each other. If you are using a <b>VPN</b> or <b>Proxy</b>, please let us know below."
                                    }
                                },
                                {
                                    "textInput": {
                                        "name": "access_explanation",
                                        "label": "Explanation (e.g. 'Connected to Frankfurt VPN')",
                                        "type": "SINGLE_LINE",
                                        "placeholderText": "I am traveling / Using a VPN",
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "I recognize this activity",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": confirm_url}
                                                },
                                            },
                                            {
                                                "text": "No, this is suspicious",
                                                "color": {
                                                    "red": 0.8,
                                                    "green": 0,
                                                    "blue": 0,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": suspicious_url}
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
