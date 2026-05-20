import os
from pathlib import Path

from card_client import generate_action_url, send_card
from dotenv import load_dotenv


"""
ChatOps Card: phishing_report_summary
Modernized Version
"""


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    return {
        "cardsV2": [
            {
                "cardId": "phishing-report",
                "card": {
                    "header": {
                        "title": "Phishing Report Summary",
                        "subtitle": "Multiple User Reports",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/phishing/default/48px.svg",
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
                                                            "topLabel": "Target",
                                                            "text": "Finance / HR",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "groups"
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
                                                            "topLabel": "Sentiment",
                                                            "text": "Suspicious",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "mood_bad"
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
                                        "text": "Analysis indicates a phishing campaign targeting executives. Use the buttons below to investigate additional details."
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Check VirusTotal",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.6,
                                                    "blue": 0.1,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": "https://virustotal.com"
                                                    }
                                                },
                                            },
                                            {
                                                "text": "Delete emails",
                                                "color": {
                                                    "red": 0.8,
                                                    "green": 0,
                                                    "blue": 0,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": generate_action_url(
                                                            "Del",
                                                            session_id=session_id,
                                                            agent_engine_id=agent_engine_id,
                                                            user_id=user_id,
                                                        )
                                                    }
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
