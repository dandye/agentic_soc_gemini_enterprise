import os
from pathlib import Path

from card_client import generate_action_url, send_card
from dotenv import load_dotenv


"""
ChatOps Card: ioc_enrichment_card
Modernized Version
"""


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    return {
        "cardsV2": [
            {
                "cardId": "ioc-enrich",
                "card": {
                    "header": {
                        "title": "IOC Enrichment",
                        "subtitle": "Intelligence for IP 1.2.3.4",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/hub/default/48px.svg",
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
                                                            "topLabel": "CrowdStrike",
                                                            "text": "Fancy Bear / APT28",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "flag"
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
                                                            "topLabel": "VirusTotal",
                                                            "text": '<font color="#ff0000">45/70</font> Detections',
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "security"
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
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Investigate History",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": generate_action_url(
                                                            "History",
                                                            session_id=session_id,
                                                            agent_engine_id=agent_engine_id,
                                                            user_id=user_id,
                                                        )
                                                    }
                                                },
                                            }
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
