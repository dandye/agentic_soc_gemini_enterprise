import os
from pathlib import Path

from card_client import generate_action_url, send_card
from dotenv import load_dotenv


"""
ChatOps Card: temp_admin_request
Generated from temp_admin_request.sh
"""


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    return {
        "cardsV2": [
            {
                "cardId": "temp-admin",
                "card": {
                    "header": {
                        "title": "Privilege Access",
                        "subtitle": "PIM Request Elevation",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/admin_panel_settings/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "Analyst",
                                        "text": "Analyst-Smith",
                                        "bottomLabel": "Duration: 60 mins",
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Approve",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.6,
                                                    "blue": 0.1,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": generate_action_url(
                                                            "Ok",
                                                            session_id=session_id,
                                                            agent_engine_id=agent_engine_id,
                                                            user_id=user_id,
                                                        )
                                                    }
                                                },
                                            },
                                            {
                                                "text": "Deny",
                                                "color": {
                                                    "red": 0.8,
                                                    "green": 0,
                                                    "blue": 0,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": generate_action_url(
                                                            "No",
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
