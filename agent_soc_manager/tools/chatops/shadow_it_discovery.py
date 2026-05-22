import os
from pathlib import Path

from card_client import generate_action_url, send_card
from dotenv import load_dotenv


"""
ChatOps Card: shadow_it_discovery
Generated from shadow_it_discovery.sh
"""


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    return {
        "cardsV2": [
            {
                "cardId": "shadow-it",
                "card": {
                    "header": {
                        "title": "Application Discovery",
                        "subtitle": "New App Connected to GSuite",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/category/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "App Name",
                                        "text": "Trello-Clone-v2",
                                        "bottomLabel": "Permissions: Read/Write Drive",
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Business Use",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": generate_action_url(
                                                            "Tag-Business",
                                                            session_id=session_id,
                                                            agent_engine_id=agent_engine_id,
                                                            user_id=user_id,
                                                        )
                                                    }
                                                },
                                            },
                                            {
                                                "text": "Personal Use",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": generate_action_url(
                                                            "Tag-Personal",
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
