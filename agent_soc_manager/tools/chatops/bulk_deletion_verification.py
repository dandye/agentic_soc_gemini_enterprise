import os
from pathlib import Path

from card_client import generate_action_url, send_card
from dotenv import load_dotenv


"""
ChatOps Card: bulk_deletion_verification
Generated from bulk_deletion_verification.sh
"""


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    return {
        "cardsV2": [
            {
                "cardId": "bulk-delete",
                "card": {
                    "header": {
                        "title": "Data Loss Prevention",
                        "subtitle": "Mass File Deletion Detected",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/delete_forever/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "Event",
                                        "text": "542 files deleted from OneDrive",
                                        "bottomLabel": "Target: /Archive/2023_Records",
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Intentional",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
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
                                                "text": "\ud83d\udea8 STOP & ROLLBACK",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": generate_action_url(
                                                            "Rollback",
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
