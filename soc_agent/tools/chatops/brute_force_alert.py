import os
from pathlib import Path

from card_client import send_card
from dotenv import load_dotenv


"""
ChatOps Card: brute_force_alert
Generated from brute_force_alert.sh
"""


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    return {
        "cardsV2": [
            {
                "cardId": "brute-force-opt",
                "card": {
                    "header": {
                        "title": "Critical Security Alert",
                        "subtitle": "Brute Force Attempt Detected",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/error/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "Source IP",
                                        "text": "192.168.1.105",
                                        "startIcon": {"knownIcon": "STAR"},
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "View in Chronicle",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": "https://chronicle.security/"
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
