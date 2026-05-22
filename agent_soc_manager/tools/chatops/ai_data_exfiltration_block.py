"""
ChatOps Card: ai_data_exfiltration_block
Generated from ai_data_exfiltration_block.sh
"""

from card_client import generate_action_url, send_card


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    # Dynamic URLs
    approve_url = generate_action_url(
        "Approve", session_id, agent_engine_id, user_id=user_id
    )
    deny_url = generate_action_url("Deny", session_id, agent_engine_id, user_id=user_id)
    return {
        "cardsV2": [
            {
                "cardId": "ai-exfil",
                "card": {
                    "header": {
                        "title": "AI DLP Alert",
                        "subtitle": "Large Outbound Transfer",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/upload_file/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "textParagraph": {
                                        "text": "User John Doe is uploading 14GB to <b>mega.nz</b>. This is atypical for their role. Should I shard the network connection?"
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Terminate Transfer",
                                                "color": {
                                                    "red": 0.8,
                                                    "green": 0,
                                                    "blue": 0,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": approve_url}
                                                },
                                            },
                                            {
                                                "text": "Acknowledge Only",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.6,
                                                    "blue": 0.1,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": deny_url}
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
    card = get_card(
        session_id="test-session", agent_engine_id="test-agent", user_id="test-user"
    )
    send_card(card)
