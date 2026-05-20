"""
ChatOps Card: ai_incident_summary_confirm
Generated from ai_incident_summary_confirm.sh
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
                "cardId": "ai-summary",
                "card": {
                    "header": {
                        "title": "AI Agent Reasoning",
                        "subtitle": "Incident #992 Analysis",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/psychology/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "textParagraph": {
                                        "text": "<b>Summary:</b> I have linked three failed logins to a later successful VPN entry. I believe this is valid Credential Stuffing."
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Correct, proceed",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.6,
                                                    "blue": 0.1,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": approve_url}
                                                },
                                            },
                                            {
                                                "text": "Mistaken, close",
                                                "color": {
                                                    "red": 0.8,
                                                    "green": 0,
                                                    "blue": 0,
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
