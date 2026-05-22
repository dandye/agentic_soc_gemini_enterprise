"""
ChatOps Card: ai_playbook_selection
Generated from ai_playbook_selection.sh
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
                "cardId": "ai-play",
                "card": {
                    "header": {
                        "title": "AI SOAR Orchestrator",
                        "subtitle": "Next Steps Recommendation",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/rebase/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "textParagraph": {
                                        "text": "I have completed initial triage. Based on incident signature, which playbook should I launch?"
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Full Ransomware Response",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {"url": approve_url}
                                                },
                                            },
                                            {
                                                "text": "Standard Malware Triage",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
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
