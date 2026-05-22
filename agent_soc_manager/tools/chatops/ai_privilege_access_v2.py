"""
ChatOps Card: ai_privilege_access_v2
Generated from Privilege Access Card_ V2 JSON Schema and Design Principles.md
"""

from card_client import generate_action_url, send_card


def get_card(session_id: str = None, agent_engine_id: str = None, user_id: str = None):
    # Dynamic URLs for buttons
    approve_url = generate_action_url(
        "Approve Elevation", session_id, agent_engine_id, user_id=user_id
    )
    deny_url = generate_action_url(
        "Deny Elevation", session_id, agent_engine_id, user_id=user_id
    )

    return {
        "cardsV2": [
            {
                "cardId": "privilege_access_card",
                "card": {
                    "header": {
                        "title": "Privilege Access",
                        "subtitle": "PIM Request Elevation",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/admin_panel_settings/default/24px.svg",
                        "imageType": "SQUARE",
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
                                                            "topLabel": "Analyst",
                                                            "text": "Analyst-Smith",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "person"
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
                                                            "topLabel": "Duration",
                                                            "text": "60 mins",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "schedule"
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
                                                "text": "Approve",
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
                                                "text": "Deny",
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
