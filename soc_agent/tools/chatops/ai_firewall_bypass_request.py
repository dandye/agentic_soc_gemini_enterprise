"""
ChatOps Card: ai_firewall_bypass_request
Modernized Version
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
                "cardId": "ai-fw",
                "card": {
                    "header": {
                        "title": "AI Agent Request",
                        "subtitle": "Temporary Firewall Bypass",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/shield_with_house/default/48px.svg",
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
                                                            "topLabel": "Source",
                                                            "text": "Isolated-VLAN-9",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "block"
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
                                                            "topLabel": "Target",
                                                            "text": "Analysis Bucket",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "storage"
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
                                    "decoratedText": {
                                        "topLabel": "Network Policy",
                                        "text": "Allow Port 443 (Egress)",
                                        "bottomLabel": "Duration: 10 minutes",
                                        "startIcon": {
                                            "materialIcon": {"name": "vpn_lock"}
                                        },
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Approve (10m)",
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
                                                "text": "Deny Request",
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
    send_card(get_card())
