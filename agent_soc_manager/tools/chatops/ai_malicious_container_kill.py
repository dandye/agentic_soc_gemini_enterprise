"""
ChatOps Card: ai_malicious_container_kill
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
                "cardId": "ai-k8s-kill",
                "card": {
                    "header": {
                        "title": "AI Runtime Defense",
                        "subtitle": "Container Compromise Detected",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/view_in_ar/default/48px.svg",
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
                                                            "topLabel": "Target Pod",
                                                            "text": "auth-api-88x",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "layers"
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
                                                            "topLabel": "CPU Usage",
                                                            "text": '<font color="#ff0000">100%</font>',
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "speed"
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
                                        "topLabel": "Detection Pattern",
                                        "text": "Cryptominer signatures identified",
                                        "startIcon": {
                                            "materialIcon": {"name": "security"}
                                        },
                                    }
                                },
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Kill & Redeploy",
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
                                                "text": "Debug Console",
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
    send_card(get_card())
