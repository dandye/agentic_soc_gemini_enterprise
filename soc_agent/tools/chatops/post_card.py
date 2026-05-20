"""
ChatOps Card: post_card (Modernized)
Standard Security Alert Template
"""

from card_client import send_card


def get_card():
    return {
        "cardsV2": [
            {
                "cardId": "secops-alert-001",
                "card": {
                    "header": {
                        "title": "Critical Security Alert",
                        "subtitle": "Project: secops-demo-env",
                        "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/error/default/48px.svg",
                        "imageType": "CIRCLE",
                    },
                    "sections": [
                        {
                            "header": "Incident Details",
                            "widgets": [
                                {
                                    "columns": {
                                        "columnItems": [
                                            {
                                                "horizontalSizeStyle": "FILL_AVAILABLE_SPACE",
                                                "widgets": [
                                                    {
                                                        "decoratedText": {
                                                            "topLabel": "Detection Type",
                                                            "text": "Brute Force Attempt",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "bolt"
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
                                                            "topLabel": "Severity",
                                                            "text": "Critical",
                                                            "startIcon": {
                                                                "materialIcon": {
                                                                    "name": "warning"
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
                                        "topLabel": "Source IP",
                                        "text": "192.168.1.105",
                                        "bottomLabel": "Location: Unknown",
                                        "startIcon": {
                                            "materialIcon": {"name": "public"}
                                        },
                                    }
                                },
                            ],
                        },
                        {
                            "widgets": [
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
                                                        "url": "https://chronicle.security/investigation/secops-demo-env"
                                                    }
                                                },
                                            },
                                            {
                                                "text": "Open Runbook",
                                                "color": {
                                                    "red": 0.1,
                                                    "green": 0.4,
                                                    "blue": 0.8,
                                                },
                                                "onClick": {
                                                    "openLink": {
                                                        "url": "https://example.com/soar/playbook-123"
                                                    }
                                                },
                                            },
                                        ]
                                    }
                                }
                            ]
                        },
                    ],
                },
            }
        ]
    }


if __name__ == "__main__":
    send_card(get_card())
