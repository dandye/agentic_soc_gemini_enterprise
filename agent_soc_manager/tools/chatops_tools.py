import importlib
import logging
import os

import httpx
from google.adk.agents.context import Context

from agent_soc_manager.tools.chatops.card_client import generate_action_url


# Explicit webhook timeout (issue #64): httpx's implicit 5s default was relied
# on before; make it visible and configurable.
CHATOPS_HTTP_TIMEOUT = float(os.environ.get("CHATOPS_HTTP_TIMEOUT", "30"))


logger = logging.getLogger(__name__)


def _chat_app_mode() -> bool:
    """True when ChatOps should post as the registered Chat App (issue #62).

    Native app posting enables background button actions (no browser tab).
    Webhook mode remains the default until CHATOPS_MODE=chat_app is set.
    """
    return os.environ.get("CHATOPS_MODE", "webhook").strip().lower() == "chat_app"


async def _send_via_chat_app(payload: dict) -> str:
    """Posts a card as the Chat App with action buttons converted in place.

    The one-seam migration: every card template's signed openLink buttons
    are rewritten to native onClick.action payloads here, so no template
    needs editing and clicks execute in the background.
    """
    from agent_soc_manager.tools.chatops.chat_api import (
        convert_openlink_to_action,
        post_card_as_app,
    )

    space = os.environ.get("CHAT_SPACE")
    if not space:
        logger.error("CHATOPS_MODE=chat_app but CHAT_SPACE is not set.")
        return (
            "Error: CHATOPS_MODE=chat_app requires CHAT_SPACE (e.g. "
            "'spaces/AAAA1234'). No message was sent to a human analyst."
        )

    try:
        converted = convert_openlink_to_action(payload)
        message_name = await post_card_as_app(space, converted)
        logger.info(f"ChatOps card posted as Chat App: {message_name}")
        return f"Successfully sent ChatOps card as Chat App. (Message: {message_name})"
    except Exception as e:
        logger.error(f"Failed to post ChatOps card as Chat App: {e}")
        return (
            f"Error sending ChatOps card via Chat App: {e}. "
            "No human analyst was notified."
        )


def _get_context_ids(
    ctx: Context,
) -> tuple[str | None, str | None, str | None]:
    """
    Extracts session_id, agent_engine_id, and user_id from the ADK Context and environment variables.
    Handles quote stripping and fallback logic for Playground testing.
    """
    session_id = None

    # 1. Provide safe extraction for AGENT_ENGINE_ID (quote stripping)
    agent_engine_id = os.environ.get("AGENT_ENGINE_RESOURCE_NAME")
    if agent_engine_id:
        agent_engine_id = agent_engine_id.strip("'").strip('"')

    # 2. Extract Session ID (with liberal logging for debug)
    if ctx:
        logger.info(f"[CHATOPS DEBUG] Inspecting Context object: dir={dir(ctx)}")
        if hasattr(ctx, "session"):
            logger.info(
                f"[CHATOPS DEBUG] Found ctx.session. Type={type(ctx.session)}, Value={ctx.session}"
            )
            if hasattr(ctx.session, "id"):
                session_id = ctx.session.id
            elif isinstance(ctx.session, str) and ctx.session:
                session_id = ctx.session

            if (
                not agent_engine_id
                and hasattr(ctx.session, "app_name")
                and ctx.session.app_name
            ):
                agent_engine_id = ctx.session.app_name
                logger.info(
                    f"[CHATOPS DEBUG] Natively resolved agent_engine_id from ADK session: {agent_engine_id}"
                )
        elif hasattr(ctx, "_invocation_context"):
            logger.info("[CHATOPS DEBUG] Found ctx._invocation_context. Inspecting...")
            if hasattr(ctx._invocation_context, "session"):
                if hasattr(ctx._invocation_context.session, "id"):
                    session_id = ctx._invocation_context.session.id
                elif isinstance(ctx._invocation_context.session, str):
                    session_id = ctx._invocation_context.session

                if (
                    not agent_engine_id
                    and hasattr(ctx._invocation_context.session, "app_name")
                    and ctx._invocation_context.session.app_name
                ):
                    agent_engine_id = ctx._invocation_context.session.app_name
                    logger.info(
                        f"[CHATOPS DEBUG] Natively resolved agent_engine_id from ADK context wrapper: {agent_engine_id}"
                    )

        if not session_id:
            logger.warning(
                f"[CHATOPS DEBUG] Failed to extract session_id! Dumping full Context __dict__: {getattr(ctx, '__dict__', 'No __dict__')}"
            )

    # 3. Extract User ID with Fallback
    user_id = None
    if ctx and hasattr(ctx, "user_id") and ctx.user_id:
        user_id = ctx.user_id
    else:
        # Fallback for Playground identity lock compliance
        user_id = "vais-query-reasoning-engine"

    return session_id, agent_engine_id, user_id


async def send_raw_card(payload: dict) -> str:
    """
    Sends a complete raw JSON card payload to the configured Google Chat webhook asynchronously.

    When CHATOPS_MODE=chat_app, posts as the registered Chat App instead so
    card buttons execute in the background (issue #62).
    """
    if _chat_app_mode():
        return await _send_via_chat_app(payload)

    webhook_url = os.environ.get("WEBHOOK_URL")
    if not webhook_url:
        logger.error("WEBHOOK_URL environment variable is not set.")
        return "Error: WEBHOOK_URL environment variable is not set."

    try:
        async with httpx.AsyncClient(timeout=CHATOPS_HTTP_TIMEOUT) as client:
            response = await client.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )
            response.raise_for_status()
            logger.info("Raw ChatOps card sent successfully.")
            return f"Successfully sent ChatOps card. (Status: {response.status_code})"
    except Exception as e:
        logger.error(f"Failed to send raw ChatOps card: {e}")
        return f"Error sending ChatOps card: {str(e)}"


async def dispatch_card(template_name: str, ctx: Context, **kwargs) -> str:
    """
    Dynamically loads and dispatches a Google Chat card from the chatops library.

    Args:
        template_name: The name of the python module in agent_soc_manager.tools.chatops (without .py)
        ctx: ADK Context to extract session and user IDs
        **kwargs: Dynamic variables to pass to the card's get_card() function.
    """
    try:
        import sys
        from pathlib import Path

        chatops_path = str(Path(__file__).parent / "chatops")
        if chatops_path not in sys.path:
            sys.path.insert(0, chatops_path)

        module = importlib.import_module(
            f"agent_soc_manager.tools.chatops.{template_name}"
        )
        if not hasattr(module, "get_card"):
            return f"Error: Template '{template_name}' does not implement get_card()."

        session_id, agent_engine_id, user_id = _get_context_ids(ctx)

        # Inject standard context args securely
        kwargs["session_id"] = session_id
        kwargs["agent_engine_id"] = agent_engine_id
        kwargs["user_id"] = user_id

        # All modern cards return a full `{"cardsV2": [...]}` dict
        card_content = module.get_card(**kwargs)

        return await send_raw_card(card_content)

    except ImportError:
        return f"Error: Card template '{template_name}' not found."
    except Exception as e:
        logger.error(f"Failed to dispatch card {template_name}: {e}")
        return f"Error dispatching card: {e}"


async def verify_user_travel(
    user_email: str, location: str, arrival_time: str, ctx: Context
) -> str:
    """
    Sends an impossible travel confirmation card to a user.
    Uses the 'traveler_confirmation' template.

    Args:
        user_email: The email of the affected user.
        location: The suspicious travel location.
        arrival_time: When the login occurred.
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card(
        "traveler_confirmation",
        ctx,
        user_email=user_email,
        location=location,
        arrival_time=arrival_time,
    )


async def request_triage_approval(
    finding_summary: str, target_system: str, ctx: Context
) -> str:
    """
    Sends an approval card to human analysts for host isolation.
    Uses the 'host_isolation_approval' template.

    Args:
        finding_summary: Why this system needs isolation.
        target_system: The hostname or IP to isolate.
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card(
        "host_isolation_approval",
        ctx,
        finding_summary=finding_summary,
        target_system=target_system,
    )


async def deliver_report(case_id: str, report_summary: str, ctx: Context) -> str:
    """
    Sends a card indicating a triage report is ready for download.
    Uses the 'triage_report_ready' template.

    Args:
        case_id: The ID of the investigation.
        report_summary: A brief summary of the findings.
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card(
        "triage_report_ready", ctx, case_id=case_id, report_summary=report_summary
    )


async def generic_notification(card_template_name: str, ctx: Context, **kwargs) -> str:
    """
    Sends any existing chatops card template by name.

    Args:
        card_template_name: The name of the python module (e.g. 'impossible_travel_alert' or 'ai_stale_account_cleanup').
        ctx: The ADK Context (injected automatically).
        **kwargs: Must include any keyword arguments the target card's get_card() expects.
    """
    return await dispatch_card(card_template_name, ctx, **kwargs)


async def send_chatops_card(
    title: str,
    subtitle: str,
    sections: list[dict],
    card_id: str = "soc-agent-alert",
    image_url: str = "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/security/default/48px.svg",
) -> str:
    """
    Sends a rich V2 card to the configured ChatOps webhook (Google Chat).

    Args:
        title: The title of the card header.
        subtitle: The subtitle of the card header.
        sections: A list of card section dictionaries. Each section can contain widgets (textParagraph, decoratedText, buttonList).
        card_id: Unique ID for the card (optional).
        image_url: URL for the header icon (optional).
    """
    payload_for_chat_app = {
        "cardsV2": [
            {
                "cardId": card_id,
                "card": {
                    "header": {
                        "title": title,
                        "subtitle": subtitle,
                        "imageUrl": image_url,
                        "imageType": "CIRCLE",
                    },
                    "sections": sections,
                },
            }
        ]
    }
    if _chat_app_mode():
        return await _send_via_chat_app(payload_for_chat_app)

    webhook_url = os.environ.get("WEBHOOK_URL")
    if not webhook_url:
        logger.error("WEBHOOK_URL environment variable is not set.")
        return "Error: WEBHOOK_URL environment variable is not set. Please configure it in .env."

    payload = payload_for_chat_app

    try:
        async with httpx.AsyncClient(timeout=CHATOPS_HTTP_TIMEOUT) as client:
            response = await client.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )
            response.raise_for_status()
            logger.info(f"ChatOps card sent successfully: {card_id}")
            return f"Successfully sent ChatOps card to human analyst. (Status: {response.status_code})"
    except httpx.TimeoutException:
        logger.error(f"ChatOps webhook timed out after {CHATOPS_HTTP_TIMEOUT}s")
        return (
            f"Error: ChatOps webhook timed out after {CHATOPS_HTTP_TIMEOUT}s. "
            "No human analyst was notified."
        )
    except Exception as e:
        # Never fabricate delivery success: request_human_confirmation and
        # notify_human_incident route through this function, and a false
        # "Successfully sent" makes the agent believe a human approved or was
        # notified of a state-changing action that nobody saw.
        if os.getenv("CHATOPS_MOCK_FALLBACK", "").lower() in ("1", "true", "yes"):
            logger.warning(
                f"Failed to send ChatOps card to webhook: {e}. "
                "CHATOPS_MOCK_FALLBACK is enabled; returning explicit mock result."
            )
            return (
                "MOCK ONLY - ChatOps webhook unreachable; NO message was delivered "
                "to a human analyst. (CHATOPS_MOCK_FALLBACK active for evaluation)"
            )
        logger.error(f"Failed to send ChatOps card to webhook: {e}")
        return f"Error sending ChatOps card: {e}. No human analyst was notified."


async def request_human_confirmation(
    action_name: str,
    description: str,
    context_data: str,
    ctx: Context,
    approval_url: str = None,
    deny_url: str = None,
) -> str:
    """
    Sends a request for human-in-the-loop confirmation via ChatOps.
    If 'ctx' is available, it will generate secure signed URLs for the action.

    Args:
        action_name: The name of the action requiring confirmation (e.g. 'Block IP', 'Isolate Host').
        description: Why this action is being proposed.
        context_data: Relevant data snippets (e.g. IP address, hostname, alert ID).
        ctx: ADK Context (automatically injected).
        approval_url: Override URL to approve (optional).
        deny_url: Override URL to deny (optional).
    """
    # Auto-resolve session and agent IDs from context utilizing the new secure helper
    session_id, agent_engine_id, user_id = _get_context_ids(ctx)

    # Generate signed URLs if not explicitly provided
    if not approval_url:
        approval_url = generate_action_url(
            f"Approve {action_name}", session_id, agent_engine_id, user_id=user_id
        )
    if not deny_url:
        deny_url = generate_action_url(
            f"Deny {action_name}", session_id, agent_engine_id, user_id=user_id
        )

    sections = [
        {
            "header": "Action Required",
            "widgets": [
                {
                    "decoratedText": {
                        "topLabel": "Proposed Action",
                        "text": action_name,
                        "startIcon": {"knownIcon": "STAR"},
                    }
                },
                {"textParagraph": {"text": f"<b>Rationale:</b> {description}"}},
                {
                    "decoratedText": {
                        "topLabel": "Context",
                        "text": context_data,
                        "startIcon": {"knownIcon": "BOOKMARK"},
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
                                "text": "Approve",
                                "color": {"red": 0.1, "green": 0.6, "blue": 0.1},
                                "onClick": {"openLink": {"url": approval_url}},
                            },
                            {
                                "text": "Deny",
                                "color": {"red": 0.8, "green": 0, "blue": 0},
                                "onClick": {"openLink": {"url": deny_url}},
                            },
                        ]
                    }
                }
            ]
        },
    ]

    return await send_chatops_card(
        title="Human Confirmation Required",
        subtitle="Agent proposing state-changing action",
        sections=sections,
        card_id=f"confirm-{action_name.lower().replace(' ', '-')}",
        image_url="https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/contact_support/default/48px.svg",
    )


async def notify_human_incident(
    incident_id: str, severity: str, summary: str, chronicle_link: str = None
) -> str:
    """
    Notifies a human analyst about a new high-priority incident.

    Args:
        incident_id: The ID of the incident.
        severity: Severity level (e.g. CRITICAL, HIGH).
        summary: Short summary of the incident.
        chronicle_link: Link to the investigation in Chronicle (optional).
    """
    widgets = [
        {
            "decoratedText": {
                "topLabel": "Incident ID",
                "text": incident_id,
                "startIcon": {"knownIcon": "TICKET"},
            }
        },
        {
            "decoratedText": {
                "topLabel": "Severity",
                "text": severity,
                "startIcon": {"materialIcon": {"name": "report_problem"}},
            }
        },
        {"textParagraph": {"text": f"<b>Summary:</b> {summary}"}},
    ]

    if chronicle_link:
        widgets.append(
            {
                "buttonList": {
                    "buttons": [
                        {
                            "text": "View in Chronicle",
                            "onClick": {"openLink": {"url": chronicle_link}},
                        }
                    ]
                }
            }
        )

    sections = [{"widgets": widgets}]

    return await send_chatops_card(
        title="Critical Incident Notification",
        subtitle=f"Automated Alert: {severity}",
        sections=sections,
        card_id=f"incident-{incident_id}",
        image_url="https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/error/default/48px.svg",
    )


# --- AUTO-GENERATED CHATOPS SKILL WRAPPERS ---


async def trigger_ai_brute_force_source_block_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Brute Force Source Block.
    Use this to request human interaction regarding Brute Force Source Block.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_brute_force_source_block", ctx)


async def trigger_ai_canary_token_deployment_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Canary Token Deployment.
    Use this to request human interaction regarding Canary Token Deployment.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_canary_token_deployment", ctx)


async def trigger_ai_compliance_violation_alert_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Compliance Violation Alert.
    Use this to request human interaction regarding Compliance Violation Alert.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_compliance_violation_alert", ctx)


async def trigger_ai_credential_reset_approval_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Credential Reset Approval.
    Use this to request human interaction regarding Credential Reset Approval.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_credential_reset_approval", ctx)


async def trigger_ai_data_classification_request_card(
    ctx: Context,
) -> str:
    """
    Sends the pre-formatted ChatOps card for Data Classification Request.
    Use this to request human interaction regarding Data Classification Request.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_data_classification_request", ctx)


async def trigger_ai_data_exfiltration_block_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Data Exfiltration Block.
    Use this to request human interaction regarding Data Exfiltration Block.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_data_exfiltration_block", ctx)


async def trigger_ai_dns_exfiltration_detection_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Dns Exfiltration Detection.
    Use this to request human interaction regarding Dns Exfiltration Detection.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_dns_exfiltration_detection", ctx)


async def trigger_ai_draft_comms_review_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Draft Comms Review.
    Use this to request human interaction regarding Draft Comms Review.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_draft_comms_review", ctx)


async def trigger_ai_false_positive_tuning_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for False Positive Tuning.
    Use this to request human interaction regarding False Positive Tuning.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_false_positive_tuning", ctx)


async def trigger_ai_firewall_bypass_request_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Firewall Bypass Request.
    Use this to request human interaction regarding Firewall Bypass Request.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_firewall_bypass_request", ctx)


async def trigger_ai_forensic_image_approval_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Forensic Image Approval.
    Use this to request human interaction regarding Forensic Image Approval.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_forensic_image_approval", ctx)


async def trigger_ai_incident_closure_confirm_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Incident Closure Confirm.
    Use this to request human interaction regarding Incident Closure Confirm.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_incident_closure_confirm", ctx)


async def trigger_ai_incident_retrospective_request_card(
    ctx: Context,
) -> str:
    """
    Sends the pre-formatted ChatOps card for Incident Retrospective Request.
    Use this to request human interaction regarding Incident Retrospective Request.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_incident_retrospective_request", ctx)


async def trigger_ai_incident_summary_confirm_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Incident Summary Confirm.
    Use this to request human interaction regarding Incident Summary Confirm.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_incident_summary_confirm", ctx)


async def trigger_ai_malicious_container_kill_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Malicious Container Kill.
    Use this to request human interaction regarding Malicious Container Kill.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_malicious_container_kill", ctx)


async def trigger_ai_malicious_domain_sinkhole_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Malicious Domain Sinkhole.
    Use this to request human interaction regarding Malicious Domain Sinkhole.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_malicious_domain_sinkhole", ctx)


async def trigger_ai_network_scan_approval_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Network Scan Approval.
    Use this to request human interaction regarding Network Scan Approval.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_network_scan_approval", ctx)


async def trigger_ai_playbook_selection_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Playbook Selection.
    Use this to request human interaction regarding Playbook Selection.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_playbook_selection", ctx)


async def trigger_ai_privilege_access_v2_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Privilege Access V2.
    Use this to request human interaction regarding Privilege Access V2.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_privilege_access_v2", ctx)


async def trigger_ai_privileged_session_recording_card(
    ctx: Context,
) -> str:
    """
    Sends the pre-formatted ChatOps card for Privileged Session Recording.
    Use this to request human interaction regarding Privileged Session Recording.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_privileged_session_recording", ctx)


async def trigger_ai_security_group_audit_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Security Group Audit.
    Use this to request human interaction regarding Security Group Audit.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_security_group_audit", ctx)


async def trigger_ai_sensitive_log_access_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Sensitive Log Access.
    Use this to request human interaction regarding Sensitive Log Access.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_sensitive_log_access", ctx)


async def trigger_ai_stale_account_cleanup_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Stale Account Cleanup.
    Use this to request human interaction regarding Stale Account Cleanup.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_stale_account_cleanup", ctx)


async def trigger_ai_suspicious_login_location_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Suspicious Login Location.
    Use this to request human interaction regarding Suspicious Login Location.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_suspicious_login_location", ctx)


async def trigger_ai_suspicious_process_kill_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Suspicious Process Kill.
    Use this to request human interaction regarding Suspicious Process Kill.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_suspicious_process_kill", ctx)


async def trigger_ai_threat_hunt_hypothesis_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Threat Hunt Hypothesis.
    Use this to request human interaction regarding Threat Hunt Hypothesis.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_threat_hunt_hypothesis", ctx)


async def trigger_ai_threat_intel_sharing_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Threat Intel Sharing.
    Use this to request human interaction regarding Threat Intel Sharing.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_threat_intel_sharing", ctx)


async def trigger_ai_user_interview_request_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for User Interview Request.
    Use this to request human interaction regarding User Interview Request.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_user_interview_request", ctx)


async def trigger_ai_user_privilege_audit_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for User Privilege Audit.
    Use this to request human interaction regarding User Privilege Audit.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_user_privilege_audit", ctx)


async def trigger_ai_vulnerability_revalidation_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Vulnerability Revalidation.
    Use this to request human interaction regarding Vulnerability Revalidation.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_vulnerability_revalidation", ctx)


async def trigger_ai_wipe_host_approval_card(ctx: Context) -> str:
    """
    Sends the pre-formatted ChatOps card for Wipe Host Approval.
    Use this to request human interaction regarding Wipe Host Approval.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ai_wipe_host_approval", ctx)


async def trigger_brute_force_alert_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Brute Force Alert.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("brute_force_alert", ctx)


async def trigger_bulk_deletion_verification_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Bulk Deletion Verification.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("bulk_deletion_verification", ctx)


async def trigger_forensics_evidence_ready_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Forensics Evidence Ready.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("forensics_evidence_ready", ctx)


async def trigger_impossible_travel_alert_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Impossible Travel Alert.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("impossible_travel_alert", ctx)


async def trigger_impossible_travel_verification_card(
    ctx: Context,
) -> str:
    """
    Sends the ChatOps notification card for Impossible Travel Verification.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("impossible_travel_verification", ctx)


async def trigger_ioc_enrichment_card_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Ioc Enrichment Card.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("ioc_enrichment_card", ctx)


async def trigger_malware_sandbox_report_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Malware Sandbox Report.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("malware_sandbox_report", ctx)


async def trigger_mfa_api_key_alert_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Mfa Api Key Alert.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("mfa_api_key_alert", ctx)


async def trigger_phishing_report_summary_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Phishing Report Summary.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("phishing_report_summary", ctx)


async def trigger_shadow_it_discovery_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Shadow It Discovery.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("shadow_it_discovery", ctx)


async def trigger_temp_admin_request_card(ctx: Context) -> str:
    """
    Sends the ChatOps notification card for Temp Admin Request.

    Args:
        ctx: The ADK context (injected automatically).
    """
    return await dispatch_card("temp_admin_request", ctx)


async def trigger_vulnerability_patch_approval_card(
    ctx: Context,
    cve_id: str = None,
    software_name: str = None,
    software_version: str = None,
    cvss_score: str = None,
    finding_summary: str = None,
    remediation_notes: str = None,
    target_system: str = None,
    cve_link: str = None,
) -> str:
    """
    Sends the ChatOps notification card for Vulnerability Patch Approval.

    Args:
        ctx: The ADK context (injected automatically).
        cve_id: The CVE identifier (e.g., "CVE-2026-1603").
        software_name: The name of the vulnerable software (e.g., "Ivanti Endpoint Manager (EPM)").
        software_version: The vulnerable version found (e.g., "2024 SU4 SR1").
        cvss_score: The CVSS severity score (e.g., "8.6 (High)").
        finding_summary: A summary of the vulnerability impact.
        remediation_notes: Analyst recommendations for patching or mitigating.
        target_system: The hostname or IP of the vulnerable system.
        cve_link: A URL linking to the CVE details.
    """
    # Build kwargs dynamically, only including non-None values to allow template defaults to shine through
    vuln_args = {}
    if cve_id:
        vuln_args["cve_id"] = cve_id
    if software_name:
        vuln_args["software_name"] = software_name
    if software_version:
        vuln_args["software_version"] = software_version
    if cvss_score:
        vuln_args["cvss_score"] = cvss_score
    if finding_summary:
        vuln_args["finding_summary"] = finding_summary
    if remediation_notes:
        vuln_args["remediation_notes"] = remediation_notes
    if target_system:
        vuln_args["target_system"] = target_system
    if cve_link:
        vuln_args["cve_link"] = cve_link

    return await dispatch_card("vulnerability_patch_approval", ctx, **vuln_args)


async def list_chatops_capabilities(ctx: Context) -> str:
    """
    Returns an exhaustive list and descriptions of all available ChatOps skills, cards, and notification templates.
    Use this tool to discover what specific notification templates (e.g., ai_wipe_host_approval, ai_malicious_container_kill)
    are available for the generic_notification dispatcher, and to understand the capabilities of the core ChatOps tools.
    """
    from pathlib import Path

    try:
        skill_md_path = (
            Path(__file__).parent.parent / "skills" / "chatops-skill" / "SKILL.md"
        )
        if skill_md_path.exists():
            with open(skill_md_path, encoding="utf-8") as f:
                content = f.read()

            tools_summary_idx = content.find("**Tools Summary:**")
            if tools_summary_idx != -1:
                return (
                    "=== EXHAUSTIVE CHATOPS CAPABILITIES ===\n\n"
                    + content[tools_summary_idx:]
                )
            return content

        return "Error: Could not find SKILL.md documentation."
    except Exception as e:
        return f"Error reading ChatOps capabilities: {e}"


async def send_all_example_cards(ctx: Context) -> str:
    """
    Sends one of each kind of predefined ChatOps card to the configured webhook.
    This is useful for demos and quality control to visualize all available templates.
    """
    import asyncio
    from pathlib import Path

    cards_dir = Path(__file__).parent / "chatops"
    sent_cards = []
    errors = []

    for py_file in cards_dir.glob("*.py"):
        if py_file.name in [
            "__init__.py",
            "card_client.py",
            "security.py",
            "test_integration.py",
            "test_security.py",
            "webhook_handler.py",
            "fix_legacy_templates.py",
            "generate_test_url.py",
        ]:
            continue

        template_name = py_file.stem
        try:
            response = await dispatch_card(template_name, ctx)
            if response.startswith("Error"):
                errors.append(f"{template_name}: {response}")
            else:
                sent_cards.append(template_name)

            # Google Chat Webhooks are strictly limited to 1 request per second
            await asyncio.sleep(1.5)
        except Exception as e:
            errors.append(f"{template_name}: {e}")

    result = f"Successfully sent {len(sent_cards)} example cards.\n"
    if errors:
        result += f"Errors encountered ({len(errors)}):\n" + "\n".join(errors)
    return result
