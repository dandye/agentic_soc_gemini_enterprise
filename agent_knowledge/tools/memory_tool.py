import datetime
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Fallback in-memory store when ADK session memory service is not active
_in_memory_store: list[dict[str, Any]] = []


def _extract_session_state(ctx: Optional[Any]) -> Optional[dict[str, Any]]:
    """Extract session state dict from ADK Context or dictionary if available."""
    if ctx is None:
        return None
    if isinstance(ctx, dict):
        return ctx
    if hasattr(ctx, "session") and hasattr(ctx.session, "state") and isinstance(ctx.session.state, dict):
        return ctx.session.state
    if hasattr(ctx, "state") and isinstance(ctx.state, dict):
        return ctx.state
    if hasattr(ctx, "_invocation_context") and hasattr(ctx._invocation_context, "session"):
        session = getattr(ctx._invocation_context, "session", None)
        if session and hasattr(session, "state") and isinstance(session.state, dict):
            return session.state
    return None


def add_investigation_note(
    entity: str,
    note: str,
    tag: str = "general",
    ctx: Optional[Any] = None,
) -> None:
    """
    Record an active investigation hypothesis, containment tag, or entity observation.

    Args:
        entity: Target entity identifier (e.g. hostname, IP, user, domain).
        note: Detailed investigation note or observation.
        tag: Category or lifecycle tag (e.g. 'credential_spray', 'containment', 'lateral_movement').
        ctx: Optional ADK agent context containing session state.
    """
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "entity": entity.strip().lower(),
        "tag": tag.strip(),
        "note": note.strip(),
    }

    _in_memory_store.append(record)

    session_state = _extract_session_state(ctx)
    if session_state is not None:
        session_state.setdefault("investigation_memory", []).append(record)

    logger.debug(f"Added investigation note for entity '{entity}' [tag: {tag}]")


async def query_investigation_memory(
    entity: Optional[str] = None,
    query: Optional[str] = None,
    max_results: int = 5,
    ctx: Optional[Any] = None,
) -> str:
    """
    Search past and active cross-session investigation memory for analyst hypotheses, containment tags, and entity observations.

    Args:
        entity: Target entity identifier to filter memory notes.
        query: Semantic search query across investigation memory notes and tags.
        max_results: Maximum memory notes to return (default 5, clamped between 1 and 50).
        ctx: Optional ADK agent context.
    """
    try:
        max_results = min(max(1, max_results), 50)

        # Collect records from context session state and fallback in-memory store
        all_records: list[dict[str, Any]] = []
        seen_ids = set()

        session_state = _extract_session_state(ctx)
        if session_state is not None:
            ctx_records = session_state.get("investigation_memory", [])
            if isinstance(ctx_records, list):
                for rec in ctx_records:
                    if isinstance(rec, dict):
                        rec_key = (rec.get("timestamp"), rec.get("entity"), rec.get("note"))
                        if rec_key not in seen_ids:
                            seen_ids.add(rec_key)
                            all_records.append(rec)

        for rec in _in_memory_store:
            rec_key = (rec.get("timestamp"), rec.get("entity"), rec.get("note"))
            if rec_key not in seen_ids:
                seen_ids.add(rec_key)
                all_records.append(rec)

        # Filter in reverse chronological order (most recent first)
        results = []
        target_entity = entity.strip().lower() if entity else None
        target_query = query.strip().lower() if query else None

        for record in reversed(all_records):
            rec_entity = str(record.get("entity", "")).lower()
            rec_note = str(record.get("note", "")).lower()
            rec_tag = str(record.get("tag", "")).lower()

            matches_entity = not target_entity or target_entity in rec_entity
            matches_query = (
                not target_query
                or target_query in rec_note
                or target_query in rec_tag
                or target_query in rec_entity
            )

            if matches_entity and matches_query:
                results.append(record)
                if len(results) >= max_results:
                    break

        if not results:
            entity_desc = f" for entity '{entity}'" if entity else ""
            query_desc = f" with query '{query}'" if query else ""
            return f"No investigation memory records found{entity_desc}{query_desc}."

        lines = ["=== Investigation Memory Notes ==="]
        for idx, rec in enumerate(results, 1):
            lines.append(
                f"[{idx}] Time: {rec.get('timestamp', 'Unknown')} | Entity: {rec.get('entity', 'Unknown')} | Tag: {rec.get('tag', 'general')}\n"
                f"    Note: {rec.get('note', '')}"
            )
        return "\n\n".join(lines)

    except Exception as e:
        logger.error(f"Investigation memory query failed: {e}")
        return f"[Investigation Memory Query Error: {str(e)}]"
