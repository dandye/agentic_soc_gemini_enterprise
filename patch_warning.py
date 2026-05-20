with open("soc_agent/agent.py") as f:
    content = f.read()

patch = """
# -------------------------------------------------------------------------
# Framework Monkey-Patches
# -------------------------------------------------------------------------
import logging
from google.adk.sessions.in_memory_session_service import InMemorySessionService

# Silence the harmless but noisy InMemorySessionService warning inside sub-agents
# The AgentTool spins up sub-agents with a brand new InMemorySessionService but passes
# the parent's session object, causing a "not in sessions" warning on every single event.
original_append_event = InMemorySessionService.append_event

async def _patched_append_event(self, session, event):
    app_name = session.app_name
    user_id = session.user_id
    session_id = session.id

    # Auto-initialize the session in the in-memory dict to prevent the warning
    if app_name not in self.sessions:
        self.sessions[app_name] = {}
    if user_id not in self.sessions[app_name]:
        self.sessions[app_name][user_id] = {}
    if session_id not in self.sessions[app_name][user_id]:
        self.sessions[app_name][user_id][session_id] = session

    return await original_append_event(self, session, event)

InMemorySessionService.append_event = _patched_append_event
# -------------------------------------------------------------------------

"""

if "InMemorySessionService.append_event = _patched_append_event" not in content:
    content = content.replace(
        "from google.adk.tools.agent_tool import AgentTool  # noqa: E402",
        "from google.adk.tools.agent_tool import AgentTool  # noqa: E402\n" + patch,
    )
    with open("soc_agent/agent.py", "w") as f:
        f.write(content)
    print("Patched.")
