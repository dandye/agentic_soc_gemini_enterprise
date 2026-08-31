#!/usr/bin/env python3
"""
Live End-to-End Test: Invokes ADK Agent equipped with Code Execution Sandbox.
Sends realistic SOC hunting prompts to Gemini and watches it write and execute Python code.
"""

import asyncio
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure project root in path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load .env
load_dotenv(Path(".env"), override=True)

# Set mTLS defaults
os.environ["GOOGLE_API_USE_MTLS_ENDPOINT"] = "never"
os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "false"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"

from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.genai.types import Content, Part
from google.adk.agents import Agent
from installation_scripts.code_executor_factory import get_code_executor
from test_agents.soc_code_analysis_agent.agent import SYSTEM_INSTRUCTION


async def run_live_code_execution_session():
    print("=" * 80)
    print("LIVE ADK AGENT CODE EXECUTION TEST (GEMINI 2.5 FLASH + PYTHON SANDBOX)")
    print("=" * 80)

    # Use local code executor for reliable hermetic execution
    agent = Agent(
        name="soc_code_analysis_agent",
        model="gemini-2.5-flash",
        instruction=SYSTEM_INSTRUCTION,
        code_executor=get_code_executor("local"),
    )

    session_svc = InMemorySessionService()
    artifact_svc = InMemoryArtifactService()
    runner = Runner(
        agent=agent,
        session_service=session_svc,
        artifact_service=artifact_svc,
        app_name="soc_live_test",
    )

    session = await session_svc.create_session(
        app_name="soc_live_test",
        user_id="dandye",
    )
    session_id = session.id
    print(f"[*] Created live ADK test session: {session_id}")

    prompt_text = """
We received a Chronicle SIEM alert regarding potential DGA domain queries and an obfuscated dropper payload on host WRK-PACMAN.

Please perform the following analytics using your Python Code Execution Sandbox:
1. Write a Python script to compute the Shannon entropy for these queried domains:
   - 'portal.internal.corp'
   - 'xk92bvf0q81lzmn04.evil-c2.net'
   - 'q7z9w8p3m2k1v5x.bad-infra.org'
   Identify which domains are high-entropy DGAs (entropy > 3.8).

2. De-obfuscate this single-byte XOR encoded payload hex string to find the cleartext C2 beacon URL:
   '32 2e 2e 2a 29 60 75 75 3b 2a 2e 68 63 77 39 68 75 3f 2c 33 36 77 3e 35 37 3b 33 34 74 39 35 37 75 38 3f 3b 39 35 34'

3. Provide a clear summary of your findings and suggest a YARA rule for the recovered C2 indicator.
"""

    print("\n[USER PROMPT]")
    print(prompt_text.strip())
    print("\n[AGENT EXECUTION TRAJECTORY]")

    user_content = Content(
        role="user",
        parts=[Part.from_text(text=prompt_text)],
    )

    turn_count = 0
    final_response_text = ""

    async for event in runner.run_async(
        user_id="dandye",
        session_id=session_id,
        new_message=user_content,
    ):
        turn_count += 1
        # Inspect event content
        if hasattr(event, "content") and event.content:
            for part in event.content.parts:
                if getattr(part, "text", None):
                    final_response_text += part.text
                if getattr(part, "executable_code", None):
                    print("\n>>> [GENERATED SANDBOX PYTHON CODE]:")
                    print(part.executable_code.code)
                if getattr(part, "code_execution_result", None):
                    print("\n<<< [SANDBOX EXECUTION OUTPUT]:")
                    print(f"Outcome: {part.code_execution_result.outcome}")
                    print(f"Output:\n{part.code_execution_result.output}")

    print("\n" + "=" * 80)
    print("FINAL AGENT SYNTHESIZED RESPONSE:")
    print("=" * 80)
    print(final_response_text.strip())
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_live_code_execution_session())
