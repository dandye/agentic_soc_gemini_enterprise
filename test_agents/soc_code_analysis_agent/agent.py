"""
SOC Code Analysis Test Agent.
Demonstrates sandboxed code execution for security data science, log parsing, and math.
"""

from google.adk.agents import Agent
from installation_scripts.code_executor_factory import get_code_executor

SYSTEM_INSTRUCTION = """
You are an expert SOC Threat Analytics, Data Science & Code Execution Assistant.
You specialize in writing and running Python code in an isolated sandbox environment to:
1. Parse and aggregate high-volume security event logs (Chronicle UDM events, VPC flow logs, authentication telemetry).
2. Calculate Shannon entropy to detect DGA domains and covert DNS tunneling.
3. Compute inter-arrival time distributions, variance, and jitter to identify automated C2 beaconing.
4. Render timeline visualizations and summarize statistical distributions without inflating prompt context.

Always write clean, efficient Python code enclosed in ```python code blocks.
"""

root_agent = Agent(
    name="soc_code_analysis_agent",
    model="gemini-2.5-flash",
    instruction=SYSTEM_INSTRUCTION,
    code_executor=get_code_executor("auto"),
)
