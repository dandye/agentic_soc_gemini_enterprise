#!/usr/bin/env python3
"""
Automated evaluation runner for the Secure Operations Agent's Elasticsearch and Neo4j integrations.
This script queries the deployed agent reasoning engine, collects the tool calls and responses,
and uses Gemini as an LLM judge to evaluate them against structured rubrics.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import vertexai
from dotenv import load_dotenv
from google import genai
from vertexai import agent_engines


# Load environment configuration
env_path = Path(".env")
if env_path.exists():
    load_dotenv(env_path, override=True)

# Configuration settings
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
GCP_LOCATION = os.environ.get("GCP_LOCATION", "us-east4")
AGENT_ENGINE_RESOURCE_NAME = os.environ.get("AGENT_ENGINE_RESOURCE_NAME")
TIER2_AGENT_RESOURCE_NAME = os.environ.get("TIER2_AGENT_RESOURCE_NAME")

if not GCP_PROJECT_ID or not AGENT_ENGINE_RESOURCE_NAME:
    print(
        "Error: GCP_PROJECT_ID and AGENT_ENGINE_RESOURCE_NAME must be set in your .env file."
    )
    sys.exit(1)

# Initialize clients
vertexai.init(project=GCP_PROJECT_ID, location=GCP_LOCATION)
genai_client = genai.Client(
    vertexai=True, project=GCP_PROJECT_ID, location=GCP_LOCATION
)

# Define test cases
TEST_CASES = [
    {
        "id": "TC-1",
        "name": "Neo4j Wildcard Entity Lookup & Activity Enrichment",
        "agent_module": "agent_soc_manager",
        "resource_env_var": "AGENT_ENGINE_RESOURCE_NAME",
        "prompt": "What else do we know about frank.kolzig?",
        "expected_tool": "query_neo4j_graph",
        "rubric": """
        Evaluate whether the agent correctly retrieved information from the Neo4j knowledge graph and structured the findings.

        REQUIRED FACTS TO CHECK IN FINAL RESPONSE:
        1. The user 'frank.kolzig' logged on to the host 'wrk-shasek' (or 'wrk-shasek.stackedpads.local').
        2. The user 'frank.kolzig' logged on to the domain controller 'activedir.stackedpads.local' (IP 10.1.0.50).
        3. The account executed credential harvesting tools, specifically 'mimikatz', 'm64.exe', or 'sekurlsa::logonpasswords'.
        4. The account executed shadow copy manipulation commands (e.g., 'vssadmin create shadow' or 'diskshadow.exe') to dump Active Directory database files.

        GRADING RUBRIC:
        - SCORE 5: All 4 facts are present, clearly structured, and the agent identifies this as an active AD credential compromise.
        - SCORE 3: At least 2 facts are present. The link to Mimikatz or the domain controller is mentioned but lateral movement path is unclear.
        - SCORE 1: No facts are present, or the database query failed and the model did not handle the failure gracefully.

        Provide your evaluation in JSON format with keys: 'score' (int 1-5), 'reason' (string), and 'facts_found' (list of strings).
        """,
    },
    {
        "id": "TC-2",
        "name": "Neo4j Lateral Movement Path Analysis",
        "agent_module": "agent_soc_manager",
        "resource_env_var": "AGENT_ENGINE_RESOURCE_NAME",
        "prompt": "Verify if there is any attack path or log correlation connecting WRK-SHASEK to our Domain Controller activedir.stackedpads.local.",
        "expected_tool": "query_neo4j_graph",
        "rubric": """
        Evaluate whether the agent successfully ran a path relationship search in Neo4j and explained the lateral movement flow.

        REQUIRED FACTS TO CHECK IN FINAL RESPONSE:
        1. The workstation 'wrk-shasek' is connected to the domain controller 'activedir' via the user account 'frank.kolzig' (or 'tim.smith').
        2. The path involves multiple failed logons followed by a successful network logon (NTLM).
        3. Credential harvesting (Mimikatz) took place on the source workstation before the successful domain logon.

        GRADING RUBRIC:
        - SCORE 5: Accurately maps the lateral movement path from WRK-SHASEK to the Domain Controller and highlights credential theft as the pivot.
        - SCORE 3: Mentions that both hosts are linked by the same user logins but fails to explain the sequence/direction of lateral movement.
        - SCORE 1: Fails to discover the link or queries unrelated nodes.

        Provide your evaluation in JSON format with keys: 'score' (int 1-5), 'reason' (string), and 'facts_found' (list of strings).
        """,
    },
    {
        "id": "TC-3",
        "name": "Elasticsearch Runbooks Grounding",
        "agent_module": "agent_soc_manager",
        "resource_env_var": "AGENT_ENGINE_RESOURCE_NAME",
        "prompt": "What is our standard procedure for handling a Mimikatz credential dumping alert on a domain workstation?",
        "expected_tool": "retrieve_elasticsearch_runbooks",
        "rubric": """
        Evaluate whether the agent successfully queried the Elasticsearch grounding database and cited source markdown documents.

        GRADING RUBRIC:
        - SCORE 5: Citations are present (contains relative paths like 'harvested_investigations/1b6bf948-0e8c-4977-9f3f-f8b085a76d2a.md' or similar document filenames) AND lists the triage steps accurately.
        - SCORE 3: Standard triage steps are summarized but source citations/filepaths are missing.
        - SCORE 1: Returns generic advice or fails to find matching runbooks.

        Provide your evaluation in JSON format with keys: 'score' (int 1-5), 'reason' (string), and 'facts_found' (list of strings).
        """,
    },
    {
        "id": "TC-4",
        "name": "Tier 2 Grounding & Graph Capabilities",
        "agent_module": "agent_a2a_tier2",
        "resource_env_var": "TIER2_AGENT_RESOURCE_NAME",
        "prompt": "Check if frank.kolzig is known in our graph database, and list any incident response runbooks associated with credential dumping.",
        "expected_tool": "query_neo4j_graph",
        "rubric": """
        Evaluate whether the Tier 2 Incident Responder can use both query_neo4j_graph and retrieve_elasticsearch_runbooks.

        GRADING RUBRIC:
        - SCORE 5: Successfully invokes query_neo4j_graph for frank.kolzig and lists credential dumping runbook metadata from Elasticsearch.
        - SCORE 3: Successfully queries one database (either Neo4j or Elasticsearch) but fails to query or locate data in the other.
        - SCORE 1: Fails to execute both tools or throws unexpected ToolNotFound errors.

        Provide your evaluation in JSON format with keys: 'score' (int 1-5), 'reason' (string), and 'facts_found' (list of strings).
        """,
    },
]


async def query_reasoning_engine(resource_name: str, message: str):
    """Query reasoning engine, collecting streaming events to capture tool calls and output."""
    remote_app = agent_engines.get(resource_name)
    user_id = "eval_user"
    session = await remote_app.async_create_session(user_id=user_id)
    session_id = session.get("id")

    text_accumulated = []
    tool_calls = []

    async for event in remote_app.async_stream_query(
        user_id=user_id, session_id=session_id, message=message
    ):
        content = event.get("content", {})
        parts = content.get("parts", [])
        for part in parts:
            if "text" in part:
                text_accumulated.append(part["text"])
            if "function_call" in part:
                tool_calls.append(part["function_call"])

    return "".join(text_accumulated), tool_calls


def run_judge(prompt: str, agent_response: str, tool_calls: list, rubric: str):
    """Invoke Gemini to evaluate agent output against the rubric."""
    judge_prompt = f"""
    You are an AI Evaluator / Judge assessing the performance of a Security Operations Assistant agent.

    USER PROMPT:
    {prompt}

    AGENT RESPONSE:
    {agent_response}

    TOOL CALLS MADE BY AGENT:
    {json.dumps(tool_calls, indent=2)}

    RUBRIC & EVALUATION CRITERIA:
    {rubric}

    Return ONLY a raw JSON block containing 'score', 'reason', and 'facts_found'. Do not wrap in markdown code blocks.
    """
    try:
        response = genai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=judge_prompt,
            config={"response_mime_type": "application/json"},
        )
        return json.loads(response.text.strip())
    except Exception as e:
        return {"score": 1, "reason": f"Judge failure: {str(e)}", "facts_found": []}


async def main():
    print(
        "================================================================================"
    )
    print("STARTING KNOWLEDGE GRAPH & GROUNDING INTEGRATION EVALUATION SUITE")
    print(
        "================================================================================"
    )

    results = []

    for case in TEST_CASES:
        print(f"\nRunning {case['id']}: {case['name']}...")

        # Resolve resource name
        res_env_var = case["resource_env_var"]
        resource = os.environ.get(res_env_var)
        if not resource:
            print(f"Skipping {case['id']} - {res_env_var} not found in environment.")
            continue

        print(f"Querying reasoning engine: {resource}...")
        try:
            response_text, tool_calls = await query_reasoning_engine(
                resource, case["prompt"]
            )

            tool_names = [tc.get("name") for tc in tool_calls]
            print(f"Agent finished. Tool calls made: {tool_names}")

            print("Evaluating response using LLM judge...")
            evaluation = run_judge(
                prompt=case["prompt"],
                agent_response=response_text,
                tool_calls=tool_calls,
                rubric=case["rubric"],
            )

            print(f"Score: {evaluation.get('score')}/5")
            print(f"Reason: {evaluation.get('reason')}")

            results.append(
                {
                    "id": case["id"],
                    "name": case["name"],
                    "prompt": case["prompt"],
                    "tool_calls": tool_names,
                    "response": response_text,
                    "score": evaluation.get("score"),
                    "reason": evaluation.get("reason"),
                    "facts_found": evaluation.get("facts_found", []),
                }
            )
        except Exception as e:
            print(f"Failed to run case {case['id']}: {str(e)}")
            results.append(
                {
                    "id": case["id"],
                    "name": case["name"],
                    "prompt": case["prompt"],
                    "tool_calls": [],
                    "response": "",
                    "score": 1,
                    "reason": f"Execution error: {str(e)}",
                    "facts_found": [],
                }
            )

    # Generate Report Artifact
    report_path = Path(
        "/Users/dandye/.gemini/jetski/brain/fe077ded-a6c1-44a6-b58f-c1d13a382454/knowledge_graph_eval_report.md"
    )

    report_content = []
    report_content.append("# INTEGRATION EVALUATION REPORT: ELASTICSEARCH & NEO4J")
    report_content.append(f"\n*Run Zone:* {GCP_LOCATION}  ")
    report_content.append(f"*Project:* {GCP_PROJECT_ID}  \n")
    report_content.append("| ID | Test Case | Score | Tool Calls Made | Status |")
    report_content.append("|---|---|---|---|---|")

    for r in results:
        status = "✅ PASS" if r["score"] >= 3 else "❌ FAIL"
        report_content.append(
            f"| {r['id']} | {r['name']} | **{r['score']}/5** | `{', '.join(r['tool_calls'])}` | {status} |"
        )

    report_content.append("\n## DETAILED RESULTS\n")
    for r in results:
        report_content.append(f"### {r['id']}: {r['name']}")
        report_content.append(f"**Prompt:** `{r['prompt']}`  ")
        report_content.append(f"**Score:** `{r['score']}/5`  ")
        report_content.append(f"**Reasoning:** {r['reason']}  ")
        report_content.append("**Facts Found:**")
        for f in r["facts_found"]:
            report_content.append(f"- {f}")
        report_content.append("\n**Final Response Content:**")
        report_content.append(f"```text\n{r['response']}\n```")
        report_content.append("\n---\n")

    report_path.write_text("\n".join(report_content))
    print(f"\nEvaluation complete. Report generated at: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
