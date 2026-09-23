"""Generate ADK EvalSet and EvalConfig files for the SOC Knowledge Agent."""

import json
from pathlib import Path

from google.adk.evaluation.eval_case import (
    EvalCase,
    IntermediateData,
    Invocation,
)
from google.adk.evaluation.eval_set import EvalSet
from google.genai import types

eval_dir = Path(__file__).resolve().parent
repo_root = eval_dir.parent.parent
evalsets_dir = repo_root / "evalsets"
evalsets_dir.mkdir(parents=True, exist_ok=True)

# Case 1: Graph traversal query (query_knowledge_graph for lateral movement)
case_1 = EvalCase(
    eval_id="case_01_lateral_movement_graph",
    conversation=[
        Invocation(
            invocation_id="turn_1",
            user_content=types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text="Investigate potential lateral movement originating from compromised host 'workstation-corp-12'. Check its network neighbors and process ancestry in the graph."
                    )
                ],
            ),
            intermediate_data=IntermediateData(
                tool_uses=[
                    types.FunctionCall(
                        name="query_knowledge_graph",
                        args={
                            "query_type": "entity_neighborhood",
                            "entity_value": "workstation-corp-12",
                        },
                    )
                ]
            ),
            final_response=types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text="Executive Summary: Graph topology investigation for host 'workstation-corp-12' identified active connections to adjacent hosts 'server-app-04' and 'dc-primary'. Process ancestry analysis reveals PowerShell execution spawned from an abnormal parent process, indicating active lateral movement pathways."
                    )
                ],
            ),
        )
    ],
)

# Case 2: Asset catalog lookup (query_asset_catalog for asset tier/OS)
case_2 = EvalCase(
    eval_id="case_02_asset_criticality_lookup",
    conversation=[
        Invocation(
            invocation_id="turn_1",
            user_content=types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text="Look up the asset classification, business tier, owner, and operating system for database host 'db-prod-finance-01' in the enterprise asset catalog."
                    )
                ],
            ),
            intermediate_data=IntermediateData(
                tool_uses=[
                    types.FunctionCall(
                        name="query_asset_catalog",
                        args={
                            "query": "db-prod-finance-01",
                            "search_mode": "exact_asset",
                        },
                    )
                ]
            ),
            final_response=types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text="Executive Summary: Asset catalog records indicate 'db-prod-finance-01' is classified as Tier 0 (Mission Critical) running Linux enterprise server OS. The system is owned by the Finance Engineering team and requires highest priority response protocol."
                    )
                ],
            ),
        )
    ],
)

# Case 3: Memory query (query_investigation_memory for past hypotheses)
case_3 = EvalCase(
    eval_id="case_03_investigation_memory_context",
    conversation=[
        Invocation(
            invocation_id="turn_1",
            user_content=types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text="Check our investigation memory notes for any past findings, active analyst hypotheses, or containment tags regarding entity 'jdoe-admin'."
                    )
                ],
            ),
            intermediate_data=IntermediateData(
                tool_uses=[
                    types.FunctionCall(
                        name="query_investigation_memory",
                        args={
                            "entity": "jdoe-admin",
                        },
                    )
                ]
            ),
            final_response=types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text="Executive Summary: Investigation memory retrieval for 'jdoe-admin' identified active analyst hypotheses regarding suspicious privileged credential usage and prior containment review tags. Correlation with historical notes suggests potential account compromise under investigation."
                    )
                ],
            ),
        )
    ],
)

# Case 4: Composite / RAG query (asset catalog lookup + RAG runbook lookup)
case_4 = EvalCase(
    eval_id="case_04_composite_rag_and_asset_investigation",
    conversation=[
        Invocation(
            invocation_id="turn_1",
            user_content=types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text="We detected suspicious process execution on host 'srv-payments-02' matching Mimikatz credential dumping. Query the asset catalog for host criticality and consult our RAG Incident Response Playbook for credential access containment steps."
                    )
                ],
            ),
            intermediate_data=IntermediateData(
                tool_uses=[
                    types.FunctionCall(
                        name="query_asset_catalog",
                        args={
                            "query": "srv-payments-02",
                            "search_mode": "exact_asset",
                        },
                    )
                ]
            ),
            final_response=types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text="Executive Summary: Asset catalog verification confirms 'srv-payments-02' is a Tier 0 high-value payment processing asset. In accordance with the Credential Dumping Incident Response Playbook (IRP-04), immediate remediation requires credential revocation, Kerberos ticket invalidation, active session termination, and network isolation."
                    )
                ],
            ),
        )
    ],
)

eval_set = EvalSet(
    eval_set_id="soc_knowledge_evalset",
    name="SOC Knowledge Agent Evaluation Set",
    description="Benchmark evaluation set for multi-modal KnowledgeAgent covering graph traversal, asset catalog, investigation memory, and composite RAG.",
    eval_cases=[case_1, case_2, case_3, case_4],
)


def generate():
    # Write to evalsets/soc_knowledge_evalset.json
    target_evalset = evalsets_dir / "soc_knowledge_evalset.json"
    target_evalset.write_text(eval_set.model_dump_json(indent=2, by_alias=True))
    print(f"Saved EvalSet to: {target_evalset}")

    # Also write local copy to test_agents/soc_knowledge_agent/soc_knowledge_evalset.json
    local_evalset = eval_dir / "soc_knowledge_evalset.json"
    local_evalset.write_text(eval_set.model_dump_json(indent=2, by_alias=True))
    print(f"Saved local EvalSet to: {local_evalset}")


if __name__ == "__main__":
    generate()
