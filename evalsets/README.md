# SOC Agent Evaluation Sets

This directory contains evaluation sets (evalsets) for validating the Agentic SOC Gemini Enterprise Agent Platform agent quality.

## Evalset Files

| File | Description | # Cases |
|------|-------------|---------|
| `soc_basic.evalset.json` | Basic operations: runbook retrieval, SOAR queries, delegation | 5 |
| `cti_research.evalset.json` | Threat intelligence research workflows using GTI | 5 |
| `tier1_triage.evalset.json` | Alert triage, basic investigation, escalation | 5 |
| `multi_specialist.evalset.json` | Complex multi-specialist workflows | 5 |

**Total:** 20 evaluation cases

## Running Evaluations

### Run all evalsets:
```bash
make eval
```

### Run a specific evalset:
```bash
make eval-basic          # soc_basic.evalset.json
adk eval soc_agent evalsets/cti_research.evalset.json
```

### Run with custom agent module:
```bash
AGENT_MODULE=soc_agent_flash make eval
```

## Evaluation Criteria (from DESIGN_SPEC.md)

### Success Thresholds:
- **Delegation Accuracy:** ≥90% of queries routed to correct specialist
- **Tool Integration:** ≤5% tool error rate
- **Response Quality:** ≥85% rated "good" or "excellent"
- **Citation Preservation:** 100% of RAG responses include source attribution
- **Specialist Attribution:** 100% of delegated queries include explicit specialist attribution

### Key Constraints Tested:
1. **Never Hallucinate:** Agent must report actual errors, not fabricate data
2. **Transparency:** Explicit specialist attribution in all responses
3. **Empty Response Clarity:** Definitive statements, no hedging language
4. **Grounding Citations:** Preserve RAG source attribution
5. **Tool Transparency:** Name specific tools used (e.g., `list_cases()`, `get_ip_address_report()`)

## Evalset Schema

Each evalset follows this structure:

```json
{
  "evalset_id": "unique_id",
  "name": "Human-readable name",
  "description": "What this evalset tests",
  "eval_cases": [
    {
      "eval_id": "case_id",
      "name": "Case name",
      "conversation": [
        {"role": "user", "content": "User query"}
      ],
      "reference": {
        "expected_specialist": "cti_researcher|tier1_analyst|orchestrator_direct",
        "tool_trajectory": ["expected_tool_name"],
        "final_response_must_contain": ["keyword1", "keyword2"],
        "success_criteria": {
          "specialist_attribution": true,
          "tool_name_mentioned": true,
          "has_grounding_citation": true
        }
      }
    }
  ]
}
```

## Mapping to DESIGN_SPEC Use Cases

| Evalset | DESIGN_SPEC Use Case |
|---------|---------------------|
| `soc_basic.evalset.json` | Use Case 1: Runbook Retrieval |
| `cti_research.evalset.json` | Use Case 2: Threat Intelligence Research |
| `tier1_triage.evalset.json` | Use Case 3: Alert Triage and Investigation |
| `multi_specialist.evalset.json` | Use Cases 4-5: Multi-Specialist & Complex Hunting |

## Adding New Evalsets

1. Create a new `.evalset.json` file in this directory
2. Follow the schema structure above
3. Add success criteria based on DESIGN_SPEC.md constraints
4. Run evaluation to validate format: `adk eval soc_agent evalsets/your_new_evalset.json`

## Expected Metrics

After running evaluations, you should see:

```
Delegation Accuracy: 90%+ (17/20+ correct specialist routing)
Tool Integration: 95%+ success rate (19/20+ successful tool calls)
Response Quality: 85%+ "good" ratings (17/20+ cases)
```

## References

- **Evaluation Methodology:** `/adk-eval-guide` skill
- **Success Criteria:** `docs/DESIGN_SPEC.md` section "Success Criteria"
- **ADK Evaluation Docs:** https://google.github.io/adk-docs/evaluation/
