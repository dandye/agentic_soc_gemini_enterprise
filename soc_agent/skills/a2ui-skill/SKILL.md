# A2UI Rich Interface Skill

This skill enables the agent to provide rich, interactive UI components using the A2UI (Agent-to-User Interface) framework.

## Instructions

When asked to present information in a rich or visual format (such as cards, tables, rows, or interactive forms), you MUST follow the instructions in the referenced `a2ui_instructions.md`.

Key requirements:
1. Divide your response into conversational text and A2UI JSON, separated by `---a2ui_JSON---`.
2. Ensure the JSON validates against the schema provided in the instructions.
3. Include at least one `surfaceUpdate` and one `beginRendering` message in the JSON array.

## References

- [A2UI Instructions](references/a2ui_instructions.md)
