import logging
from pathlib import Path

from google import genai
from google.genai import types


logger = logging.getLogger(__name__)


def render_dashboard(
    data_to_render: str,
    requested_layout: str = "A comprehensive security dashboard with cards and tables",
) -> str:
    """
    Converts raw security data, lists, or alerts into a rich A2UI JSON dashboard.
    Use this whenever the user asks for a visual report, dashboard, or structured view.
    Returns raw text and JSON that MUST be passed directly to the user in your final response.

    Args:
        data_to_render: The raw JSON or text data to format into the dashboard.
        requested_layout: A description of how the dashboard should look (e.g. cards, tables, grid).
    """
    logger.info(f"render_dashboard: Rendering UI with layout: {requested_layout}")

    # Load the A2UI protocol instructions
    try:
        a2ui_instruction_path = "a2ui_prompt.md"
        instruction_file = Path(a2ui_instruction_path)
        if not instruction_file.exists():
            # Fallback to absolute path relative to project root if needed
            instruction_file = Path(__file__).parents[2] / a2ui_instruction_path

        with open(instruction_file) as f:
            system_instruction = f.read()
    except Exception as e:
        logger.error(f"render_dashboard: Failed to load instructions: {e}")
        system_instruction = "Generate A2UI JSON for the provided data."

    try:
        # Initialize client using environment defaults
        client = genai.Client()

        # Prepare the prompt
        prompt = f"Please render the following data into a beautiful and functional A2UI interface.\n\nLAYOUT REQUESTED: {requested_layout}\n\nDATA TO RENDER:\n{data_to_render}"

        # Use Gemini Flash for fast, efficient UI generation
        response = client.models.generate_content(
            model="gemini-3-flash-preview",  # Using latest preview flash
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.1,  # Keep it strictly aligned to schema
            ),
        )

        if not response or not response.text:
            return "Error: UI generation failed to produce a response."

        return response.text

    except Exception as e:
        logger.error(f"render_dashboard: Execution failed: {e}", exc_info=True)
        return f"Error rendering UI: {str(e)}"


# Register for export
__all__ = ["render_dashboard"]
