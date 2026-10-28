# ============================================================================
# [GitHub File 4/5]: examples/app_integration_examples.py
# Purpose: 1) 2-line decorator pattern & 2) Explicit exception handling for APIs
# Dependencies: pip install google-genai google-auth requests
# ============================================================================
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from google import genai
from model_armor_interceptor import (
    ModelArmorClient,
    ModelArmorBlockedException,
    protect_with_model_armor,
)

ai_client = genai.Client()
armor = ModelArmorClient(location="europe-west1", template_id="agent-security-policy")


# ----------------------------------------------------------------------------
# Pattern 1: Zero-Refactoring Decorator (Add 1 line above your existing function)
# ----------------------------------------------------------------------------
@protect_with_model_armor(client=armor)
def ask_assistant(user_prompt: str) -> str:
    response = ai_client.models.generate_content(
        model="gemini-2.5-flash",
        contents=user_prompt,
    )
    return response.text


# ----------------------------------------------------------------------------
# Pattern 2: Explicit Agent / API Handler with Graceful UX Error Responses
# ----------------------------------------------------------------------------
def handle_chat_request(user_input: str) -> dict:
    try:
        # Step 1: Sanitize incoming user prompt (blocks PIJB, masks PII)
        safe_prompt = armor.sanitize_prompt(user_input)

        # Step 2: Call your LLM or Agent with the sanitized prompt
        llm_resp = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=safe_prompt,
        )

        # Step 3: Sanitize outgoing model response before returning to caller
        safe_output = armor.sanitize_response(llm_resp.text)
        return {"status": "ok", "reply": safe_output, "blocked": False}

    except ModelArmorBlockedException as e:
        # Map specific guardrail triggers to friendly, non-technical user messages
        if "PROMPT_INJECTION_JAILBREAK" in e.triggered_filters:
            user_message = "We detected an unsupported instruction override. Please rephrase your question."
        elif "SENSITIVE_DATA_EXPOSURE" in e.triggered_filters:
            user_message = "Please do not include sensitive personal or financial data (such as credit cards or keys) in your message."
        else:
            user_message = "This message could not be processed due to our AI safety policy."

        return {
            "status": "blocked",
            "stage": e.stage,
            "triggered_filters": e.triggered_filters,
            "reply": user_message,
            "blocked": True,
        }
