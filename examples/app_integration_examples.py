# ============================================================================
# examples/app_integration_examples.py
# Purpose: 1) Low-level genai.Client SDK boundary interceptor (RAG, multi-turn, multimodal)
#          2) Google ADK (Agent Development Kit) callbacks (tool & model boundary)
#          3) 2-line function decorator & explicit UX exception handler
# Dependencies: pip install google-genai google-auth requests
# ============================================================================
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from google import genai
from google.genai import types
from model_armor_interceptor import (
    ModelArmorClient,
    ModelArmorBlockedException,
    protect_with_model_armor,
)

armor = ModelArmorClient(location="europe-west1", template_id="agent-security-policy")

# ----------------------------------------------------------------------------
# Pattern 1 (Recommended for Production RAG, Multi-Turn & Multimodal Apps):
# Intercept at the low-level genai.Client.models.generate_content boundary!
# This guarantees that conversation history, system instructions, retrieved
# RAG documents, tool outputs, and binary PDF/IMAGE attachments are ALL
# scanned together right before the payload leaves your process.
# ----------------------------------------------------------------------------
ai_client = armor.wrap_genai_client(genai.Client())


def answer_with_rag_and_attachment(
    user_query: str,
    chat_history: list,
    retrieved_rag_docs: list[str],
    pdf_bytes: bytes | None = None,
) -> str:
    contents = list(chat_history)
    rag_context = "\n".join(retrieved_rag_docs)
    parts: list = [{"text": f"Context:\n{rag_context}\n\nUser Question: {user_query}"}]

    if pdf_bytes:
        # Automatically scanned via Model Armor byteItem (ByteDataType="PDF")
        parts.append({"inline_data": {"data": pdf_bytes, "mime_type": "application/pdf"}})

    contents.append({"role": "user", "parts": parts})

    # guarded_generate_content inspects the full assembled contents + system_instruction
    response = ai_client.models.generate_content(
        model="gemini-2.5-flash",
        contents=contents,
        config=types.GenerateContentConfig(
            system_instruction="You are a helpful cloud security assistant."
        ),
    )
    return response.text


# ----------------------------------------------------------------------------
# Pattern 2: Google ADK (Agent Development Kit) Callbacks
# Scans assembled LLM requests, untrusted tool outputs, and model responses
# ----------------------------------------------------------------------------
adk_callbacks = armor.create_adk_callbacks()
# Example usage with google.adk.agents.LlmAgent:
# agent = LlmAgent(
#     name="secure_cloud_agent",
#     model="gemini-2.5-flash",
#     tools=[search_knowledge_base],
#     before_model_callback=adk_callbacks["before_model_callback"],
#     after_tool_callback=adk_callbacks["after_tool_callback"],
#     after_model_callback=adk_callbacks["after_model_callback"],
# )


# ----------------------------------------------------------------------------
# Pattern 3: Zero-Refactoring Decorator (Add 1 line above simple functions)
# ----------------------------------------------------------------------------
@protect_with_model_armor(client=armor)
def ask_assistant(user_prompt: str) -> str:
    raw_client = genai.Client()
    response = raw_client.models.generate_content(
        model="gemini-2.5-flash",
        contents=user_prompt,
    )
    return response.text


# ----------------------------------------------------------------------------
# Pattern 4: Explicit API Handler with Graceful UX Error Responses
# ----------------------------------------------------------------------------
def handle_chat_request(user_input: str, chat_history: list | None = None) -> dict:
    try:
        # Step 1: Sanitize full multi-turn contents or multimodal attachment
        payload = (chat_history or []) + [{"role": "user", "parts": [{"text": user_input}]}]
        safe_contents, combined_prompt = armor.sanitize_contents(payload)

        # Step 2: Call your LLM (if using unwrapped client)
        raw_client = genai.Client()
        llm_resp = raw_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=safe_contents,
        )

        # Step 3: Sanitize outgoing model response with prompt context
        safe_output = armor.sanitize_response(llm_resp.text, user_prompt=combined_prompt)
        return {"status": "ok", "reply": safe_output, "blocked": False}

    except ModelArmorBlockedException as e:
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
