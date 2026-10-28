# ============================================================================
# src/model_armor_interceptor.py
# Purpose: Google Cloud Model Armor client, genai.Client SDK interceptor,
#          ADK callbacks, multimodal (byteItem) scanner & 2-line decorator
# Dependencies: pip install google-auth requests
# ============================================================================
import os
import re
import copy
import json
import base64
import inspect
import logging
from typing import Optional, Dict, Any, Callable, List, Tuple, Union
from functools import wraps
import google.auth
import google.auth.transport.requests

logger = logging.getLogger("model_armor")
logger.setLevel(logging.INFO)

_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_LOCATION_RE = re.compile(r"^[a-z0-9-]+$")
_TEMPLATE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,63}$")

# Official Model Armor v1 ByteDataItem enum values + MIME-type mapping
_VALID_BYTE_DATA_TYPES = {
    "PLAINTEXT_UTF8",
    "PDF",
    "WORD_DOCUMENT",
    "EXCEL_DOCUMENT",
    "POWERPOINT_DOCUMENT",
    "TXT",
    "CSV",
    "IMAGE",
}

_MIME_TO_BYTE_TYPE = {
    "application/pdf": "PDF",
    "text/plain": "TXT",
    "text/csv": "CSV",
    "application/csv": "CSV",
    "image/png": "IMAGE",
    "image/jpeg": "IMAGE",
    "image/jpg": "IMAGE",
    "image/webp": "IMAGE",
    "image/gif": "IMAGE",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "WORD_DOCUMENT",
    "application/msword": "WORD_DOCUMENT",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "EXCEL_DOCUMENT",
    "application/vnd.ms-excel": "EXCEL_DOCUMENT",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "POWERPOINT_DOCUMENT",
    "application/vnd.ms-powerpoint": "POWERPOINT_DOCUMENT",
}


class ModelArmorBlockedException(Exception):
    """Raised when Model Armor blocks a user prompt, attachment, tool output, or model response."""

    def __init__(
        self,
        verdict_reason: str,
        triggered_filters: List[str],
        filter_results: Dict[str, Any],
        stage: str = "prompt",
    ):
        self.verdict_reason = verdict_reason
        self.triggered_filters = triggered_filters
        self.filter_results = filter_results
        self.stage = stage
        super().__init__(
            f"Model Armor blocked {stage} [{', '.join(triggered_filters) or 'POLICY'}]: {verdict_reason}"
        )


class ModelArmorClient:
    def __init__(
        self,
        project_id: Optional[str] = None,
        location: str = "europe-west1",
        template_id: str = "agent-security-policy",
        fail_closed: bool = True,
        block_on_sdp_match: bool = False,
        timeout: float = 5.0,
        max_text_chars: int = 500_000,
        max_byte_size: int = 20 * 1024 * 1024,
    ):
        self.credentials, default_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        self.project_id = (
            project_id or default_project or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )
        if not self.project_id or not _PROJECT_ID_RE.match(self.project_id):
            raise ValueError("A valid GOOGLE_CLOUD_PROJECT ID must be set or passed as project_id.")
        if not _LOCATION_RE.match(location):
            raise ValueError(f"Invalid Google Cloud location: {location!r}")
        if not _TEMPLATE_ID_RE.match(template_id):
            raise ValueError(f"Invalid Model Armor template_id: {template_id!r}")

        self.location = location
        self.template_id = template_id
        self.fail_closed = fail_closed
        self.block_on_sdp_match = block_on_sdp_match
        self.timeout = timeout
        self.max_text_chars = max_text_chars
        self.max_byte_size = max_byte_size
        self.request_adapter = google.auth.transport.requests.Request()

        # Strictly validated regional Model Armor v1 endpoint (prevents SSRF / path traversal)
        self.base_url = (
            f"https://modelarmor.{self.location}.rep.googleapis.com/v1/"
            f"projects/{self.project_id}/locations/{self.location}/templates/{self.template_id}"
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        if not self.credentials.valid:
            self.credentials.refresh(self.request_adapter)
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.credentials.token}",
        }

    def sanitize_prompt(self, user_text: str) -> str:
        """Inspects & sanitizes a plaintext prompt string before calling the LLM."""
        if not isinstance(user_text, str):
            raise TypeError(
                f"sanitize_prompt expects a str, got {type(user_text).__name__}. "
                "Use sanitize_bytes() for binary files or sanitize_contents() for multimodal/multi-turn payloads."
            )
        if len(user_text) > self.max_text_chars:
            raise ModelArmorBlockedException(
                verdict_reason=f"Prompt exceeds maximum length ({len(user_text)} > {self.max_text_chars} chars)",
                triggered_filters=["PAYLOAD_SIZE_LIMIT"],
                filter_results={},
                stage="prompt",
            )
        endpoint = f"{self.base_url}:sanitizeUserPrompt"
        payload = {"userPromptData": {"text": user_text}}
        return self._execute_sanitization(endpoint, payload, user_text, stage="prompt")

    def sanitize_bytes(
        self,
        data: Union[bytes, bytearray],
        byte_data_type: str = "PDF",
        stage: str = "prompt",
    ) -> None:
        """
        Inspects binary / multimodal attachments (PDF, DOCX, XLSX, PPTX, CSV, TXT, IMAGE)
        via Model Armor's ByteDataItem (byteItem) API so binary payloads cannot bypass text checks.
        Accepts either an official ByteDataType enum (e.g. 'PDF', 'IMAGE') or a MIME type ('application/pdf', 'image/png').
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"sanitize_bytes expects bytes, got {type(data).__name__}")
        if len(data) > self.max_byte_size:
            raise ModelArmorBlockedException(
                verdict_reason=f"Binary attachment exceeds maximum size ({len(data)} > {self.max_byte_size} bytes)",
                triggered_filters=["PAYLOAD_SIZE_LIMIT"],
                filter_results={},
                stage=stage,
            )

        normalized = byte_data_type.strip()
        resolved_type = _MIME_TO_BYTE_TYPE.get(normalized.lower(), normalized.upper())
        if resolved_type not in _VALID_BYTE_DATA_TYPES:
            if self.fail_closed:
                raise ModelArmorBlockedException(
                    verdict_reason=f"Unsupported multimodal byteDataType/MIME type (Fail-Closed): {byte_data_type!r}",
                    triggered_filters=["UNSUPPORTED_MULTIMODAL_TYPE"],
                    filter_results={},
                    stage=stage,
                )
            logger.warning(f"Skipping unsupported byteDataType in fail-open mode: {byte_data_type!r}")
            return

        b64_payload = base64.b64encode(bytes(data)).decode("ascii")
        data_key = "userPromptData" if stage != "response" else "modelResponseData"
        method_suffix = "sanitizeUserPrompt" if stage != "response" else "sanitizeModelResponse"
        endpoint = f"{self.base_url}:{method_suffix}"
        payload = {
            data_key: {
                "byteItem": {
                    "byteDataType": resolved_type,
                    "byteData": b64_payload,
                }
            }
        }
        self._execute_sanitization(endpoint, payload, "", stage=stage)

    def sanitize_response(self, model_text: str, user_prompt: Optional[str] = None) -> str:
        """
        Inspects & sanitizes an outgoing LLM response before returning to the caller.
        Optionally includes user_prompt so Model Armor evaluates the response in context.
        """
        if not isinstance(model_text, str):
            raise TypeError(f"sanitize_response expects a str, got {type(model_text).__name__}")
        endpoint = f"{self.base_url}:sanitizeModelResponse"
        payload: Dict[str, Any] = {"modelResponseData": {"text": model_text}}
        if user_prompt:
            payload["userPrompt"] = user_prompt[: self.max_text_chars]
        return self._execute_sanitization(endpoint, payload, model_text, stage="response")

    def sanitize_contents(
        self,
        contents: Any,
        system_instruction: Optional[Any] = None,
    ) -> Tuple[Any, str]:
        """
        Deeply inspects an assembled LLM payload (multi-turn conversation history,
        system instructions, retrieved RAG documents, tool outputs, and multimodal byte parts).
        1. Scans all binary/inline_data parts via sanitize_bytes() (prevents Multimodal Bypass).
        2. Scans the combined multi-turn transcript in a single context window (prevents
           Multi-Turn / Split-Payload Smuggling and RAG/Tool Indirect Prompt Injection).
        3. Applies any SDP PII redactions back onto text nodes.
        """
        cloned = copy.deepcopy(contents)
        text_segments: List[str] = []

        if system_instruction is not None:
            sys_texts: List[str] = []
            self._walk_and_inspect_parts(system_instruction, sys_texts, redact_in_place=False)
            if sys_texts:
                text_segments.append(f"[SYSTEM_INSTRUCTION]\n" + "\n".join(sys_texts))

        self._walk_and_inspect_parts(cloned, text_segments, redact_in_place=True)

        combined_transcript = "\n---\n".join(seg for seg in text_segments if seg.strip())
        if combined_transcript:
            # Scan the entire assembled multi-turn + RAG + tool transcript together
            self.sanitize_prompt(combined_transcript)

        return cloned, combined_transcript

    def _walk_and_inspect_parts(
        self, node: Any, text_collector: List[str], redact_in_place: bool = True
    ) -> Any:
        if node is None:
            return None

        if isinstance(node, str):
            sanitized = self.sanitize_prompt(node) if redact_in_place else node
            text_collector.append(sanitized)
            return sanitized

        if isinstance(node, (bytes, bytearray)):
            self.sanitize_bytes(node, byte_data_type="PDF", stage="prompt")
            return node

        if isinstance(node, list):
            for idx, item in enumerate(node):
                node[idx] = self._walk_and_inspect_parts(item, text_collector, redact_in_place)
            return node

        if isinstance(node, dict):
            # Reject uninspected external file_data URIs in fail-closed mode
            if "file_data" in node or "fileData" in node:
                if self.fail_closed:
                    raise ModelArmorBlockedException(
                        verdict_reason="Uninspected external file_data URI blocked (pass raw bytes/inline_data for Model Armor byteItem inspection).",
                        triggered_filters=["UNINSPECTED_EXTERNAL_FILE_URI"],
                        filter_results={},
                        stage="prompt",
                    )
            if "inline_data" in node or "inlineData" in node:
                inline = node.get("inline_data") or node.get("inlineData") or {}
                raw_data = inline.get("data", b"")
                mime_type = inline.get("mime_type") or inline.get("mimeType") or "application/octet-stream"
                if isinstance(raw_data, str):
                    raw_data = base64.b64decode(raw_data)
                self.sanitize_bytes(raw_data, byte_data_type=mime_type, stage="prompt")
            if "text" in node and isinstance(node["text"], str):
                if redact_in_place:
                    node["text"] = self.sanitize_prompt(node["text"])
                text_collector.append(node["text"])
            if "parts" in node and isinstance(node["parts"], list):
                node["parts"] = self._walk_and_inspect_parts(node["parts"], text_collector, redact_in_place)
            if "response" in node and isinstance(node["response"], (dict, str)):
                # Tool / FunctionResponse output inspection
                tool_str = json.dumps(node["response"]) if isinstance(node["response"], dict) else node["response"]
                self.sanitize_prompt(tool_str)
                text_collector.append(f"[TOOL_OUTPUT]\n{tool_str}")
            return node

        # Support google-genai / Gemini Enterprise Agent Platform (formerly Vertex AI) SDK Content & Part objects
        if hasattr(node, "file_data") and getattr(node, "file_data", None) is not None:
            if self.fail_closed:
                raise ModelArmorBlockedException(
                    verdict_reason="Uninspected external Part.file_data URI blocked (use Part.from_bytes for Model Armor byteItem inspection).",
                    triggered_filters=["UNINSPECTED_EXTERNAL_FILE_URI"],
                    filter_results={},
                    stage="prompt",
                )

        if hasattr(node, "inline_data") and getattr(node, "inline_data", None) is not None:
            blob = getattr(node, "inline_data")
            raw_data = getattr(blob, "data", b"")
            mime_type = getattr(blob, "mime_type", None) or "application/octet-stream"
            if isinstance(raw_data, str):
                raw_data = base64.b64decode(raw_data)
            self.sanitize_bytes(raw_data, byte_data_type=mime_type, stage="prompt")

        if hasattr(node, "function_response") and getattr(node, "function_response", None) is not None:
            fn_resp = getattr(node, "function_response")
            resp_payload = getattr(fn_resp, "response", fn_resp)
            tool_str = json.dumps(resp_payload, default=str)
            self.sanitize_prompt(tool_str)
            text_collector.append(f"[TOOL_OUTPUT]\n{tool_str}")

        if hasattr(node, "text") and isinstance(getattr(node, "text"), str) and getattr(node, "text"):
            current_text = getattr(node, "text")
            if redact_in_place:
                sanitized_text = self.sanitize_prompt(current_text)
                try:
                    setattr(node, "text", sanitized_text)
                except Exception:
                    pass
                text_collector.append(sanitized_text)
            else:
                text_collector.append(current_text)

        if hasattr(node, "parts") and isinstance(getattr(node, "parts"), list):
            self._walk_and_inspect_parts(getattr(node, "parts"), text_collector, redact_in_place)

        return node

    def wrap_genai_client(self, genai_client: Any) -> Any:
        """
        Wraps a google.genai.Client at the low-level models.generate_content and
        models.generate_content_stream boundary so the ENTIRE assembled payload
        (history, RAG context, system_instruction, tool outputs, and multimodal bytes)
        is inspected right before it leaves the process.
        """
        orig_generate = genai_client.models.generate_content
        orig_stream = getattr(genai_client.models, "generate_content_stream", None)
        armor = self

        @wraps(orig_generate)
        def guarded_generate_content(*args, **kwargs):
            sig = inspect.signature(orig_generate)
            bound = sig.bind_partial(*args, **kwargs)
            contents = bound.arguments.get("contents")
            config = bound.arguments.get("config")

            sys_inst = None
            if isinstance(config, dict):
                sys_inst = config.get("system_instruction")
            elif config is not None and hasattr(config, "system_instruction"):
                sys_inst = getattr(config, "system_instruction")

            sanitized_contents, combined_prompt = armor.sanitize_contents(
                contents, system_instruction=sys_inst
            )
            bound.arguments["contents"] = sanitized_contents

            response = orig_generate(*bound.args, **bound.kwargs)
            resp_text = getattr(response, "text", None)
            if isinstance(resp_text, str) and resp_text:
                safe_text = armor.sanitize_response(resp_text, user_prompt=combined_prompt)
                try:
                    if safe_text != resp_text and hasattr(response, "candidates"):
                        response.candidates[0].content.parts[0].text = safe_text
                except Exception:
                    pass
            return response

        genai_client.models.generate_content = guarded_generate_content

        if callable(orig_stream):
            @wraps(orig_stream)
            def guarded_generate_content_stream(*args, **kwargs):
                sig = inspect.signature(orig_stream)
                bound = sig.bind_partial(*args, **kwargs)
                contents = bound.arguments.get("contents")
                config = bound.arguments.get("config")

                sys_inst = None
                if isinstance(config, dict):
                    sys_inst = config.get("system_instruction")
                elif config is not None and hasattr(config, "system_instruction"):
                    sys_inst = getattr(config, "system_instruction")

                sanitized_contents, combined_prompt = armor.sanitize_contents(
                    contents, system_instruction=sys_inst
                )
                bound.arguments["contents"] = sanitized_contents

                raw_stream = orig_stream(*bound.args, **bound.kwargs)
                buffered_chunks = list(raw_stream)
                assembled_text = "".join(
                    getattr(chunk, "text", "") or "" for chunk in buffered_chunks
                )
                if assembled_text:
                    armor.sanitize_response(assembled_text, user_prompt=combined_prompt)
                for chunk in buffered_chunks:
                    yield chunk

            genai_client.models.generate_content_stream = guarded_generate_content_stream

        return genai_client

    def create_adk_callbacks(self) -> Dict[str, Callable]:
        """
        Returns ready-to-use Google ADK (Agent Development Kit) callbacks:
        before_model_callback, after_tool_callback, and after_model_callback.
        """
        armor = self

        def before_model_callback(callback_context: Any, llm_request: Any) -> Optional[Any]:
            sys_inst = getattr(getattr(llm_request, "config", None), "system_instruction", None)
            sanitized_contents, _ = armor.sanitize_contents(
                getattr(llm_request, "contents", []),
                system_instruction=sys_inst,
            )
            llm_request.contents = sanitized_contents
            return None

        def after_tool_callback(
            tool: Any, args: Dict[str, Any], tool_context: Any, tool_response: Any
        ) -> Optional[Any]:
            serialized = (
                tool_response
                if isinstance(tool_response, str)
                else json.dumps(tool_response, default=str)
            )
            armor.sanitize_prompt(serialized)
            return None

        def after_model_callback(callback_context: Any, llm_response: Any) -> Optional[Any]:
            parts = getattr(getattr(llm_response, "content", None), "parts", []) or []
            for part in parts:
                if hasattr(part, "text") and isinstance(part.text, str) and part.text:
                    part.text = armor.sanitize_response(part.text)
            return None

        return {
            "before_model_callback": before_model_callback,
            "after_tool_callback": after_tool_callback,
            "after_model_callback": after_model_callback,
        }

    def _execute_sanitization(
        self, endpoint: str, payload: Dict[str, Any], original_text: str, stage: str
    ) -> str:
        headers = self._get_auth_headers()
        try:
            resp = self.request_adapter(
                method="POST",
                url=endpoint,
                headers=headers,
                body=json.dumps(payload).encode("utf-8"),
                timeout=self.timeout,
            )
            http_status = getattr(resp, "status", getattr(resp, "status_code", 500))
            raw_body = resp.data.decode("utf-8") if resp.data else "{}"

            if http_status != 200:
                raise RuntimeError(f"Model Armor API HTTP {http_status}")

            data = json.loads(raw_body)
            result = data.get("sanitizationResult", {})
            invocation_result = result.get("invocationResult", "SUCCESS")
            if self.fail_closed and invocation_result in ("FAILURE", "PARTIAL"):
                raise RuntimeError(
                    f"Model Armor filter execution incomplete (invocationResult={invocation_result})"
                )

            filter_results = result.get("filterResults", {})
            match_state = result.get("filterMatchState", "NO_MATCH_FOUND")
            verdict = result.get("sanitizationVerdict", "")

            # 1. Extract any SDP de-identified / redacted text if available
            sdp_entry = filter_results.get("sdp", {})
            sdp_result = sdp_entry.get("sdpFilterResult", sdp_entry.get("data", {}))
            deid_result = sdp_result.get("deidentifyResult", {})
            redacted_text = (
                deid_result.get("data", {}).get("text")
                or deid_result.get("redactedText")
            )

            # 2. Identify which blocking filters matched (PIJB, RAI, Malicious URI, CSAM, SDP Inspect)
            triggered: List[str] = []
            pijb = filter_results.get("pi_and_jailbreak", filter_results.get("piAndJailbreak", {}))
            if pijb.get("piAndJailbreakFilterResult", pijb).get("matchState") == "MATCH_FOUND":
                triggered.append("PROMPT_INJECTION_JAILBREAK")

            rai = filter_results.get("rai", {})
            if rai.get("raiFilterResult", rai).get("matchState") == "MATCH_FOUND":
                triggered.append("RESPONSIBLE_AI_SAFETY")

            uris = filter_results.get("malicious_uris", filter_results.get("maliciousUris", {}))
            if uris.get("maliciousUriFilterResult", uris).get("matchState") == "MATCH_FOUND":
                triggered.append("MALICIOUS_URI")

            csam = filter_results.get("csam", {})
            csam_inner = csam.get("csamFilterFilterResult", csam.get("csamFilterResult", csam))
            if csam_inner.get("matchState") == "MATCH_FOUND":
                triggered.append("CSAM_SAFETY")

            sdp_inspect_match = (
                sdp_result.get("inspectResult", {}).get("matchState") == "MATCH_FOUND"
            )
            if sdp_inspect_match and (self.block_on_sdp_match or not redacted_text):
                triggered.append("SENSITIVE_DATA_EXPOSURE")

            # 3. Raise ModelArmorBlockedException if any blocking filter matched
            if (
                triggered
                or verdict == "MODEL_ARMOR_SANITIZATION_VERDICT_BLOCK"
                or (match_state == "MATCH_FOUND" and not redacted_text)
            ):
                reason = result.get(
                    "sanitizationVerdictReason",
                    f"Matched security filters: {', '.join(triggered) or 'POLICY_MATCH'}",
                )
                logger.warning(f"Model Armor blocked {stage}: {reason}")
                raise ModelArmorBlockedException(
                    verdict_reason=reason,
                    triggered_filters=triggered or ["POLICY_MATCH"],
                    filter_results=filter_results,
                    stage=stage,
                )

            # 4. Otherwise return SDP-redacted text (if PII was masked) or original text
            return redacted_text if redacted_text else original_text

        except ModelArmorBlockedException:
            raise
        except Exception as e:
            logger.error(f"Model Armor check failed on {stage}: {type(e).__name__}: {str(e)}")
            if self.fail_closed:
                raise ModelArmorBlockedException(
                    verdict_reason=f"Security check unavailable (Fail-Closed): {str(e)}",
                    triggered_filters=["FAIL_CLOSED_ERROR"],
                    filter_results={},
                    stage=stage,
                )
            logger.warning("Fail-open enabled: allowing traffic despite inspection error.")
            return original_text


def protect_with_model_armor(
    client: Optional[ModelArmorClient] = None,
    blocked_fallback_msg: str = "Your request could not be completed because it triggered our AI safety guardrails.",
):
    """
    Decorator that sanitizes incoming inputs (single strings, multi-turn contents lists,
    or multimodal parts) and outgoing LLM responses.
    Note: For RAG or tool-calling agents where context is assembled inside the function,
    also wrap the low-level SDK client via armor.wrap_genai_client(ai_client).
    """
    armor = client or ModelArmorClient()

    def decorator(fn: Callable):
        sig = inspect.signature(fn)
        first_param = next(iter(sig.parameters), None)

        @wraps(fn)
        def wrapper(*args, **kwargs):
            bound = sig.bind_partial(*args, **kwargs)
            if not first_param or first_param not in bound.arguments:
                raise ValueError("Decorated function must receive a prompt or contents payload as its first parameter.")

            raw_input = bound.arguments[first_param]
            try:
                sanitized_input, prompt_context = armor.sanitize_contents(raw_input)
                bound.arguments[first_param] = sanitized_input
            except ModelArmorBlockedException as e:
                logger.warning(f"Prompt blocked [{e.triggered_filters}]: {e.verdict_reason}")
                return blocked_fallback_msg

            model_response = fn(*bound.args, **bound.kwargs)

            try:
                if isinstance(model_response, str):
                    return armor.sanitize_response(model_response, user_prompt=prompt_context)
                return model_response
            except ModelArmorBlockedException as e:
                logger.warning(f"Response blocked [{e.triggered_filters}]: {e.verdict_reason}")
                return blocked_fallback_msg

        return wrapper

    return decorator
