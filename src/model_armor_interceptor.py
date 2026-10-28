# ============================================================================
# [GitHub File 3/5]: src/model_armor_interceptor.py
# Purpose: Reusable, zero-refactoring Google Cloud Model Armor client & decorator
# Dependencies: pip install google-auth requests
# ============================================================================
import os
import json
import logging
from typing import Optional, Dict, Any, Callable, List
from functools import wraps
import google.auth
import google.auth.transport.requests

logger = logging.getLogger("model_armor")
logger.setLevel(logging.INFO)


class ModelArmorBlockedException(Exception):
    """Raised when Model Armor blocks a user prompt or model response."""

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
    ):
        self.credentials, default_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        self.project_id = (
            project_id or default_project or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )
        if not self.project_id:
            raise ValueError("GOOGLE_CLOUD_PROJECT must be set or passed as project_id.")

        self.location = location
        self.template_id = template_id
        self.fail_closed = fail_closed
        self.block_on_sdp_match = block_on_sdp_match
        self.timeout = timeout
        self.request_adapter = google.auth.transport.requests.Request()

        # Strictly regional Model Armor v1 endpoint
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
        """Inspects & sanitizes an incoming user prompt before calling the LLM."""
        endpoint = f"{self.base_url}:sanitizeUserPrompt"
        payload = {"userPromptData": {"text": user_text}}
        return self._execute_sanitization(endpoint, payload, user_text, stage="prompt")

    def sanitize_response(self, model_text: str) -> str:
        """Inspects & sanitizes an outgoing LLM response before returning to the user."""
        endpoint = f"{self.base_url}:sanitizeModelResponse"
        payload = {"modelResponseData": {"text": model_text}}
        return self._execute_sanitization(endpoint, payload, model_text, stage="response")

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
                raise RuntimeError(f"Model Armor API HTTP {http_status}: {raw_body}")

            data = json.loads(raw_body)
            result = data.get("sanitizationResult", {})
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
            logger.error(f"Model Armor check failed on {stage}: {str(e)}")
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
    """2-line decorator that sanitizes both the incoming prompt and outgoing LLM response."""
    armor = client or ModelArmorClient()

    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(prompt: str, *args, **kwargs):
            try:
                safe_prompt = armor.sanitize_prompt(prompt)
            except ModelArmorBlockedException as e:
                logger.warning(f"Prompt blocked [{e.triggered_filters}]: {e.verdict_reason}")
                return blocked_fallback_msg

            model_response = fn(safe_prompt, *args, **kwargs)

            try:
                return armor.sanitize_response(str(model_response))
            except ModelArmorBlockedException as e:
                logger.warning(f"Response blocked [{e.triggered_filters}]: {e.verdict_reason}")
                return blocked_fallback_msg

        return wrapper

    return decorator
