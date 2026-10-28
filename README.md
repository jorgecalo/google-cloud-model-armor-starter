# Google Cloud Model Armor — Python Developer Integration Starter 🛡️🤖

Companion repository for **[Protecting Your AI Apps from Prompt Injection & Data Leaks: A Developer's Guide to Model Armor](https://jorgeliauw.nl/posts/consume-google-cloud-model-armor-in-your-ai-application/)**.

This repository provides a hardened, drop-in Python client (`ModelArmorClient`), a low-level `genai.Client` SDK boundary interceptor (`armor.wrap_genai_client()`), Google ADK callbacks (`armor.create_adk_callbacks()`), multimodal binary/document inspection (`sanitize_bytes()` / `byteItem`), a 2-line decorator (`@protect_with_model_armor`), declarative Terraform infrastructure (`terraform/main.tf`), and an automated verification suite (`tests/test_model_armor.py`) for **Google Cloud Model Armor (`v1`)**.

---

## Repository Structure

| File | Description |
| :--- | :--- |
| `terraform/main.tf` | Enables `modelarmor.googleapis.com` APIs, binds `roles/modelarmor.user` IAM, and deploys the hardened `agent-security-policy` Model Armor template |
| `src/model_armor_interceptor.py` | Drop-in `ModelArmorClient`, `wrap_genai_client()` (`generate_content` / `generate_content_stream` boundary), `create_adk_callbacks()`, `sanitize_contents()` (multi-turn + RAG), `sanitize_bytes()` (`byteItem`), and `@protect_with_model_armor` |
| `examples/app_integration_examples.py` | Examples showing `wrap_genai_client()`, Google ADK callbacks, the 2-line decorator, and explicit `try / except` UX error handling |
| `tests/test_model_armor.py` | Automated verification suite for Benign, Prompt Injection, Credit Card PII, Malicious URLs, Multi-Turn Split Payloads, and Multimodal (`byteItem`) attachments |

---

## Quick Start

### 1. Install Dependencies & Authenticate
```bash
pip install -r requirements.txt
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
```

### 2. Provision APIs, IAM & Model Armor Template with Terraform
```bash
cd terraform
terraform init
terraform apply \
  -var="project_id=${GOOGLE_CLOUD_PROJECT}" \
  -var="app_service_account_email=your-app-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
cd ..
```

### 3. Run the Verification Suite
```bash
python tests/test_model_armor.py
```

Expected output:
```text
=== Running Google Cloud Model Armor Verification Suite ===

[PASS] Test 1 (Benign Prompt Allowed): What is the difference between Cloud Run and GKE?
[PASS] Test 2 (Prompt Injection Blocked): filters=['PROMPT_INJECTION_JAILBREAK'] | reason=Matched security filters: PROMPT_INJECTION_JAILBREAK
[PASS] Test 3 (PII Blocked by Policy): filters=['RESPONSIBLE_AI_SAFETY', 'SENSITIVE_DATA_EXPOSURE'] | reason=Matched security filters: RESPONSIBLE_AI_SAFETY, SENSITIVE_DATA_EXPOSURE
[PASS] Test 4 (Malicious URI Blocked): filters=['MALICIOUS_URI'] | reason=Matched security filters: MALICIOUS_URI
[PASS] Test 5 (Multi-Turn Split Payload Blocked): filters=['PROMPT_INJECTION_JAILBREAK']
[PASS] Test 6 (Multimodal byteItem Blocked): filters=['PROMPT_INJECTION_JAILBREAK', 'MALICIOUS_URI']
[PASS] Test 7a (Decorator Benign): Simulated LLM reply to: How does Binary Authorization work?
[PASS] Test 7b (Decorator Blocked): Your request could not be completed because it triggered our AI safety guardrails.
```
