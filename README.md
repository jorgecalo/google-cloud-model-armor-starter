# Google Cloud Model Armor — Python Developer Integration Starter 🛡️

Companion repository for **[Protecting Your AI Apps from Prompt Injection & Data Leaks: A Developer's Guide to Google Cloud Model Armor](https://jorgeliauw.nl/posts/consume-google-cloud-model-armor-in-your-ai-application/)**.

This repository provides a drop-in, model-agnostic Python client (`ModelArmorClient`), a 2-line decorator (`@protect_with_model_armor`), Terraform policy-as-code (`google_model_armor_template`), and an automated verification suite (`tests/test_model_armor.py`) for **Google Cloud Model Armor (`v1`)**.

---

## Repository Structure

| File | Description |
| :--- | :--- |
| `scripts/setup-gcp-model-armor.sh` | Enables `modelarmor.googleapis.com` and grants least-privilege `roles/modelarmor.user` |
| `terraform/main.tf` | Deploys the `agent-security-policy` Model Armor template (`europe-west1`) |
| `src/model_armor_interceptor.py` | Drop-in `ModelArmorClient`, `@protect_with_model_armor`, and `ModelArmorBlockedException` |
| `examples/app_integration_examples.py` | Examples showing the 2-line decorator and explicit `try / except` UX error handling |
| `tests/test_model_armor.py` | Automated smoke test suite for Benign, Prompt Injection, Credit Card PII, and Malicious URLs |

---

## Quick Start

### 1. Install Dependencies & Authenticate
```bash
pip install -r requirements.txt
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
```

### 2. Provision the Model Armor Template with Terraform
```bash
cd terraform
terraform init
terraform apply -var="project_id=${GOOGLE_CLOUD_PROJECT}"
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
[PASS] Test 5a (Decorator Benign): Simulated LLM reply to: How does Binary Authorization work?
[PASS] Test 5b (Decorator Blocked): Your request could not be completed because it triggered our AI safety guardrails.
```
