# MEGA.dev S02E04 — two places

This public repository runs the independent **job-1** worker remotely in GitHub
Actions. The coordinator and separate job-2 worker run on the student's machine.
The coordinator does not perform either job; it joins the two accepted results.

## Configure

Add repository Actions secrets:

- `GEMINI_API_KEY`: a Google AI Studio API key for a project **without billing**.
- `JOB_1_MCP_URL`: the course's secret, day-long job-1 MCP link.

Never commit either secret or paste it into an issue. The MCP link is itself a
credential. Google receives the job skill, records and tool exchanges, but the
worker does not send Google its Gemini API key or job MCP URL in model context.
Consult Google's current terms for free-tier data handling and regional rules.

Run the `Remote job-1 (Gemini free tier)` workflow manually and check the free-tier
confirmation only after confirming no Gemini billing. The workflow is restricted
to public `ladamczewski/mega-s02e04-ci` on the standard `ubuntu-latest` runner.
No scheduled or push-triggered runs are configured. Do not enable paid fallbacks.

The model is pinned to `gemini-3.8-flash`, advertised with free input/output on
2026-11-24. A model's free-tier eligibility does not make requests free on a
billed Google project. The script cannot verify the project's billing status.
Quota failures stop the worker; there is no paid fallback. The run has a 12-minute
timeout and 24-model-turn limit. No third-party Python packages are installed.

## Worker behavior and evidence

The remote worker downloads and installs the exact course `incident-lookup` v1
skill, reads its MCP resource, discovers tool schemas and lets Gemini do the job
using only that job's tools. It cannot execute arbitrary shell commands or call
other services. It captures an actual submit response, not a model-written proof.

The publicly downloadable artifact contains **only** `job-1.cms`: a ZIP encrypted
with OpenSSL CMS AES-256-GCM and the RSA public certificate in
`artifact-recipient.pem`. It holds the original accepted submit result and receipt
plus the audit log. Masking alone does not make the audit safe to publish.
The private RSA key stays exclusively on the coordinator machine; never add it
to GitHub, Actions secrets, logs or artifacts. Retention is one day. Encryption
failure or timeout never uploads plaintext. Public logs contain progress only;
HTTP bodies and exception details are restricted to the encrypted audit.
The coordinator authenticates/decrypts the envelope and validates the captured
submit response locally before merging with job-2. Success in CI is not a course
claim. Run `python3 -m unittest -v` for offline tests; they do not execute job-1.

## Contracts consulted

- https://ai.google.dev/gemini-api/docs/pricing
- https://aistudio.google.com/api-reference/generate-content/generate-content
- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/specification/2025-11-25/server/resources
