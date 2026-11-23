# @surinch/verifiable-core

> **Layer 3 Verifiable Runtime Core**: Offline `surinch.receipt.h1` verifier (with `--rerun` engine re-execution & Ed25519 signature verification), deterministic `verify_recompute` summary-vs-detail reconciler, 3-Gate SHA-256 audit chain with separation of duties, and bilingual offline HTML audit report generator. Zero third-party dependencies.

## Modules

1. **`verifyReceipt` / `verifyReceiptWithRerun` / `signReceipt`**:
   - **Integrity mode (`--result`)**: Independently recomputes `input_sha256`, `context_sha256`, canonical `output_sha256`, and expected `verdict` (`verificationMode: "INTEGRITY_ONLY"`). Proves artifact consistency, not provenance.
   - **Engine rerun mode (`--rerun`)**: Re-executes the deterministic `@surinch/db-guard-mcp` engine against the raw input and verifies `engine_version`, `dialect`, `config_sha256`, and recomputed output (`verificationMode: "RERUN_VERIFIED"`), catching forged `PASS` receipts.
   - **Ed25519 signing (`--public-key`)**: Optional cryptographic origin authentication (`SIGNED_INTEGRITY_VERIFIED` / `RERUN_AND_SIGNED_VERIFIED`).
2. **`verifyRecompute`**: Deterministic reconciler (`sum` and `weighted_sum` with exact integer scaling, `penalty`, `clampMin`, `count`, `count_where`) that blocks builds (`exit 1`) whenever summary != details.
3. **`createGateChain` / `advanceGate` / `signGateChain` / `verifyGateChain`**: Strict 3-gate workflow (`GATE_1_INPUT_LOCK` -> `GATE_2_RESULT_CONFIRM` -> `GATE_3_REPORT_CONFIRM`) with `decided_at` bound into chained SHA-256 hashes, separation of duties (distinct actors across all 3 gates), mandatory waiver justification, and optional Ed25519 chain signing.
4. **`renderAuditReportHtml`**: Zero-CDN, print-to-PDF bilingual (`zh` / `en`) HTML audit report with an offline verification bar and XSS-safe rendering.

## CLI Usage

```bash
# 1. Re-execute deterministic engine & verify receipt (catches forged PASS receipts)
surinch-verify receipt --receipt receipt.json --input schema.sql --rerun --dialect postgresql [--public-key pub.pem]

# 2. Hash-only integrity check (consistency of 3 artifacts)
surinch-verify receipt --receipt receipt.json --input schema.sql --result result.json [--public-key pub.pem]

# 3. Deterministic summary-vs-detail reconciliation
surinch-verify recompute --file recompute-spec.json

# 4. Verify 3-gate SHA-256 sign-off chain
surinch-verify gate-chain --file chain.json [--public-key pub.pem]

# 5. Render bilingual offline HTML audit report
surinch-verify report --file bundle.json --lang en --out audit-report.html
```
