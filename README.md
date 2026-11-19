# @surinch/verifiable-core

> **Layer 3 Verifiable Runtime Core**: Offline `surinch.receipt.h1` verifier, deterministic `verify_recompute` summary-vs-detail reconciler, 3-Gate SHA-256 audit chain, and bilingual offline HTML audit report generator. Zero third-party dependencies.

## Modules

1. **`verifyReceipt`**: Independently recomputes `input_sha256`, canonical `output_sha256`, and expected `verdict` to detect input substitution, result tampering, or fake-green verdict overrides.
2. **`verifyRecompute`**: Deterministic reconciler (`sum` with integer scaling, `weighted_sum`, `count`, `count_where`) that blocks builds (`exit 1`) whenever summary ≠ details.
3. **`createGateChain` / `advanceGate` / `verifyGateChain`**: Strict 3-gate workflow (`GATE_1_INPUT_LOCK` → `GATE_2_RESULT_CONFIRM` → `GATE_3_REPORT_CONFIRM`) with chained SHA-256 hashes, mandatory waiver justification, and offline tamper detection.
4. **`renderAuditReportHtml`**: Zero-CDN, print-to-PDF bilingual (`zh` / `en`) HTML audit report with an offline verification bar and XSS-safe rendering.

## CLI Usage

```bash
surinch-verify receipt --receipt receipt.json --input schema.sql --result result.json
surinch-verify recompute --file recompute-spec.json
surinch-verify gate-chain --file chain.json
surinch-verify report --file bundle.json --lang en --out audit-report.html
```
