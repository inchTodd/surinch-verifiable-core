import { CORE_VERSION } from './canonical.mjs';

const I18N = {
    zh: {
        title: '盈尺可复算数据治理审计报告',
        subtitle: 'Local-First · 确定性执行 · SHA-256 离线可复算回执',
        verifyBar: '离线可复算校验条',
        tool: '执行引擎',
        verdict: '裁决结果',
        inputHash: '输入 SHA-256',
        outputHash: '输出 SHA-256',
        recomputeStatus: '汇总复算状态',
        gatesSection: '三道确认闸门留痕链',
        findingsSection: '确定性审计发现明细',
        noFindings: '未检出风险项（全部规则通过）。',
        colGate: '闸门',
        colActor: '确认人',
        colDecision: '结论',
        colHash: '链式哈希 (前 16 位)',
        colSev: '级别',
        colTarget: '目标对象',
        colMsg: '说明',
        footer: '由 Surinch Verifiable Runtime 确定性生成，支持浏览器打印导出 PDF。',
    },
    en: {
        title: 'Surinch Verifiable Governance Audit Report',
        subtitle: 'Local-First · Deterministic Execution · SHA-256 Recomputable Receipt',
        verifyBar: 'Offline Recomputable Verification Bar',
        tool: 'Engine Tool',
        verdict: 'Verdict',
        inputHash: 'Input SHA-256',
        outputHash: 'Output SHA-256',
        recomputeStatus: 'Recompute Check',
        gatesSection: '3-Gate SHA-256 Audit Chain',
        findingsSection: 'Deterministic Audit Findings',
        noFindings: 'No risk findings detected (all rules passed).',
        colGate: 'Gate',
        colActor: 'Actor',
        colDecision: 'Decision',
        colHash: 'Chain Hash (16 hex)',
        colSev: 'Severity',
        colTarget: 'Target',
        colMsg: 'Message',
        footer: 'Generated deterministically by Surinch Verifiable Runtime. Print to PDF directly in any browser.',
    },
};

function escapeHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function badgeColor(verdict) {
    const v = String(verdict || '').toUpperCase();
    if (v === 'PASS' || v === 'VERIFIED' || v === 'RECOMPUTE_MATCH' || v === 'COMPLETED_VERIFIED') return '#0f766e';
    if (v === 'WARN' || v === 'IN_PROGRESS_VERIFIED') return '#b45309';
    return '#b91c1c';
}

/**
 * Render a zero-dependency, self-contained bilingual HTML audit report
 * with an offline verification bar, optional 3-gate audit chain, and findings table.
 */
export function renderAuditReportHtml({ result, receipt, recompute = null, gateChain = null, lang = 'zh', title = '' } = {}) {
    if (!result || typeof result !== 'object' || !receipt || typeof receipt !== 'object') {
        return { ok: false, errorCode: 'INVALID_INPUT', message: 'Both result and receipt objects are required.' };
    }
    const normalizedLang = String(lang || 'zh').toLowerCase();
    if (normalizedLang !== 'zh' && normalizedLang !== 'en') {
        return { ok: false, errorCode: 'UNSUPPORTED_LANG', message: `Unsupported lang "${lang}". Supported: zh, en.` };
    }

    const t = I18N[normalizedLang];
    const reportTitle = title ? String(title) : t.title;
    const verdict = receipt.verdict || 'UNKNOWN';
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const gates = Array.isArray(gateChain?.gates) ? gateChain.gates : [];

    const gatesHtml = gates.length > 0
        ? `<section class="card">
            <h2>${escapeHtml(t.gatesSection)}</h2>
            <table>
              <thead><tr><th>${escapeHtml(t.colGate)}</th><th>${escapeHtml(t.colActor)}</th><th>${escapeHtml(t.colDecision)}</th><th>${escapeHtml(t.colHash)}</th></tr></thead>
              <tbody>
                ${gates.map((g) => `<tr>
                  <td><code>${escapeHtml(g.gate_id)}</code></td>
                  <td>${escapeHtml(g.actor)}</td>
                  <td><span class="pill" style="background:${badgeColor(g.decision === 'APPROVE' ? 'PASS' : g.decision === 'WAIVE' ? 'WARN' : 'BLOCK')}">${escapeHtml(g.decision)}</span></td>
                  <td><code>${escapeHtml(String(g.gate_hash || '').slice(0, 16))}</code></td>
                </tr>`).join('\n')}
              </tbody>
            </table>
          </section>`
        : '';

    const findingsHtml = findings.length === 0
        ? `<p class="ok-empty">${escapeHtml(t.noFindings)}</p>`
        : `<table>
            <thead><tr><th>${escapeHtml(t.colSev)}</th><th>${escapeHtml(t.colTarget)}</th><th>${escapeHtml(t.colMsg)}</th></tr></thead>
            <tbody>
              ${findings.map((f) => `<tr>
                <td><span class="pill" style="background:${badgeColor(f.severity === 'P0' ? 'BLOCK' : f.severity === 'P1' ? 'WARN' : 'PASS')}">${escapeHtml(f.severity)}</span></td>
                <td><code>${escapeHtml(f.target || f.column || (f.statementIndex ? `stmt#${f.statementIndex}` : '-'))}</code></td>
                <td>${escapeHtml(f.message)}</td>
              </tr>`).join('\n')}
            </tbody>
          </table>`;

    const recomputeBadge = recompute
        ? `<div class="kv"><span>${escapeHtml(t.recomputeStatus)}</span><strong style="color:${badgeColor(recompute.verdict)}">${escapeHtml(recompute.verdict)}</strong></div>`
        : '';

    const html = `<!doctype html>
<html lang="${normalizedLang}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(reportTitle)}</title>
  <style>
    :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", sans-serif; }
    body { margin: 0; padding: 28px; background: #f8fafc; color: #0f172a; line-height: 1.5; }
    .wrap { max-width: 960px; margin: 0 auto; }
    header { margin-bottom: 20px; }
    h1 { margin: 0 0 4px; font-size: 24px; }
    .sub { color: #475569; margin: 0; font-size: 13px; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; }
    .verify-bar { border-left: 5px solid ${badgeColor(verdict)}; }
    .verify-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 10px; }
    .kv { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; font-size: 12px; }
    .kv span { display: block; color: #64748b; margin-bottom: 2px; }
    .kv code { word-break: break-all; font-size: 11px; }
    h2 { margin: 0 0 12px; font-size: 16px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    th { background: #f1f5f9; font-weight: 600; }
    .pill { display: inline-block; color: #fff; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
    .ok-empty { color: #0f766e; font-weight: 600; margin: 4px 0; }
    footer { text-align: center; color: #64748b; font-size: 12px; margin-top: 20px; }
    @media print { body { background: #fff; padding: 0; } .card { break-inside: avoid; } }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>${escapeHtml(reportTitle)}</h1>
      <p class="sub">${escapeHtml(t.subtitle)} · v${escapeHtml(CORE_VERSION)}</p>
    </header>
    <section class="card verify-bar">
      <h2>${escapeHtml(t.verifyBar)}</h2>
      <div class="verify-grid">
        <div class="kv"><span>${escapeHtml(t.tool)}</span><strong><code>${escapeHtml(receipt.tool || '-')}</code></strong></div>
        <div class="kv"><span>${escapeHtml(t.verdict)}</span><span class="pill" style="background:${badgeColor(verdict)}">${escapeHtml(verdict)}</span></div>
        ${recomputeBadge}
        <div class="kv"><span>${escapeHtml(t.inputHash)}</span><code>${escapeHtml(receipt.input_sha256 || '')}</code></div>
        <div class="kv"><span>${escapeHtml(t.outputHash)}</span><code>${escapeHtml(receipt.output_sha256 || '')}</code></div>
      </div>
    </section>
    ${gatesHtml}
    <section class="card">
      <h2>${escapeHtml(t.findingsSection)} (${findings.length})</h2>
      ${findingsHtml}
    </section>
    <footer>${escapeHtml(t.footer)}</footer>
  </div>
</body>
</html>`;

    return { ok: true, lang: normalizedLang, html };
}
