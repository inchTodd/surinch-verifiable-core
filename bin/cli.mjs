#!/usr/bin/env node
import fs from 'node:fs';
import {
    verifyReceipt,
    verifyRecompute,
    verifyGateChain,
    renderAuditReportHtml,
} from '../src/index.mjs';

const args = process.argv.slice(2);
const command = args[0];

function getFlag(name, fallback = '') {
    const idx = args.indexOf(name);
    return idx >= 0 && args[idx + 1] ? args[idx + 1] : fallback;
}

if (!command || command === '--help' || command === '-h') {
    console.log(`Usage:
  surinch-verify receipt --receipt <receipt.json> --input <raw.sql> --result <result.json>
  surinch-verify recompute --file <recompute-spec.json>
  surinch-verify gate-chain --file <chain.json>
  surinch-verify report --file <bundle.json> [--lang zh|en] [--out report.html]`);
    process.exit(0);
}

try {
    if (command === 'receipt') {
        const receipt = JSON.parse(fs.readFileSync(getFlag('--receipt'), 'utf8'));
        const rawInput = fs.readFileSync(getFlag('--input'), 'utf8');
        const recomputedResult = JSON.parse(fs.readFileSync(getFlag('--result'), 'utf8'));
        const out = verifyReceipt({ receipt, rawInput, recomputedResult });
        console.log(JSON.stringify(out, null, 2));
        process.exit(out.ok ? 0 : out.verdict === 'INVALID_INPUT' ? 2 : 1);
    }

    if (command === 'recompute') {
        const spec = JSON.parse(fs.readFileSync(getFlag('--file'), 'utf8'));
        const out = verifyRecompute(spec);
        console.log(JSON.stringify(out, null, 2));
        process.exit(out.ok ? 0 : out.verdict === 'INVALID_INPUT' ? 2 : 1);
    }

    if (command === 'gate-chain') {
        const chain = JSON.parse(fs.readFileSync(getFlag('--file'), 'utf8'));
        const out = verifyGateChain(chain);
        console.log(JSON.stringify(out, null, 2));
        process.exit(out.ok ? 0 : out.verdict === 'INVALID_INPUT' ? 2 : 1);
    }

    if (command === 'report') {
        const bundle = JSON.parse(fs.readFileSync(getFlag('--file'), 'utf8'));
        const lang = getFlag('--lang', 'zh');
        const outPath = getFlag('--out', '');
        const rendered = renderAuditReportHtml({ ...bundle, lang });
        if (!rendered.ok) {
            console.error(JSON.stringify(rendered, null, 2));
            process.exit(2);
        }
        if (outPath) {
            fs.writeFileSync(outPath, rendered.html, 'utf8');
            console.log(JSON.stringify({ ok: true, lang: rendered.lang, outPath, bytes: Buffer.byteLength(rendered.html, 'utf8') }));
        } else {
            process.stdout.write(rendered.html);
        }
        process.exit(0);
    }

    console.error(`Unknown command: ${command}`);
    process.exit(2);
} catch (err) {
    console.error(JSON.stringify({ ok: false, errorCode: 'CLI_ERROR', message: err.message }));
    process.exit(2);
}
