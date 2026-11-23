#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    canonicalJson,
    sha256Hex,
    verifyReceipt,
    verifyReceiptWithRerun,
    verifyRecompute,
    verifyGateChain,
    renderAuditReportHtml,
} from '../src/index.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const command = args[0];

function hasFlag(name) {
    return args.includes(name);
}

function getFlag(name, fallback = '') {
    const idx = args.indexOf(name);
    if (idx < 0) return fallback;
    const next = args[idx + 1];
    return next && !next.startsWith('--') ? next : fallback;
}

if (!command || command === '--help' || command === '-h') {
    console.log(`Usage:
  surinch-verify receipt --receipt <receipt.json> --input <raw.sql> --result <result.json> [--public-key <pub.pem>]
  surinch-verify receipt --receipt <receipt.json> --input <raw.sql> --rerun [--dialect mysql|postgresql|doris] [--config <.surinchrc.json>] [--public-key <pub.pem>]
  surinch-verify recompute --file <recompute-spec.json>
  surinch-verify gate-chain --file <chain.json> [--public-key <pub.pem>]
  surinch-verify report --file <bundle.json> [--lang zh|en] [--out report.html]

Trust model:
  --result  Verifies SHA-256 self-consistency (INTEGRITY_ONLY unless --public-key is provided).
  --rerun   Re-executes the deterministic @surinch/db-guard-mcp engine and checks engine_version + output hash (RERUN_VERIFIED).`);
    process.exit(0);
}

async function loadDbGuardEngine() {
    const candidates = [
        path.resolve(__dirname, '..', '..', 'db-guard-mcp', 'src', 'index.mjs'),
        path.resolve(__dirname, '..', '..', '01-db-guard-engine', 'src', 'index.mjs'),
    ];
    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return import(candidate);
        }
    }
    return import('@surinch/db-guard-mcp');
}

try {
    if (command === 'receipt') {
        const receipt = JSON.parse(fs.readFileSync(getFlag('--receipt'), 'utf8'));
        const rawInput = fs.readFileSync(getFlag('--input'), 'utf8');
        const pubKeyPath = getFlag('--public-key', '');
        const publicKeyPem = pubKeyPath ? fs.readFileSync(pubKeyPath, 'utf8') : null;
        const rerunMode = hasFlag('--rerun');

        let out;
        if (rerunMode) {
            const dg = await loadDbGuardEngine();
            const dialect = getFlag('--dialect', '') || receipt.dialect || 'mysql';
            const configPath = getFlag('--config', '') || undefined;
            out = await verifyReceiptWithRerun({
                receipt,
                rawInput,
                dialect,
                config: configPath,
                publicKeyPem,
                requireSignature: Boolean(publicKeyPem),
                runEngine: ({ tool, rawInput: input, dialect: d, config: cfg }) => {
                    let result = null;
                    if (tool === 'ddl_governance_check') {
                        result = dg.analyzeDdlGovernance(input, d, { config: cfg });
                    } else if (tool === 'sql_readonly_review') {
                        result = dg.reviewSqlReadonly(input, d, { config: cfg });
                    } else if (tool === 'sensitive_masking_scan') {
                        result = dg.scanSensitiveMasking(input, d, { config: cfg });
                    } else {
                        return null;
                    }
                    const configSha256 = dg.serializeConfigForHash
                        ? sha256Hex(canonicalJson(dg.serializeConfigForHash(cfg)))
                        : null;
                    return {
                        result,
                        engineVersion: dg.ENGINE_VERSION,
                        configSha256,
                    };
                },
            });
        } else {
            const recomputedResult = JSON.parse(fs.readFileSync(getFlag('--result'), 'utf8'));
            out = verifyReceipt({
                receipt,
                rawInput,
                recomputedResult,
                publicKeyPem,
                requireSignature: Boolean(publicKeyPem),
            });
        }
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
        const pubKeyPath = getFlag('--public-key', '');
        const publicKeyPem = pubKeyPath ? fs.readFileSync(pubKeyPath, 'utf8') : null;
        const out = verifyGateChain(chain, {
            publicKeyPem,
            requireSignature: Boolean(publicKeyPem),
        });
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
