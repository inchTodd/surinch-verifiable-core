import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
    RECEIPT_SCHEMA_VERSION,
    canonicalJson,
    sha256Hex,
    deriveExpectedVerdict,
    verifyReceipt,
    verifyRecompute,
    GATE_SEQUENCE,
    createGateChain,
    advanceGate,
    verifyGateChain,
    renderAuditReportHtml,
} from '../src/index.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'cli.mjs');

function makeFixtureResult(ddl) {
    return {
        ok: true,
        dialect: 'mysql',
        totalScore: 55,
        counts: { p0: 1, p1: 1, p2: 0 },
        findings: [
            { id: 'float-money', severity: 'P0', target: 'bad_orders.pay_amount', message: 'Money column uses FLOAT' },
            { id: 'missing-pk', severity: 'P1', target: 'bad_orders', message: 'Missing PRIMARY KEY' },
        ],
        rawLength: ddl.length,
    };
}

function makeFixtureReceipt({ tool, rawInput, result }) {
    return {
        schema_version: RECEIPT_SCHEMA_VERSION,
        tool,
        engine_version: '0.1.0',
        verdict: deriveExpectedVerdict(result),
        input_sha256: sha256Hex(rawInput),
        output_sha256: sha256Hex(canonicalJson(result)),
        generated_at: new Date().toISOString(),
    };
}

test('verifyReceipt verifies receipts (including db-guard-mcp interop when present) and catches input/output/verdict tampering', async () => {
    const ddl = `CREATE TABLE bad_orders (pay_amount FLOAT);`;
    const dbGuardPath = path.resolve(__dirname, '..', '..', 'db-guard-mcp', 'src', 'index.mjs');
    let result;
    let receipt;
    if (fs.existsSync(dbGuardPath)) {
        const dbGuard = await import(dbGuardPath);
        result = dbGuard.analyzeDdlGovernance(ddl, 'mysql');
        receipt = dbGuard.buildReceipt({ tool: 'ddl_governance_check', rawInput: ddl, result });
    } else {
        result = makeFixtureResult(ddl);
        receipt = makeFixtureReceipt({ tool: 'ddl_governance_check', rawInput: ddl, result });
    }

    // Positive: untouched receipt verifies cleanly
    const ok = verifyReceipt({ receipt, rawInput: ddl, recomputedResult: result });
    assert.equal(ok.ok, true);
    assert.equal(ok.verdict, 'VERIFIED');
    assert.equal(ok.mismatches.length, 0);

    // Fault injection 1: tamper raw input by 1 space
    const badInput = verifyReceipt({ receipt, rawInput: `${ddl} `, recomputedResult: result });
    assert.equal(badInput.ok, false);
    assert.equal(badInput.verdict, 'TAMPERED_OR_MISMATCH');
    assert.ok(badInput.mismatches.some((m) => m.code === 'INPUT_HASH_MISMATCH'));

    // Fault injection 2: fake green tamper (change BLOCK -> PASS)
    const tamperedReceipt = { ...receipt, verdict: 'PASS' };
    const badVerdict = verifyReceipt({ receipt: tamperedReceipt, rawInput: ddl, recomputedResult: result });
    assert.equal(badVerdict.ok, false);
    assert.ok(badVerdict.mismatches.some((m) => m.code === 'VERDICT_TAMPERED'));

    // Fault injection 3: tamper result totalScore
    const tamperedResult = { ...result, totalScore: 100 };
    const badOutput = verifyReceipt({ receipt, rawInput: ddl, recomputedResult: tamperedResult });
    assert.equal(badOutput.ok, false);
    assert.ok(badOutput.mismatches.some((m) => m.code === 'OUTPUT_HASH_MISMATCH'));

    // Fault injection 4: missing receipt
    const missing = verifyReceipt({ receipt: null, rawInput: ddl, recomputedResult: result });
    assert.equal(missing.ok, false);
    assert.equal(missing.verdict, 'INVALID_INPUT');
});

test('verifyRecompute handles financial decimal sums, weighted DDL scores, and blocks mismatches', async () => {
    // IEEE-754 decimal precision check: 0.1 + 0.2 === 0.3 exact
    const finOk = verifyRecompute({
        summary: { totalAmount: 0.3, rowCount: 2, p0Count: 1 },
        details: [
            { amt: 0.1, severity: 'P0' },
            { amt: 0.2, severity: 'P1' },
        ],
        rules: [
            { summaryKey: 'totalAmount', op: 'sum', detailField: 'amt' },
            { summaryKey: 'rowCount', op: 'count' },
            { summaryKey: 'p0Count', op: 'count_where', detailField: 'severity', equals: 'P0' },
        ],
    });
    assert.equal(finOk.ok, true);
    assert.equal(finOk.verdict, 'RECOMPUTE_MATCH');

    // Mismatch of 0.01 must block build (ok: false)
    const finBad = verifyRecompute({
        summary: { totalAmount: 0.31 },
        details: [{ amt: 0.1 }, { amt: 0.2 }],
        rules: [{ summaryKey: 'totalAmount', op: 'sum', detailField: 'amt' }],
    });
    assert.equal(finBad.ok, false);
    assert.equal(finBad.verdict, 'RECOMPUTE_MISMATCH');
    assert.equal(finBad.diffs[0].delta, 0.01);

    // Weighted DDL score recompute (uses live db-guard-mcp when present, self-contained fixture standalone)
    const dbGuardPath = path.resolve(__dirname, '..', '..', 'db-guard-mcp', 'src', 'index.mjs');
    let ddlRes;
    if (fs.existsSync(dbGuardPath)) {
        const dbGuard = await import(dbGuardPath);
        ddlRes = dbGuard.analyzeDdlGovernance(`
            CREATE TABLE orders_fact (
                id BIGINT PRIMARY KEY COMMENT 'pk',
                pay_amount DECIMAL(18,2) COMMENT 'amt',
                created_at DATETIME COMMENT 'ts'
            ) COMMENT='orders';
        `, 'mysql');
    } else {
        ddlRes = {
            totalScore: 95,
            dimensions: [
                { name: 'keys', score: 100, weightPct: 30 },
                { name: 'types', score: 100, weightPct: 25 },
                { name: 'naming', score: 80, weightPct: 25 },
                { name: 'comments', score: 100, weightPct: 20 },
            ],
        };
    }
    const scoreCheck = verifyRecompute({
        summary: { totalScore: ddlRes.totalScore },
        details: ddlRes.dimensions,
        rules: [{ summaryKey: 'totalScore', op: 'weighted_sum', detailField: 'score', weightField: 'weightPct', weightScale: 100 }],
    });
    assert.equal(scoreCheck.ok, true);

    // Fault injection: empty details & NaN
    assert.equal(verifyRecompute({ summary: { a: 1 }, details: [], rules: [{ summaryKey: 'a', op: 'count' }] }).errorCode, 'EMPTY_DETAILS');
    assert.equal(verifyRecompute({ summary: { a: 1 }, details: [{ v: 'not-a-num' }], rules: [{ summaryKey: 'a', op: 'sum', detailField: 'v' }] }).errorCode, 'INVALID_DETAIL_VALUE');
});

test('3-Gate SHA-256 audit chain enforces strict order, waiver reason, and tamper detection', () => {
    const { ok, chain: c0 } = createGateChain('run-20261119-001');
    assert.equal(ok, true);

    // Cannot skip Gate 1
    const skipAttempt = advanceGate(c0, { gateId: GATE_SEQUENCE[1], payload: { x: 1 }, actor: 'alice' });
    assert.equal(skipAttempt.ok, false);
    assert.equal(skipAttempt.errorCode, 'OUT_OF_ORDER_GATE');

    // Gate 1: Input lock
    const g1 = advanceGate(c0, { gateId: GATE_SEQUENCE[0], payload: 'CREATE TABLE t (id INT);', actor: 'maker-agent', decision: 'APPROVE' });
    assert.equal(g1.ok, true);

    // Gate 2: WAIVE without reason must fail
    const badWaive = advanceGate(g1.chain, { gateId: GATE_SEQUENCE[1], payload: { p0: 1 }, actor: 'reviewer', decision: 'WAIVE' });
    assert.equal(badWaive.ok, false);
    assert.equal(badWaive.errorCode, 'MISSING_WAIVER_REASON');

    // Gate 2: WAIVE with explicit reason succeeds
    const g2 = advanceGate(g1.chain, {
        gateId: GATE_SEQUENCE[1],
        payload: { p0: 1 },
        actor: 'reviewer-bob',
        decision: 'WAIVE',
        waiverReason: 'Legacy archive table scheduled for Q2 migration',
    });
    assert.equal(g2.ok, true);

    // Gate 3: Report confirm
    const g3 = advanceGate(g2.chain, { gateId: GATE_SEQUENCE[2], payload: '<html>report</html>', actor: 'approver-lead', decision: 'APPROVE' });
    assert.equal(g3.ok, true);
    assert.equal(g3.chain.status, 'COMPLETED');

    const verified = verifyGateChain(g3.chain);
    assert.equal(verified.ok, true);
    assert.equal(verified.complete, true);
    assert.equal(verified.verdict, 'COMPLETED_VERIFIED');

    // Tamper historical Gate 1 actor -> immediate detection
    const tampered = structuredClone(g3.chain);
    tampered.gates[0].actor = 'mallory';
    const tamperedCheck = verifyGateChain(tampered);
    assert.equal(tamperedCheck.ok, false);
    assert.equal(tamperedCheck.verdict, 'CHAIN_TAMPERED');
    assert.ok(tamperedCheck.mismatches.some((m) => m.code === 'GATE_HASH_MISMATCH' && m.index === 0));

    // REJECT halts chain permanently
    const rej = advanceGate(g1.chain, { gateId: GATE_SEQUENCE[1], payload: { p0: 2 }, actor: 'verifier', decision: 'REJECT' });
    assert.equal(rej.chain.status, 'REJECTED');
    const afterRej = advanceGate(rej.chain, { gateId: GATE_SEQUENCE[2], payload: 'report', actor: 'approver', decision: 'APPROVE' });
    assert.equal(afterRej.ok, false);
    assert.equal(afterRej.errorCode, 'CHAIN_REJECTED');
});

test('renderAuditReportHtml generates bilingual offline reports and escapes XSS payloads', () => {
    const ddl = 'CREATE TABLE bad_t (pay_amount FLOAT);';
    const result = makeFixtureResult(ddl);
    result.findings.push({
        id: 'xss-test',
        severity: 'P1',
        target: '<script>alert(1)</script>',
        message: 'Injected <img src=x onerror=alert(1)>',
    });
    const receipt = makeFixtureReceipt({ tool: 'ddl_governance_check', rawInput: ddl, result });

    const zh = renderAuditReportHtml({ result, receipt, lang: 'zh' });
    assert.equal(zh.ok, true);
    assert.match(zh.html, /离线可复算校验条/);
    assert.equal(zh.html.includes('<script>alert(1)</script>'), false);
    assert.equal(zh.html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), true);

    const en = renderAuditReportHtml({ result, receipt, lang: 'en' });
    assert.equal(en.ok, true);
    assert.match(en.html, /Offline Recomputable Verification Bar/);

    const badLang = renderAuditReportHtml({ result, receipt, lang: 'fr' });
    assert.equal(badLang.ok, false);
    assert.equal(badLang.errorCode, 'UNSUPPORTED_LANG');
});

test('surinch-verify CLI enforces exit codes 0 (match), 1 (mismatch/tamper), and 2 (invalid)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'surinch-verify-'));
    try {
        const matchFile = path.join(tmpDir, 'match.json');
        const mismatchFile = path.join(tmpDir, 'mismatch.json');
        fs.writeFileSync(matchFile, JSON.stringify({
            summary: { total: 30 },
            details: [{ v: 10 }, { v: 20 }],
            rules: [{ summaryKey: 'total', op: 'sum', detailField: 'v' }],
        }));
        fs.writeFileSync(mismatchFile, JSON.stringify({
            summary: { total: 35 },
            details: [{ v: 10 }, { v: 20 }],
            rules: [{ summaryKey: 'total', op: 'sum', detailField: 'v' }],
        }));

        const r0 = spawnSync(process.execPath, [CLI_PATH, 'recompute', '--file', matchFile], { encoding: 'utf8' });
        assert.equal(r0.status, 0);
        assert.equal(JSON.parse(r0.stdout).verdict, 'RECOMPUTE_MATCH');

        const r1 = spawnSync(process.execPath, [CLI_PATH, 'recompute', '--file', mismatchFile], { encoding: 'utf8' });
        assert.equal(r1.status, 1);
        assert.equal(JSON.parse(r1.stdout).verdict, 'RECOMPUTE_MISMATCH');

        const r2 = spawnSync(process.execPath, [CLI_PATH, 'unknown-cmd'], { encoding: 'utf8' });
        assert.equal(r2.status, 2);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('Publishable package files contain no local host paths or embedded credentials', () => {
    const pkgRoot = path.resolve(path.dirname(CLI_PATH), '..');
    const pkg = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
    const forbidden = [
        /\/Users\/[A-Za-z0-9_.-]+/,
        /ghp_[A-Za-z0-9]{20,}/,
        /npm_[A-Za-z0-9]{20,}/,
        /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
        /client_secret\s*[:=]\s*["'][^"']+["']/i,
    ];
    const collectFiles = (entry) => {
        const full = path.join(pkgRoot, entry);
        if (!fs.existsSync(full)) return [];
        const stat = fs.statSync(full);
        if (stat.isFile()) return [full];
        return fs.readdirSync(full).flatMap((child) => collectFiles(path.join(entry, child)));
    };
    const files = ['package.json', ...(pkg.files || [])].flatMap(collectFiles);
    assert.ok(files.length > 0, 'Expected publishable files to exist');
    for (const file of files) {
        const text = fs.readFileSync(file, 'utf8');
        for (const re of forbidden) {
            assert.equal(re.test(text), false, `Forbidden pattern ${re} matched in ${file}`);
        }
    }
});
