import {
    RECEIPT_SCHEMA_VERSION,
    canonicalJson,
    sha256Hex,
    deriveExpectedVerdict,
} from './canonical.mjs';

const SHA256_RE = /^[0-9a-f]{64}$/;

/**
 * Independently verify a surinch.receipt.h1 artifact against raw input bytes
 * and a recomputed result object. Never passes on missing or tampered fields.
 */
export function verifyReceipt({ receipt, rawInput, recomputedResult } = {}) {
    if (!receipt || typeof receipt !== 'object') {
        return {
            ok: false,
            errorCode: 'INVALID_INPUT',
            verdict: 'INVALID_INPUT',
            mismatches: [{ code: 'MISSING_RECEIPT', message: 'Receipt object is required.' }],
        };
    }
    if (typeof rawInput !== 'string') {
        return {
            ok: false,
            errorCode: 'INVALID_INPUT',
            verdict: 'INVALID_INPUT',
            mismatches: [{ code: 'MISSING_RAW_INPUT', message: 'rawInput must be a string.' }],
        };
    }
    if (!recomputedResult || typeof recomputedResult !== 'object') {
        return {
            ok: false,
            errorCode: 'INVALID_INPUT',
            verdict: 'INVALID_INPUT',
            mismatches: [{ code: 'MISSING_RESULT', message: 'recomputedResult object is required.' }],
        };
    }

    const mismatches = [];

    if (receipt.schema_version !== RECEIPT_SCHEMA_VERSION) {
        mismatches.push({
            code: 'INVALID_RECEIPT_SCHEMA',
            expected: RECEIPT_SCHEMA_VERSION,
            actual: receipt.schema_version ?? null,
            message: `Expected schema_version "${RECEIPT_SCHEMA_VERSION}".`,
        });
    }

    if (!SHA256_RE.test(String(receipt.input_sha256 || ''))) {
        mismatches.push({
            code: 'MALFORMED_INPUT_SHA256',
            actual: receipt.input_sha256 ?? null,
            message: 'receipt.input_sha256 is not a valid 64-char hex SHA-256.',
        });
    }

    if (!SHA256_RE.test(String(receipt.output_sha256 || ''))) {
        mismatches.push({
            code: 'MALFORMED_OUTPUT_SHA256',
            actual: receipt.output_sha256 ?? null,
            message: 'receipt.output_sha256 is not a valid 64-char hex SHA-256.',
        });
    }

    const expectedInputSha = sha256Hex(rawInput);
    if (receipt.input_sha256 !== expectedInputSha) {
        mismatches.push({
            code: 'INPUT_HASH_MISMATCH',
            expected: expectedInputSha,
            actual: receipt.input_sha256 ?? null,
            message: 'Raw input bytes do not match receipt.input_sha256.',
        });
    }

    const expectedOutputSha = sha256Hex(canonicalJson(recomputedResult));
    if (receipt.output_sha256 !== expectedOutputSha) {
        mismatches.push({
            code: 'OUTPUT_HASH_MISMATCH',
            expected: expectedOutputSha,
            actual: receipt.output_sha256 ?? null,
            message: 'Recomputed canonical output does not match receipt.output_sha256.',
        });
    }

    const expectedVerdict = deriveExpectedVerdict(recomputedResult);
    if (receipt.verdict !== expectedVerdict) {
        mismatches.push({
            code: 'VERDICT_TAMPERED',
            expected: expectedVerdict,
            actual: receipt.verdict ?? null,
            message: `Receipt verdict "${receipt.verdict}" does not match derived verdict "${expectedVerdict}".`,
        });
    }

    const verified = mismatches.length === 0;
    return {
        ok: verified,
        verified,
        verdict: verified ? 'VERIFIED' : 'TAMPERED_OR_MISMATCH',
        tool: receipt.tool ?? null,
        engine_version: receipt.engine_version ?? null,
        expectedInputSha256: expectedInputSha,
        expectedOutputSha256: expectedOutputSha,
        expectedVerdict,
        mismatches,
    };
}
