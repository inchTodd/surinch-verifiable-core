import crypto from 'node:crypto';
import {
    RECEIPT_SCHEMA_VERSION,
    canonicalJson,
    sha256Hex,
    deriveExpectedVerdict,
} from './canonical.mjs';

const SHA256_RE = /^[0-9a-f]{64}$/;

function extractReceiptSignableBody(receipt) {
    const { signature: _sig, signature_alg: _alg, ...body } = receipt;
    return body;
}

/**
 * Sign a surinch.receipt.h1 object using an Ed25519 private key (PEM)
 * to prove authenticity/origin in addition to SHA-256 integrity.
 */
export function signReceipt(receipt, privateKeyPem) {
    if (!receipt || typeof receipt !== 'object') {
        throw new Error('Receipt object is required.');
    }
    if (!privateKeyPem) {
        throw new Error('Ed25519 privateKeyPem is required to sign receipt.');
    }
    const body = extractReceiptSignableBody(receipt);
    const canonical = Buffer.from(canonicalJson(body), 'utf8');
    const signature = crypto.sign(null, canonical, privateKeyPem).toString('base64');
    return {
        ...body,
        signature_alg: 'ed25519',
        signature,
    };
}

/**
 * Independently verify a surinch.receipt.h1 artifact against raw input bytes
 * and a recomputed result object.
 *
 * Trust model note:
 * - Without `publicKeyPem` or `verifyReceiptWithRerun`, this proves mutual
 *   integrity/consistency (`verificationMode: 'INTEGRITY_ONLY'`), NOT engine provenance.
 * - Pass `publicKeyPem` for cryptographic origin authentication (`SIGNED_INTEGRITY_VERIFIED`),
 *   or use `verifyReceiptWithRerun` to re-execute the deterministic engine (`RERUN_VERIFIED`).
 */
export function verifyReceipt({
    receipt,
    rawInput,
    recomputedResult,
    expectedEngineVersion = null,
    expectedDialect = null,
    expectedConfigSha256 = null,
    publicKeyPem = null,
    requireSignature = false,
} = {}) {
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

    if (expectedEngineVersion && receipt.engine_version !== expectedEngineVersion) {
        mismatches.push({
            code: 'ENGINE_VERSION_MISMATCH',
            expected: expectedEngineVersion,
            actual: receipt.engine_version ?? null,
            message: `Receipt engine_version "${receipt.engine_version}" does not match expected "${expectedEngineVersion}".`,
        });
    }

    if (expectedDialect) {
        const normExpected = String(expectedDialect).trim().toLowerCase();
        const normActual = String(receipt.dialect ?? recomputedResult.dialect ?? '').trim().toLowerCase();
        if (normActual !== normExpected) {
            mismatches.push({
                code: 'DIALECT_MISMATCH',
                expected: normExpected,
                actual: normActual || null,
                message: `Receipt dialect "${normActual}" does not match expected "${normExpected}".`,
            });
        }
    }

    if (expectedConfigSha256) {
        if (receipt.config_sha256 !== expectedConfigSha256) {
            mismatches.push({
                code: 'CONFIG_HASH_MISMATCH',
                expected: expectedConfigSha256,
                actual: receipt.config_sha256 ?? null,
                message: 'Receipt config_sha256 does not match expected configuration hash.',
            });
        }
    }

    // If v0.3+ context_sha256 is present, verify it binds tool + dialect + engine_version + input_sha256 + config_sha256
    if (receipt.context_sha256 !== undefined) {
        const recomputedContextSha = sha256Hex(canonicalJson({
            tool: receipt.tool ?? null,
            dialect: receipt.dialect ?? null,
            engine_version: receipt.engine_version ?? null,
            input_sha256: expectedInputSha,
            config_sha256: receipt.config_sha256 ?? null,
        }));
        if (receipt.context_sha256 !== recomputedContextSha) {
            mismatches.push({
                code: 'CONTEXT_HASH_MISMATCH',
                expected: recomputedContextSha,
                actual: receipt.context_sha256 ?? null,
                message: 'Receipt context_sha256 does not match tool/dialect/engine_version/config binding.',
            });
        }
    }

    let signatureVerified = false;
    if (publicKeyPem || requireSignature) {
        if (!receipt.signature || typeof receipt.signature !== 'string') {
            mismatches.push({
                code: 'MISSING_SIGNATURE',
                message: 'Receipt Ed25519 signature is required but missing.',
            });
        } else if (!publicKeyPem) {
            mismatches.push({
                code: 'MISSING_PUBLIC_KEY',
                message: 'publicKeyPem is required to verify receipt signature.',
            });
        } else {
            let sigOk = false;
            try {
                const canonical = Buffer.from(canonicalJson(extractReceiptSignableBody(receipt)), 'utf8');
                const sigBuf = Buffer.from(receipt.signature, 'base64');
                sigOk = crypto.verify(null, canonical, publicKeyPem, sigBuf);
            } catch {
                sigOk = false;
            }
            if (!sigOk) {
                mismatches.push({
                    code: 'INVALID_SIGNATURE',
                    message: 'Receipt Ed25519 signature verification failed.',
                });
            } else {
                signatureVerified = true;
            }
        }
    }

    const verified = mismatches.length === 0;
    return {
        ok: verified,
        verified,
        signatureVerified,
        verificationMode: signatureVerified ? 'SIGNED_INTEGRITY_VERIFIED' : 'INTEGRITY_ONLY',
        verdict: verified ? 'VERIFIED' : 'TAMPERED_OR_MISMATCH',
        tool: receipt.tool ?? null,
        dialect: receipt.dialect ?? null,
        engine_version: receipt.engine_version ?? null,
        expectedInputSha256: expectedInputSha,
        expectedOutputSha256: expectedOutputSha,
        expectedVerdict,
        mismatches,
    };
}

/**
 * Re-execute the deterministic engine on `rawInput` and independently verify
 * the receipt against the live recomputed result + engine version + config hash.
 * Catches forged PASS receipts (audit A2).
 */
export async function verifyReceiptWithRerun({
    receipt,
    rawInput,
    runEngine,
    dialect = null,
    config = undefined,
    publicKeyPem = null,
    requireSignature = false,
} = {}) {
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
    if (typeof runEngine !== 'function') {
        return {
            ok: false,
            errorCode: 'MISSING_ENGINE_RUNNER',
            verdict: 'INVALID_INPUT',
            mismatches: [{ code: 'MISSING_ENGINE_RUNNER', message: 'runEngine callback is required for rerun verification.' }],
        };
    }

    const effectiveDialect = dialect || receipt.dialect || 'mysql';
    const rerun = await runEngine({
        tool: receipt.tool,
        rawInput,
        dialect: effectiveDialect,
        config,
    });

    if (!rerun || !rerun.result) {
        return {
            ok: false,
            errorCode: 'ENGINE_RERUN_FAILED',
            verdict: 'INVALID_INPUT',
            mismatches: [{ code: 'ENGINE_RERUN_FAILED', message: `Unsupported or failed engine rerun for tool "${receipt.tool}".` }],
        };
    }

    const verified = verifyReceipt({
        receipt,
        rawInput,
        recomputedResult: rerun.result,
        expectedEngineVersion: rerun.engineVersion || null,
        expectedDialect: effectiveDialect,
        expectedConfigSha256: receipt.config_sha256 ? rerun.configSha256 || null : null,
        publicKeyPem,
        requireSignature,
    });

    return {
        ...verified,
        rerunEngineVersion: rerun.engineVersion || null,
        verificationMode: verified.signatureVerified ? 'RERUN_AND_SIGNED_VERIFIED' : 'RERUN_VERIFIED',
    };
}
