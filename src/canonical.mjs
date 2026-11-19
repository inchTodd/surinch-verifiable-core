import crypto from 'node:crypto';

export const CORE_VERSION = '0.1.1';
export const RECEIPT_SCHEMA_VERSION = 'surinch.receipt.h1';
export const GATE_CHAIN_SCHEMA_VERSION = 'surinch.gate_chain.v1';

export function canonicalize(value) {
    if (value === null || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(canonicalize);
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
        if (value[key] !== undefined) {
            sorted[key] = canonicalize(value[key]);
        }
    }
    return sorted;
}

export function canonicalJson(value) {
    return JSON.stringify(canonicalize(value));
}

export function sha256Hex(text) {
    return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

export function deriveExpectedVerdict(result) {
    if (!result || typeof result !== 'object' || !result.ok) {
        return 'INVALID_INPUT';
    }
    if ((result.counts?.p0 || 0) > 0 || result.readonlySafe === false) {
        return 'BLOCK';
    }
    if ((result.counts?.p1 || 0) + (result.counts?.p2 || 0) > 0) {
        return 'WARN';
    }
    return 'PASS';
}
