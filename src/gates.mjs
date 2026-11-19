import {
    CORE_VERSION,
    GATE_CHAIN_SCHEMA_VERSION,
    canonicalJson,
    sha256Hex,
} from './canonical.mjs';

export const GATE_SEQUENCE = ['GATE_1_INPUT_LOCK', 'GATE_2_RESULT_CONFIRM', 'GATE_3_REPORT_CONFIRM'];
const VALID_DECISIONS = new Set(['APPROVE', 'WAIVE', 'REJECT']);
const GENESIS_HASH = '0'.repeat(64);

function computeGateHash({ prevHash, gateId, payloadSha256, actor, decision, waiverReason }) {
    return sha256Hex(canonicalJson({
        prev_hash: prevHash,
        gate_id: gateId,
        payload_sha256: payloadSha256,
        actor,
        decision,
        waiver_reason: waiverReason || '',
    }));
}

export function createGateChain(runId) {
    const id = String(runId || '').trim();
    if (!id) {
        return { ok: false, errorCode: 'EMPTY_RUN_ID', message: 'runId is required.' };
    }
    return {
        ok: true,
        chain: {
            schema_version: GATE_CHAIN_SCHEMA_VERSION,
            core_version: CORE_VERSION,
            run_id: id,
            status: 'IN_PROGRESS',
            gates: [],
        },
    };
}

/**
 * Append the next gate transition in strict sequence:
 * GATE_1_INPUT_LOCK -> GATE_2_RESULT_CONFIRM -> GATE_3_REPORT_CONFIRM.
 */
export function advanceGate(chain, { gateId, payload, actor, decision = 'APPROVE', waiverReason = '', timestamp } = {}) {
    if (!chain || chain.schema_version !== GATE_CHAIN_SCHEMA_VERSION || !Array.isArray(chain.gates)) {
        return { ok: false, errorCode: 'INVALID_CHAIN', message: 'Invalid gate chain object.' };
    }
    if (chain.status === 'REJECTED') {
        return { ok: false, errorCode: 'CHAIN_REJECTED', message: 'Cannot advance a rejected gate chain.' };
    }
    if (chain.status === 'COMPLETED') {
        return { ok: false, errorCode: 'CHAIN_ALREADY_COMPLETED', message: 'Gate chain is already completed.' };
    }

    const expectedGate = GATE_SEQUENCE[chain.gates.length];
    if (gateId !== expectedGate) {
        return {
            ok: false,
            errorCode: 'OUT_OF_ORDER_GATE',
            message: `Expected next gate "${expectedGate}", got "${gateId}". Skipping or repeating gates is forbidden.`,
        };
    }

    const cleanActor = String(actor || '').trim();
    if (!cleanActor) {
        return { ok: false, errorCode: 'MISSING_ACTOR', message: 'actor is required for audit attribution.' };
    }

    const cleanDecision = String(decision || '').trim().toUpperCase();
    if (!VALID_DECISIONS.has(cleanDecision)) {
        return { ok: false, errorCode: 'INVALID_DECISION', message: `Unsupported decision "${decision}".` };
    }

    const cleanWaiver = String(waiverReason || '').trim();
    if (cleanDecision === 'WAIVE' && !cleanWaiver) {
        return { ok: false, errorCode: 'MISSING_WAIVER_REASON', message: 'WAIVE decision requires a non-empty waiverReason.' };
    }

    if (payload === undefined || payload === null) {
        return { ok: false, errorCode: 'MISSING_PAYLOAD', message: 'payload is required to lock gate hash.' };
    }

    const payloadSha256 = typeof payload === 'string'
        ? sha256Hex(payload)
        : sha256Hex(canonicalJson(payload));

    const prevHash = chain.gates.length === 0
        ? GENESIS_HASH
        : chain.gates[chain.gates.length - 1].gate_hash;

    const gateHash = computeGateHash({
        prevHash,
        gateId,
        payloadSha256,
        actor: cleanActor,
        decision: cleanDecision,
        waiverReason: cleanWaiver,
    });

    const record = {
        index: chain.gates.length,
        gate_id: gateId,
        prev_hash: prevHash,
        payload_sha256: payloadSha256,
        actor: cleanActor,
        decision: cleanDecision,
        waiver_reason: cleanWaiver,
        gate_hash: gateHash,
        decided_at: timestamp || new Date().toISOString(),
    };

    const nextGates = [...chain.gates, record];
    let nextStatus = 'IN_PROGRESS';
    if (cleanDecision === 'REJECT') nextStatus = 'REJECTED';
    else if (nextGates.length === GATE_SEQUENCE.length) nextStatus = 'COMPLETED';

    return {
        ok: true,
        chain: {
            ...chain,
            status: nextStatus,
            gates: nextGates,
        },
        record,
    };
}

/**
 * Offline verifier for a 3-gate SHA-256 audit chain.
 */
export function verifyGateChain(chain) {
    if (!chain || chain.schema_version !== GATE_CHAIN_SCHEMA_VERSION || !Array.isArray(chain.gates)) {
        return {
            ok: false,
            verdict: 'INVALID_INPUT',
            errorCode: 'INVALID_CHAIN',
            mismatches: [{ code: 'INVALID_CHAIN_SCHEMA', message: 'Invalid gate chain schema.' }],
        };
    }
    if (chain.gates.length === 0) {
        return {
            ok: false,
            verdict: 'INVALID_INPUT',
            errorCode: 'EMPTY_CHAIN',
            mismatches: [{ code: 'EMPTY_CHAIN', message: 'Gate chain contains zero gates.' }],
        };
    }

    const mismatches = [];
    let expectedPrev = GENESIS_HASH;
    let sawReject = false;

    for (let i = 0; i < chain.gates.length; i += 1) {
        const g = chain.gates[i];
        const expectedGateId = GATE_SEQUENCE[i];

        if (sawReject) {
            mismatches.push({ index: i, code: 'ADVANCED_AFTER_REJECT', message: `Gate ${i} exists after a prior REJECT.` });
        }
        if (g.gate_id !== expectedGateId) {
            mismatches.push({ index: i, code: 'GATE_ORDER_TAMPERED', expected: expectedGateId, actual: g.gate_id });
        }
        if (g.prev_hash !== expectedPrev) {
            mismatches.push({ index: i, code: 'CHAIN_LINK_BROKEN', expected: expectedPrev, actual: g.prev_hash });
        }
        if (g.decision === 'WAIVE' && !String(g.waiver_reason || '').trim()) {
            mismatches.push({ index: i, code: 'MISSING_WAIVER_REASON', message: 'WAIVE gate is missing waiver_reason.' });
        }

        const recomputedHash = computeGateHash({
            prevHash: g.prev_hash,
            gateId: g.gate_id,
            payloadSha256: g.payload_sha256,
            actor: g.actor,
            decision: g.decision,
            waiverReason: g.waiver_reason,
        });
        if (g.gate_hash !== recomputedHash) {
            mismatches.push({ index: i, code: 'GATE_HASH_MISMATCH', expected: recomputedHash, actual: g.gate_hash });
        }

        if (g.decision === 'REJECT') sawReject = true;
        expectedPrev = g.gate_hash;
    }

    const complete = !sawReject && chain.gates.length === GATE_SEQUENCE.length;
    const valid = mismatches.length === 0;
    return {
        ok: valid,
        verified: valid,
        complete,
        verdict: !valid ? 'CHAIN_TAMPERED' : sawReject ? 'REJECTED' : complete ? 'COMPLETED_VERIFIED' : 'IN_PROGRESS_VERIFIED',
        run_id: chain.run_id,
        gateCount: chain.gates.length,
        headHash: chain.gates[chain.gates.length - 1].gate_hash,
        mismatches,
    };
}
