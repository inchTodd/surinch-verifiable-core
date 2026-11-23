const SUPPORTED_OPS = new Set(['sum', 'weighted_sum', 'count', 'count_where']);

function toFiniteNumber(val) {
    if (typeof val === 'boolean' || val === null || val === undefined || val === '') return NaN;
    const n = Number(val);
    return Number.isFinite(n) ? n : NaN;
}

/**
 * Deterministic summary-vs-detail reconciler (verify_recompute).
 * Uses integer scaling to avoid IEEE-754 decimal drift on financial sums and weighted scores.
 * Blocks build/delivery whenever summary != recomputed detail aggregation.
 */
export function verifyRecompute({ summary, details, rules } = {}) {
    if (!summary || typeof summary !== 'object' || Array.isArray(summary)) {
        return { ok: false, errorCode: 'INVALID_SUMMARY', verdict: 'INVALID_INPUT', message: 'summary must be a non-null object.' };
    }
    if (!Array.isArray(details) || details.length === 0) {
        return { ok: false, errorCode: 'EMPTY_DETAILS', verdict: 'INVALID_INPUT', message: 'details must be a non-empty array.' };
    }
    if (!Array.isArray(rules) || rules.length === 0) {
        return { ok: false, errorCode: 'EMPTY_RULES', verdict: 'INVALID_INPUT', message: 'rules must be a non-empty array.' };
    }

    const checks = [];
    const diffs = [];

    for (const rule of rules) {
        const op = String(rule?.op || '').trim().toLowerCase();
        const summaryKey = String(rule?.summaryKey || '').trim();
        const tolerance = rule?.tolerance == null ? 0 : toFiniteNumber(rule.tolerance);

        if (!summaryKey) {
            return { ok: false, errorCode: 'INVALID_RULE', verdict: 'INVALID_INPUT', message: 'Each rule requires summaryKey.' };
        }
        if (!SUPPORTED_OPS.has(op)) {
            return { ok: false, errorCode: 'UNSUPPORTED_OP', verdict: 'INVALID_INPUT', message: `Unsupported recompute op "${rule?.op}".` };
        }
        if (!Number.isFinite(tolerance) || tolerance < 0) {
            return { ok: false, errorCode: 'INVALID_TOLERANCE', verdict: 'INVALID_INPUT', message: `Invalid tolerance for "${summaryKey}".` };
        }

        const reported = toFiniteNumber(summary[summaryKey]);
        if (!Number.isFinite(reported)) {
            return {
                ok: false,
                errorCode: 'INVALID_SUMMARY_VALUE',
                verdict: 'INVALID_INPUT',
                message: `summary.${summaryKey} must be a finite number (got ${JSON.stringify(summary[summaryKey])}).`,
            };
        }

        let recomputed = 0;

        if (op === 'count') {
            recomputed = details.length;
        } else if (op === 'count_where') {
            const field = String(rule.detailField || '').trim();
            if (!field) {
                return { ok: false, errorCode: 'INVALID_RULE', verdict: 'INVALID_INPUT', message: `Rule "${summaryKey}" (count_where) requires detailField.` };
            }
            recomputed = details.filter((row) => row && row[field] === rule.equals).length;
        } else if (op === 'sum') {
            const field = String(rule.detailField || '').trim();
            if (!field) {
                return { ok: false, errorCode: 'INVALID_RULE', verdict: 'INVALID_INPUT', message: `Rule "${summaryKey}" (sum) requires detailField.` };
            }
            // Use integer scaling (1e6) to eliminate IEEE-754 decimal drift on financial sums
            let scaled = 0;
            for (let i = 0; i < details.length; i += 1) {
                const v = toFiniteNumber(details[i]?.[field]);
                if (!Number.isFinite(v)) {
                    return {
                        ok: false,
                        errorCode: 'INVALID_DETAIL_VALUE',
                        verdict: 'INVALID_INPUT',
                        message: `details[${i}].${field} is not a finite number.`,
                    };
                }
                scaled += Math.round(v * 1e6);
            }
            recomputed = scaled / 1e6;
        } else if (op === 'weighted_sum') {
            const valueField = String(rule.detailField || '').trim();
            const weightField = String(rule.weightField || '').trim();
            const weightScale = rule.weightScale == null ? 1 : toFiniteNumber(rule.weightScale);
            if (!valueField || !weightField || !Number.isFinite(weightScale) || weightScale <= 0) {
                return { ok: false, errorCode: 'INVALID_RULE', verdict: 'INVALID_INPUT', message: `Rule "${summaryKey}" (weighted_sum) requires detailField, weightField, and positive weightScale.` };
            }
            // Exact scaled integer accumulation eliminates IEEE-754 drift (e.g. 0.2 + 9.3 = 9.499999999999998)
            let scaledNumerator = 0;
            for (let i = 0; i < details.length; i += 1) {
                const v = toFiniteNumber(details[i]?.[valueField]);
                const w = toFiniteNumber(details[i]?.[weightField]);
                if (!Number.isFinite(v) || !Number.isFinite(w)) {
                    return {
                        ok: false,
                        errorCode: 'INVALID_DETAIL_VALUE',
                        verdict: 'INVALID_INPUT',
                        message: `details[${i}] has non-finite value/weight for "${summaryKey}".`,
                    };
                }
                scaledNumerator += Math.round(v * w * 1e6);
            }
            const exactTotal = scaledNumerator / (1e6 * weightScale);
            recomputed = rule.roundDigits != null
                ? Number(exactTotal.toFixed(rule.roundDigits))
                : Math.round(exactTotal);
        }

        if (rule.penalty != null) {
            const penalty = toFiniteNumber(rule.penalty);
            if (!Number.isFinite(penalty) || penalty < 0) {
                return { ok: false, errorCode: 'INVALID_RULE', verdict: 'INVALID_INPUT', message: `Rule "${summaryKey}" penalty must be a non-negative finite number.` };
            }
            recomputed -= penalty;
        }

        if (rule.clampMin != null) {
            const minVal = toFiniteNumber(rule.clampMin);
            if (Number.isFinite(minVal)) {
                recomputed = Math.max(minVal, recomputed);
            }
        }
        if (rule.clampMax != null) {
            const maxVal = toFiniteNumber(rule.clampMax);
            if (Number.isFinite(maxVal)) {
                recomputed = Math.min(maxVal, recomputed);
            }
        }

        const delta = Number(Math.abs(reported - recomputed).toFixed(6));
        const passed = delta <= tolerance;
        const entry = { summaryKey, op, reported, recomputed, delta, tolerance, passed };
        checks.push(entry);
        if (!passed) {
            diffs.push(entry);
        }
    }

    const allPassed = diffs.length === 0;
    return {
        ok: allPassed,
        verdict: allPassed ? 'RECOMPUTE_MATCH' : 'RECOMPUTE_MISMATCH',
        detailCount: details.length,
        ruleCount: rules.length,
        checks,
        diffs,
    };
}
