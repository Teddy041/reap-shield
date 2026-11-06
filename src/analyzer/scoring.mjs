/**
 * Threat scoring. Findings are weighted by severity, repeated hits of the same
 * rule have diminishing returns, and the sum saturates smoothly into 0..100.
 */
import { SEVERITY_WEIGHT, SEVERITIES } from './config.mjs';

export const LEVELS = ['Low', 'Medium', 'High', 'Critical'];

/**
 * @param {Array<{id:string, severity:string, category:string}>} findings
 * @param {{trustedSignature?: boolean}} ctx
 */
export function scoreFindings(findings, ctx = {}) {
  const byRule = new Map();
  for (const f of findings) {
    const key = f.ruleId ?? f.id;
    const entry = byRule.get(key) ?? { severity: f.severity, n: 0 };
    entry.n += 1;
    if (SEVERITIES.indexOf(f.severity) > SEVERITIES.indexOf(entry.severity)) entry.severity = f.severity;
    byRule.set(key, entry);
  }
  let raw = 0;
  let criticalRules = 0;
  let highRules = 0;
  for (const { severity, n } of byRule.values()) {
    const w = SEVERITY_WEIGHT[severity] ?? 0;
    raw += w * Math.min(2, 1 + 0.25 * (n - 1));
    if (severity === 'critical') criticalRules += 1;
    if (severity === 'high') highRules += 1;
  }
  // A valid, trusted signature lowers non-critical risk, but never hides critical behaviour.
  if (ctx.trustedSignature && criticalRules === 0) raw *= 0.45;

  const score = Math.round(100 * (1 - Math.exp(-raw / 70)));
  let level = score < 20 ? 'Low' : score < 45 ? 'Medium' : score < 70 ? 'High' : 'Critical';
  if (criticalRules >= 1 && LEVELS.indexOf(level) < 2) level = 'High';
  if (criticalRules >= 2) level = 'Critical';
  if (highRules >= 3 && LEVELS.indexOf(level) < 2 && !ctx.trustedSignature) level = 'High';
  return { score, level, rawWeight: Math.round(raw), criticalRules, highRules };
}

export function summarise(level, findings) {
  const notable = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  if (findings.length === 0 || findings.every((f) => f.severity === 'info')) {
    return 'No suspicious behaviour was identified by static analysis. This does not prove the file is safe.';
  }
  const lead = {
    Low: 'Only weak indicators were found.',
    Medium: 'Some suspicious capabilities were found that deserve a manual review.',
    High: 'Multiple strong indicators of malicious or high-risk behaviour were found.',
    Critical: 'The file shows behaviour strongly associated with malware. Do not run it.',
  }[level];
  const top = notable.slice(0, 3).map((f) => f.title);
  return top.length ? `${lead} Key reasons: ${top.join('; ')}.` : lead;
}
