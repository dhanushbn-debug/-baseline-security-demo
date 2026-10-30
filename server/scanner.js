// server/scanner.js
// Scanner Agent: Runs fixed safe heuristics against bundled fixtures or authorized local targets.

import { SAMPLE_FIXTURES, getFixtureById } from './fixtures.js';
import { PREDEFINED_RULES, getRuleById } from './rules.js';

export function isTargetAuthorized(target) {
  if (!target) return false;
  const clean = target.trim().toLowerCase();
  if (clean.startsWith('bundled://fixtures/')) return true;
  if (clean.startsWith('http://localhost') || clean.startsWith('http://127.0.0.1')) return true;
  return false;
}

export async function runScannerAgent({ fixtureId, customTarget, onProgress }) {
  const fixture = getFixtureById(fixtureId);
  const target = fixture ? fixture.targetUri : (customTarget || '').trim();

  // Safety check: Strict authorized target enforcement
  if (!isTargetAuthorized(target)) {
    throw new Error(
      `Access Denied: Target "${target}" is not an authorized bundled fixture or local training target. Arbitrary internet scanning is disabled for safety.`
    );
  }

  const logs = [];
  function log(msg) {
    logs.push(msg);
    if (onProgress) onProgress({ agent: 'Scanner Agent', message: msg });
  }

  log(`[Scanner Agent] Initiating safe static scan on target: ${target}`);
  log(`[Scanner Agent] Mode: Fictional Baseline Simulation (No exploit execution).`);

  const candidateFindings = [];

  if (fixture) {
    log(`[Scanner Agent] Loading bundled fixture manifest: ${fixture.name}`);
    log(`[Scanner Agent] Found ${fixture.files.length} source file(s) in scope.`);

    for (const ruleId of fixture.candidateRules) {
      const rule = getRuleById(ruleId);
      if (!rule) continue;

      // Find corresponding file
      let matchedFile = fixture.files[0];
      if (rule.category === 'Security Headers' && fixture.files.length > 1) {
        matchedFile = fixture.files[0];
      } else if (rule.category === 'Rate Limiting & DoS' && fixture.files.length > 1) {
        matchedFile = fixture.files[1];
      }

      log(`[Scanner Agent] Running check ${rule.id} (${rule.name})... Pattern matched.`);

      candidateFindings.push({
        id: `find-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        ruleId: rule.id,
        title: rule.name,
        category: rule.category,
        cwe: rule.cwe,
        severity: rule.severity,
        confidence: rule.confidence,
        status: "Needs manual verification",
        targetFile: matchedFile.path,
        line: 15,
        evidence: matchedFile.snippet.slice(0, 300),
        whyMatched: rule.whyMatched,
        limitations: rule.limitations,
        genericRemediation: rule.genericRemediation,
        remediationType: rule.remediationType,
        verified: false,
        patchAvailable: false
      });
    }
  } else {
    // Local training target check
    log(`[Scanner Agent] Probing authorized local endpoint: ${target}`);
    const rule = getRuleById('RULE-SEC-005');
    candidateFindings.push({
      id: `find-${Date.now()}-local`,
      ruleId: rule.id,
      title: rule.name,
      category: rule.category,
      cwe: rule.cwe,
      severity: rule.severity,
      confidence: rule.confidence,
      status: "Needs manual verification",
      targetFile: "server/fixtures/local_mock.js",
      line: 12,
      evidence: "app.get('/fixture/status', (req, res) => { res.send({ status: 'ok', debug: true }); });",
      whyMatched: rule.whyMatched,
      limitations: rule.limitations,
      genericRemediation: rule.genericRemediation,
      remediationType: rule.remediationType,
      verified: false,
      patchAvailable: false
    });
  }

  log(`[Scanner Agent] Finished static scan pass. Discovered ${candidateFindings.length} candidate finding(s).`);
  log(`[Scanner Agent] Handing off raw candidate findings to Report Agent.`);

  return {
    candidateFindings,
    logs,
    rulesChecked: PREDEFINED_RULES.length
  };
}
