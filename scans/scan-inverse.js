// ============================================================
// R4qib — Inverse Finance Scan
// Live Immunefi programme: $100k max critical
// Target: Freshest in-scope contracts (address-based, Path A)
// Chain: Ethereum mainnet
//
// EXPLOIT HISTORY — what to look for:
// April 2022: $15.6M — INV price oracle manipulation via SushiSwap
// June 2022:  $1.2M  — LP token price oracle manipulation (Curve pool)
// Both exploits: oracle price derived from manipulable on-chain source
// Fix: moved to Chainlink feeds
// Attacker angle: check if any NEW markets/feeds still use
// manipulable on-chain price sources, or if Chainlink integration
// has edge cases (stale price, fallback logic, aggregator trust)
//
// PRIORITY TARGETS (freshest, least audited):
// 1. PSMFed v2           — added Dec 30 2025 (5 months old)
// 2. DOLA PSM v2         — added Dec 30 2025 (5 months old)
// 3. CurveDolaLPHelper v2 — added Jul 2 2025 (10 months old)
// ============================================================

import { fetchContractForAnalysis } from './somnia-connector.js';
import { analyseCategory, ACTIVE_CATEGORIES } from './r4qib-analyst.js';
import fs from 'fs';

// ── Ethereum mainnet chain config ─────────────────────────────
// We add ETH mainnet to the connector inline here
// Full address from Etherscan (expanding the truncated Immunefi addresses)
const TARGETS = [
  {
    name: 'PSMFed v2',
    address: '0x67fC2c1e4bA1244D89A0E960aA9B4B3F7FA69Fcc',
    chainKey: 'ethereum-mainnet',
    addedToScope: '2025-12-30',
    notes: 'Peg Stability Module Fed v2. Newest contract. Controls DOLA minting via PSM. High value target.',
    attackAngle: 'PSM peg mechanics, fee calculation, access control on mint/burn, oracle price bounds'
  },
  {
    name: 'DOLA PSM v2',
    address: '0x1d0218A2F9ADa55D3c9Cb7bC67E89D7Ed9290dfa',
    chainKey: 'ethereum-mainnet',
    addedToScope: '2025-12-30',
    notes: 'DOLA Peg Stability Module v2. Newest contract. Direct DOLA/stablecoin swap mechanism.',
    attackAngle: 'Rounding in swap calculations, slippage, fee extraction, reserve accounting'
  },
  {
    name: 'FiRM CurveDolaLPHelper v2',
    address: '0x8084d0b5Ee6Ac4a34C14B5D1Ff9A08eF1aF8F5E0',
    chainKey: 'ethereum-mainnet',
    addedToScope: '2025-07-02',
    notes: 'LP helper for Curve DOLA pools. v2 = updated logic. LP price manipulation is their historical weakness.',
    attackAngle: 'LP token pricing, Curve pool interaction, slippage, reentrancy via Curve callbacks'
  }
];

// Categories tuned for Inverse Finance's known vulnerability profile
// Oracle manipulation is their #1 historical weakness
// Logic errors in accounting is #2
const SCAN_CATEGORIES = ACTIVE_CATEGORIES.filter(c =>
  ['logic_errors', 'flash_loan', 'intent_mismatch', 'access_control'].includes(c.id)
);

console.log('\n👁️  R4qib — Inverse Finance Scan');
console.log('   Programme  : Immunefi — $100k max critical');
console.log('   Strategy   : Freshest contracts + oracle bypass angle');
console.log('   Categories : logic_errors, flash_loan, intent_mismatch, access_control');
console.log('   Started    :', new Date().toISOString());
console.log('\n📚 EXPLOIT HISTORY CONTEXT:');
console.log('   Apr 2022: $15.6M — INV oracle manipulation (SushiSwap spot price)');
console.log('   Jun 2022: $1.2M  — LP token oracle manipulation (Curve pool balance)');
console.log('   Pattern : on-chain price source manipulable via flash loan');
console.log('   Fix     : moved to Chainlink. Watch for: stale fallback, new markets');
console.log('   Angle   : do any new PSM or LP contracts trust manipulable sources?\n');

const allResults = [];

for (const target of TARGETS) {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`📄 Target: ${target.name}`);
  console.log(`   Address     : ${target.address}`);
  console.log(`   In scope    : ${target.addedToScope}`);
  console.log(`   Attack angle: ${target.attackAngle}`);
  console.log(`   Note        : ${target.notes}`);

  // Fetch source via Etherscan API
  const contract = await fetchContractForAnalysis(target.address, target.chainKey);

  if (!contract.success) {
    console.log(`   ❌ Fetch failed: ${contract.error}`);
    allResults.push({ ...target, error: contract.error });
    continue;
  }

  if (!contract.hasSource) {
    console.log(`   ⚠️  Source not verified on Etherscan — skipping`);
    allResults.push({ ...target, error: 'Source not verified' });
    continue;
  }

  console.log(`   ✅ Source: ${contract.name} (${contract.bytecodeSize} bytes, ${contract.sourceCode?.split('\n').length} lines)`);

  const contractResults = {
    name: target.name,
    address: target.address,
    contractName: contract.name,
    sourceLines: contract.sourceCode?.split('\n').length,
    scannedAt: new Date().toISOString(),
    attackAngle: target.attackAngle,
    findings: []
  };

  for (const category of SCAN_CATEGORIES) {
    const result = await analyseCategory(contract.sourceCode, category, contract.name);
    contractResults.findings.push(result);

    const icon = result.vulnerable ? '⚠️ ' : '✅';
    console.log(`\n   ${icon} ${category.name}`);
    console.log(`      Vulnerable : ${result.vulnerable}`);
    console.log(`      Confidence : ${result.confidence}`);
    console.log(`      Findings   : ${result.findings?.length || 0}`);

    if (result.findings?.length) {
      for (const f of result.findings) {
        console.log(`\n      → [${f.severity}] ${f.title}`);
        console.log(`        Location   : ${f.location}`);
        console.log(`        Attack     : ${f.attack_scenario?.slice(0, 150)}...`);
        console.log(`        Fix        : ${f.remediation?.slice(0, 100)}...`);
        console.log(`        Confidence : ${f.confidence}`);
      }
    }
  }

  allResults.push(contractResults);

  // Save after each contract
  const filename = `r4qib-inverse-${Date.now()}.json`;
  fs.writeFileSync(filename, JSON.stringify(allResults, null, 2));
  console.log(`\n   💾 Saved: ${filename}`);
}

// Final summary
console.log(`\n${'═'.repeat(60)}`);
console.log('  R4qib — INVERSE FINANCE SCAN COMPLETE');
console.log(`${'═'.repeat(60)}`);
console.log(`  Completed  : ${new Date().toISOString()}`);
console.log(`  Contracts  : ${allResults.filter(r => !r.error).length}/${TARGETS.length}`);

const allFindings = allResults
  .flatMap(r => r.findings || [])
  .flatMap(f => f.findings || []);

['Critical','High','Medium','Low','Informational'].forEach(s => {
  const n = allFindings.filter(f => f.severity === s).length;
  if (n > 0) console.log(`  ${s.padEnd(15)}: ${n}`);
});

console.log(`  Total      : ${allFindings.length}`);
console.log('\n⚠️  Human review required. Verify against source before any submission.');
console.log(`${'═'.repeat(60)}\n`);
