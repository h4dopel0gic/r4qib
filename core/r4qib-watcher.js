// ============================================================
// R4qib — Watcher v1.0
// On-chain event listener + pipeline orchestrator
//
// Listens for ScanComplete events from R4qibAgent.sol
// Picks up on-chain intelligence (exploit history, scope, briefing)
// Prepends context to DeepSeek analysis via r4qib-analyst.js
// Anchors findings back on-chain after human review
//
// Flow:
//   R4qibAgent.sol emits ScanComplete
//     → watcher picks up context
//     → fetches contract source via somnia-connector.js
//     → runs full analyst pipeline with on-chain context prepended
//     → saves report to reports/ (off-chain, sovereign)
//     → prompts human review
//     → anchors findings hash on-chain via anchorFindings()
//
// Human-in-the-Loop throughout. AI amplifies. Human decides.
// ============================================================

import { ethers }                  from 'ethers';
import { getProvider, fetchContractForAnalysis } from './somnia-connector.js';
import { analyseContract }          from './r4qib-analyst.js';
import fs                           from 'fs';
import crypto                       from 'crypto';
import readline                     from 'readline';

// ── Config ────────────────────────────────────────────────────

const CHAIN_KEY        = 'somnia-testnet';
const AGENT_ADDRESS    = process.env.R4QIB_AGENT_ADDRESS || '';
const SIGNER_KEY       = process.env.R4QIB_SIGNER_KEY   || '';

if (!AGENT_ADDRESS) throw new Error('R4QIB_AGENT_ADDRESS not set in environment');
if (!SIGNER_KEY)    throw new Error('R4QIB_SIGNER_KEY not set in environment');

// ── ABI (minimal — only what the watcher needs) ───────────────

const AGENT_ABI = [
  // Events
  'event ScanComplete(uint256 indexed scanId, address indexed target, string briefingSummary, bool scopeDegraded, uint256 timestamp)',
  'event ScanRequested(uint256 indexed scanId, address indexed target, uint256 timestamp)',
  'event FindingsAnchored(uint256 indexed scanId, address indexed target, string riskLevel, uint256 findingCount, bytes32 reportHash, uint256 timestamp)',

  // Read
  'function getScanIntelligence(uint256 scanId) view returns (address target, uint8 stage, bool scopeDegraded, string exploitHistory, string scopeData, string briefing, uint256 startedAt, uint256 completedAt)',
  'function getAnchoredFindings(uint256 scanId) view returns (string riskLevel, uint256 findingCount, bytes32 reportHash, bool anchored)',
  'function scanCount() view returns (uint256)',

  // Write
  'function requestScan(address target) returns (uint256 scanId)',
  'function anchorFindings(uint256 scanId, string riskLevel, uint256 findingCount, bytes32 reportHash)',
];

// ── Setup ─────────────────────────────────────────────────────

const provider = getProvider(CHAIN_KEY);
const signer   = new ethers.Wallet(SIGNER_KEY, provider);
const agent    = new ethers.Contract(AGENT_ADDRESS, AGENT_ABI, signer);

// ── Utility ───────────────────────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

function saveReport(scanId, target, report) {
  const dir = './reports';
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  const filename = `${dir}/scan-${scanId}-${target.slice(0, 8)}-${Date.now()}.json`;
  fs.writeFileSync(filename, JSON.stringify(report, null, 2));
  console.log(`\n   💾 Report saved: ${filename}`);
  return filename;
}

async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => {
    rl.close();
    resolve(answer.trim());
  }));
}

// ── Core Pipeline ─────────────────────────────────────────────

async function runAnalysisPipeline(scanId, target, onChainContext) {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`👁️  R4qib Pipeline — Scan #${scanId}`);
  console.log(`   Target        : ${target}`);
  console.log(`   Exploit hist  : ${onChainContext.exploitHistory?.slice(0, 80) || 'unavailable'}...`);
  console.log(`   Scope         : ${onChainContext.scopeDegraded ? '⚠️  degraded (two-agent mode)' : '✅ available'}`);
  console.log(`   Briefing      : ${onChainContext.briefing?.slice(0, 80) || 'unavailable'}...`);
  console.log(`${'═'.repeat(60)}`);

  // 1. Fetch contract source
  console.log('\n🔍 Fetching contract source...');
  const contract = await fetchContractForAnalysis(target, CHAIN_KEY);

  if (!contract.success) {
    console.log(`   ❌ Fetch failed: ${contract.error}`);
    return null;
  }

  if (!contract.hasSource) {
    console.log(`   ⚠️  Source not verified — limited analysis`);
  }

  // 2. Build context prefix from on-chain intelligence
  const contextPrefix = buildContextPrefix(onChainContext);

  // 3. Run full analyst pipeline with context
  console.log('\n🧠 Running DeepSeek analysis with on-chain context...');
  const findings = await analyseContract(contract, contextPrefix);

  // 4. Build full report
  const report = {
    scanId,
    target,
    chain: CHAIN_KEY,
    contractName: contract.name || 'Unknown',
    scannedAt: new Date().toISOString(),
    onChainContext: {
      exploitHistory: onChainContext.exploitHistory,
      scopeData:      onChainContext.scopeData,
      briefing:       onChainContext.briefing,
      scopeDegraded:  onChainContext.scopeDegraded,
    },
    findings,
    reportVersion: '1.0',
    analyst: 'DeepSeek Coder v2 Lite via LMStudio',
    humanReviewed: false,
    anchoredOnChain: false,
  };

  // 5. Save off-chain (sovereign — never goes on-chain)
  const filename = saveReport(scanId, target, report);
  report.reportFile = filename;

  return report;
}

function buildContextPrefix(ctx) {
  const lines = [
    '══ ON-CHAIN INTELLIGENCE (R4qib — Somnia Agent Pipeline) ══',
    '',
  ];

  if (ctx.exploitHistory && ctx.exploitHistory !== 'unavailable') {
    lines.push(`EXPLOIT HISTORY (DeFiLlama):`);
    lines.push(ctx.exploitHistory);
    lines.push('');
  }

  if (!ctx.scopeDegraded && ctx.scopeData) {
    lines.push(`PROTOCOL SCOPE (Immunefi):`);
    lines.push(ctx.scopeData);
    lines.push('');
  } else {
    lines.push(`PROTOCOL SCOPE: Unavailable (scope agent degraded gracefully)`);
    lines.push('');
  }

  if (ctx.briefing && ctx.briefing !== 'Briefing unavailable') {
    lines.push(`ADVERSARIAL BRIEFING (Qwen3-30B — chain-of-thought, consensus-validated):`);
    // Parse pipe-separated vectors
    const vectors = ctx.briefing.split('|').map(v => v.trim()).filter(Boolean);
    vectors.forEach((v, i) => lines.push(`  ${i + 1}. ${v}`));
    lines.push('');
  }

  lines.push('══ Use the above as priority attack surface context ══');
  lines.push('');

  return lines.join('\n');
}

// ── Human Review Gate ─────────────────────────────────────────

async function humanReviewGate(scanId, report) {
  console.log('\n' + '═'.repeat(60));
  console.log('  ⚠️  HUMAN REVIEW REQUIRED');
  console.log('  R4qib findings are for human review only.');
  console.log('  Verify all findings against source before any action.');
  console.log('═'.repeat(60));

  // Print summary
  const allFindings = report.findings?.flatMap(f => f.findings || []) || [];
  const bySeverity = ['Critical','High','Medium','Low','Informational'].map(s => ({
    severity: s,
    count: allFindings.filter(f => f.severity === s).length
  })).filter(s => s.count > 0);

  console.log('\n  📊 Finding Summary:');
  bySeverity.forEach(s => console.log(`     ${s.severity.padEnd(15)}: ${s.count}`));
  console.log(`     ${'Total'.padEnd(15)}: ${allFindings.length}`);
  console.log(`\n  📄 Report: ${report.reportFile}`);

  // Risk level input
  console.log('\n  Risk levels: Critical / High / Medium / Low / Informational / None');
  const riskLevel = await prompt('\n  Enter overall risk level after review: ');

  const validLevels = ['Critical','High','Medium','Low','Informational','None'];
  if (!validLevels.includes(riskLevel)) {
    console.log(`  ⚠️  Invalid risk level. Defaulting to "Informational".`);
    return { riskLevel: 'Informational', findingCount: allFindings.length };
  }

  const confirmedCount = parseInt(
    await prompt(`  Enter number of CONFIRMED findings (0–${allFindings.length}): `),
    10
  ) || 0;

  const anchor = await prompt('\n  Anchor findings on-chain? (yes/no): ');

  return {
    riskLevel,
    findingCount: confirmedCount,
    shouldAnchor: anchor.toLowerCase() === 'yes',
  };
}

// ── On-Chain Anchoring ────────────────────────────────────────

async function anchorFindings(scanId, report, riskLevel, findingCount) {
  console.log('\n⛓️  Anchoring findings on-chain...');

  // SHA-256 of the full report — links on-chain record to off-chain findings
  const hash    = sha256(report);
  const bytes32 = '0x' + hash;

  try {
    const tx = await agent.anchorFindings(
      scanId,
      riskLevel,
      findingCount,
      bytes32
    );
    console.log(`   📡 Transaction: ${tx.hash}`);
    await tx.wait();
    console.log(`   ✅ Findings anchored on-chain`);
    console.log(`   📋 Risk level  : ${riskLevel}`);
    console.log(`   📋 Findings    : ${findingCount} confirmed`);
    console.log(`   📋 Report hash : ${bytes32.slice(0, 18)}...`);

    // Update local report
    report.humanReviewed    = true;
    report.anchoredOnChain  = true;
    report.anchorTx         = tx.hash;
    report.reportHash       = bytes32;

    // Overwrite saved report with updated state
    fs.writeFileSync(report.reportFile, JSON.stringify(report, null, 2));
    console.log(`   💾 Report updated: ${report.reportFile}`);

  } catch (err) {
    console.error(`   ❌ Anchor failed: ${err.message}`);
  }
}

// ── Event Listener ────────────────────────────────────────────

async function startWatcher() {
  console.log('\n👁️  R4qib Watcher starting...');
  console.log(`   Agent contract : ${AGENT_ADDRESS}`);
  console.log(`   Chain          : ${CHAIN_KEY}`);
  console.log(`   Signer         : ${signer.address}`);
  console.log('\n   Listening for ScanComplete events...\n');

  agent.on('ScanComplete', async (scanId, target, briefingSummary, scopeDegraded, timestamp, event) => {
    console.log(`\n🔔 ScanComplete received — Scan #${scanId}`);
    console.log(`   Target        : ${target}`);
    console.log(`   Block         : ${event.log.blockNumber}`);

    try {
      // Fetch full on-chain context
      const intel = await agent.getScanIntelligence(scanId);

      const onChainContext = {
        exploitHistory: intel[3],
        scopeData:      intel[4],
        briefing:       intel[5],
        scopeDegraded:  intel[2],
      };

      // Run analysis pipeline
      const report = await runAnalysisPipeline(scanId, target, onChainContext);
      if (!report) return;

      // Human review gate
      const review = await humanReviewGate(scanId, report);

      // Anchor on-chain if human approves
      if (review.shouldAnchor) {
        await anchorFindings(scanId, report, review.riskLevel, review.findingCount);
      } else {
        console.log('\n   ℹ️  Anchoring skipped by researcher. Report saved locally.');
        report.humanReviewed = true;
        fs.writeFileSync(report.reportFile, JSON.stringify(report, null, 2));
      }

      console.log(`\n${'═'.repeat(60)}`);
      console.log(`  ✅ Scan #${scanId} complete`);
      console.log(`${'═'.repeat(60)}\n`);

    } catch (err) {
      console.error(`\n❌ Pipeline error for scan #${scanId}: ${err.message}`);
      console.error(err);
    }
  });

  // Also surface ScanRequested for visibility
  agent.on('ScanRequested', (scanId, target, timestamp) => {
    console.log(`\n📡 Scan #${scanId} initiated — ${target}`);
  });

  // Keep alive
  process.on('SIGINT', () => {
    console.log('\n\n👁️  R4qib Watcher stopped.\n');
    process.exit(0);
  });
}

// ── Convenience: trigger a scan from CLI ─────────────────────

export async function triggerScan(targetAddress) {
  console.log(`\n👁️  Requesting scan for: ${targetAddress}`);
  const tx = await agent.requestScan(targetAddress);
  console.log(`   📡 Transaction: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`   ✅ Scan requested — block ${receipt.blockNumber}`);
  return receipt;
}

// ── Entry Point ───────────────────────────────────────────────

startWatcher().catch(err => {
  console.error('Fatal watcher error:', err);
  process.exit(1);
});
