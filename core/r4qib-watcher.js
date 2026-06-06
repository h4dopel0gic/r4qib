// ============================================================
// R4qib — Watcher v1.3
// On-chain event listener + pipeline orchestrator
// Now with live dashboard integration via WebSocket
//
// Connects to r4qib-server.js as a client on ws://localhost:3001
// Pushes stage/log/finding events to dashboard in real time
// ============================================================

import 'dotenv/config';
import { ethers }                  from 'ethers';
import { getProvider, fetchContractForAnalysis } from './somnia-connector.js';
import { analyseContract, ACTIVE_CATEGORIES }    from './r4qib-analyst.js';
import { WebSocket }               from 'ws';
import fs                          from 'fs';
import crypto                      from 'crypto';
import readline                    from 'readline';

// ── Config ────────────────────────────────────────────────────

const CHAIN_KEY     = 'somnia-testnet';
const AGENT_ADDRESS = process.env.R4QIB_AGENT_ADDRESS || '';
const SIGNER_KEY    = process.env.R4QIB_SIGNER_KEY   || '';
const SERVER_URL    = 'ws://localhost:3001';

if (!AGENT_ADDRESS) throw new Error('R4QIB_AGENT_ADDRESS not set in environment');
if (!SIGNER_KEY)    throw new Error('R4QIB_SIGNER_KEY not set in environment');

// ── ABI ───────────────────────────────────────────────────────

const AGENT_ABI = [
  'event ScanComplete(uint256 indexed scanId, address indexed target, string briefingSummary, bool scopeDegraded, uint256 timestamp)',
  'event ScanRequested(uint256 indexed scanId, address indexed target, uint256 timestamp)',
  'event FindingsAnchored(uint256 indexed scanId, address indexed target, string riskLevel, uint256 findingCount, bytes32 reportHash, uint256 timestamp)',
  'function getScanIntelligence(uint256 scanId) view returns (address target, uint8 stage, bool scopeDegraded, string exploitHistory, string scopeData, string briefing, uint256 startedAt, uint256 completedAt)',
  'function getAnchoredFindings(uint256 scanId) view returns (string riskLevel, uint256 findingCount, bytes32 reportHash, bool anchored)',
  'function scanCount() view returns (uint256)',
  'function requestScan(address target) returns (uint256 scanId)',
  'function anchorFindings(uint256 scanId, string riskLevel, uint256 findingCount, bytes32 reportHash)',
];

// ── Setup ─────────────────────────────────────────────────────

const provider = getProvider(CHAIN_KEY);
const signer   = new ethers.Wallet(SIGNER_KEY, provider);
const agent    = new ethers.Contract(AGENT_ADDRESS, AGENT_ABI, signer);

// ── Dashboard Bridge ──────────────────────────────────────────

let dashboardWs = null;

function connectDashboard() {
  try {
    dashboardWs = new WebSocket(SERVER_URL);

    dashboardWs.on('open', () => {
      console.log('   📺 Dashboard bridge connected');
    });

    dashboardWs.on('close', () => {
      console.log('   📺 Dashboard bridge disconnected — will retry in 5s');
      dashboardWs = null;
      setTimeout(connectDashboard, 5000);
    });

    dashboardWs.on('error', () => {
      // Server not running — silent retry
      dashboardWs = null;
    });
  } catch {
    dashboardWs = null;
  }
}

function dashSend(type, data = {}) {
  if (dashboardWs?.readyState === WebSocket.OPEN) {
    try {
      // Send via relay protocol — server broadcasts to all dashboard clients
      dashboardWs.send(JSON.stringify({
        type: 'watcher_relay',
        relayType: type,
        relayData: { ...data, ts: Date.now() }
      }));
    } catch { /* silent */ }
  }
}

function dashLog(message, tag = 'info') {
  dashSend('log', { tag, message });
  console.log(`   [${tag.toUpperCase()}] ${message}`);
}

function dashStage(id, state) {
  dashSend('stage', { id, state });
}

function dashFinding(data) {
  dashSend('finding', data);
}

// ── Utility ───────────────────────────────────────────────────

const bigintReplacer = (key, value) =>
  typeof value === 'bigint' ? value.toString() : value;

function sha256(data) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(data, bigintReplacer))
    .digest('hex');
}

function saveReport(scanId, target, report) {
  const dir = './reports';
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  const filename = `${dir}/scan-${scanId}-${target.slice(0, 8)}-${Date.now()}.json`;
  fs.writeFileSync(filename, JSON.stringify(report, bigintReplacer, 2));
  console.log(`\n   💾 Report saved: ${filename}`);
  return filename;
}

function writeReport(filepath, report) {
  fs.writeFileSync(filepath, JSON.stringify(report, bigintReplacer, 2));
}

async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => {
    rl.close();
    resolve(answer.trim());
  }));
}

// ── Findings normaliser ───────────────────────────────────────

function flattenFindings(results) {
  if (!results) return [];
  if (!Array.isArray(results)) return [];
  const flat = [];
  for (const item of results) {
    if (!item) continue;
    if (Array.isArray(item.findings)) flat.push(...item.findings);
    else if (item.severity || item.title) flat.push(item);
  }
  return flat;
}

// ── Core Pipeline ─────────────────────────────────────────────

async function runAnalysisPipeline(scanId, target, onChainContext) {
  const scanIdStr = scanId.toString();

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`👁️  R4qib Pipeline — Scan #${scanIdStr}`);
  console.log(`   Target   : ${target}`);
  console.log(`${'═'.repeat(60)}`);

  // Notify dashboard — scan starting
  dashSend('scan_start', {
    scanId:     scanIdStr,
    address:    target,
    chain:      'somnia-testnet',
    targetName: `Scan #${scanIdStr} — ${target.slice(0, 10)}...`,
  });

  dashStage('stage-idle', 'complete');

  // Show on-chain intelligence in dashboard
  dashLog(`Somnia agent pipeline complete — Scan #${scanIdStr}`, 'agent');
  dashLog(`Exploit history: ${onChainContext.exploitHistory || 'unavailable'}`, 'agent');

  if (onChainContext.scopeDegraded) {
    dashLog('Scope data: unavailable (two-agent mode)', 'warn');
  } else {
    dashLog(`Scope data received`, 'agent');
  }

  if (onChainContext.briefing && onChainContext.briefing !== 'Briefing unavailable') {
    dashLog(`Adversarial briefing (Qwen3-30B):`, 'reason');
    onChainContext.briefing.split('|').map(v => v.trim()).filter(Boolean)
      .forEach((v, i) => dashLog(`  ${i + 1}. ${v}`, 'reason'));
  } else {
    dashLog('Briefing: unavailable', 'warn');
  }

  // Stage 4 — analysis
  dashStage('stage-4', 'active');
  dashLog(`Fetching contract source from Somnia testnet...`, 'info');

  // Build context prefix
  const contextPrefix = buildContextPrefix(onChainContext);

  // Run analyst — pass target address + chain + contextPrefix
  dashLog(`Running DeepSeek — ${ACTIVE_CATEGORIES.length} vulnerability categories`, 'info');

  let rawResults;
  try {
    const analysisChain = process.env.R4QIB_CHAIN || 'ethereum-mainnet';
	rawResults = await analyseContract(target, analysisChain, undefined, contextPrefix);
  } catch (err) {
    dashLog(`Analysis error: ${err.message}`, 'error');
    dashStage('stage-4', 'failed');
    rawResults = [];
  }

  const allFindings = flattenFindings(rawResults);

  // Stream findings to dashboard
  allFindings.forEach(f => {
    dashFinding({
      severity:    f.severity,
      title:       f.title,
      location:    f.location,
      description: f.description,
      category:    f.category,
      swc:         f.swc,
      confidence:  f.confidence,
    });
  });

  dashStage('stage-4', 'complete');
  dashStage('stage-5', 'active');

  const overallRisk = allFindings.some(f => f.severity === 'Critical') ? 'Critical'
    : allFindings.some(f => f.severity === 'High') ? 'High'
    : allFindings.length > 0 ? 'Medium' : 'Low';

  dashLog(`Analysis complete — ${allFindings.length} finding(s) | Risk: ${overallRisk}`,
    overallRisk === 'Critical' || overallRisk === 'High' ? 'warn' : 'success');
  dashLog('Human review required', 'human');

  // Build report
  const report = {
    scanId:       scanIdStr,
    target,
    chain:        CHAIN_KEY,
    scannedAt:    new Date().toISOString(),
    onChainContext: {
      exploitHistory: onChainContext.exploitHistory,
      scopeData:      onChainContext.scopeData,
      briefing:       onChainContext.briefing,
      scopeDegraded:  onChainContext.scopeDegraded,
    },
    findings:        allFindings,
    rawResults,
    overallRisk,
    totalFindings:   allFindings.length,
    reportVersion:   '1.3',
    analyst:         'DeepSeek via LMStudio',
    humanReviewed:   false,
    anchoredOnChain: false,
  };

  const filename = saveReport(scanId, target, report);
  report.reportFile = filename;

  dashSend('scan_complete', {
    scanId:        scanIdStr,
    address:       target,
    overallRisk,
    totalFindings: allFindings.length,
  });

  return report;
}

function buildContextPrefix(ctx) {
  const lines = [
    '══ ON-CHAIN INTELLIGENCE (R4qib — Somnia Agent Pipeline) ══',
    '',
  ];
  if (ctx.exploitHistory && ctx.exploitHistory !== 'unavailable') {
    lines.push('EXPLOIT HISTORY (DeFiLlama):');
    lines.push(ctx.exploitHistory);
    lines.push('');
  }
  if (!ctx.scopeDegraded && ctx.scopeData) {
    lines.push('PROTOCOL SCOPE (Immunefi):');
    lines.push(ctx.scopeData);
    lines.push('');
  } else {
    lines.push('PROTOCOL SCOPE: Unavailable (scope agent degraded gracefully)');
    lines.push('');
  }
  if (ctx.briefing && ctx.briefing !== 'Briefing unavailable') {
    lines.push('ADVERSARIAL BRIEFING (Qwen3-30B — chain-of-thought, consensus-validated):');
    ctx.briefing.split('|').map(v => v.trim()).filter(Boolean)
      .forEach((v, i) => lines.push(`  ${i + 1}. ${v}`));
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
  console.log('  Verify all findings against source before any action.');
  console.log('═'.repeat(60));

  const allFindings = report.findings || [];

  console.log('\n  📊 Finding Summary:');
  if (allFindings.length === 0) {
    console.log('     No structured findings (bytecode-only scan or clean contract)');
  } else {
    ['Critical','High','Medium','Low','Informational'].forEach(s => {
      const count = allFindings.filter(f => f.severity === s).length;
      if (count > 0) console.log(`     ${s.padEnd(15)}: ${count}`);
    });
  }
  console.log(`     ${'Total'.padEnd(15)}: ${allFindings.length}`);
  console.log(`\n  📄 Report: ${report.reportFile}`);

  console.log('\n  Risk levels: Critical / High / Medium / Low / Informational / None');
  const riskInput = await prompt('\n  Enter overall risk level after review: ');
  const validLevels = ['Critical','High','Medium','Low','Informational','None'];
  const riskLevel = validLevels.includes(riskInput) ? riskInput : 'Informational';
  if (riskLevel !== riskInput) console.log('  ⚠️  Invalid — defaulting to "Informational".');

  const confirmedCount = parseInt(
    await prompt(`  Enter number of CONFIRMED findings (0–${allFindings.length}): `), 10
  ) || 0;

  const anchor = await prompt('\n  Anchor findings on-chain? (yes/no): ');

  // Update dashboard stage
  dashStage('stage-5', 'complete');
  if (anchor.toLowerCase() === 'yes') {
    dashStage('stage-6', 'active');
  }

  return {
    riskLevel,
    findingCount: confirmedCount,
    shouldAnchor: anchor.toLowerCase() === 'yes',
  };
}

// ── On-Chain Anchoring ────────────────────────────────────────

async function anchorFindingsOnChain(scanId, report, riskLevel, findingCount) {
  console.log('\n⛓️  Anchoring findings on-chain...');
  dashLog('Anchoring findings on-chain...', 'agent');

  const hash    = sha256(report);
  const bytes32 = '0x' + hash;

  try {
    const tx = await agent.anchorFindings(scanId, riskLevel, findingCount, bytes32);
    console.log(`   📡 Transaction: ${tx.hash}`);
    dashLog(`Anchor tx: ${tx.hash}`, 'agent');
    await tx.wait();

    console.log(`   ✅ Findings anchored`);
    dashLog(`✅ Findings anchored on-chain — ${riskLevel} | ${findingCount} confirmed`, 'success');
    dashStage('stage-6', 'complete');

    report.humanReviewed   = true;
    report.anchoredOnChain = true;
    report.anchorTx        = tx.hash;
    report.reportHash      = bytes32;
    writeReport(report.reportFile, report);
    console.log(`   💾 Report updated: ${report.reportFile}`);
  } catch (err) {
    console.error(`   ❌ Anchor failed: ${err.message}`);
    dashLog(`Anchor failed: ${err.message}`, 'error');
    dashStage('stage-6', 'failed');
  }
}

// ── Event Listener ────────────────────────────────────────────

async function startWatcher() {
  console.log('\n👁️  R4qib Watcher v1.3 starting...');
  console.log(`   Agent contract : ${AGENT_ADDRESS}`);
  console.log(`   Chain          : ${CHAIN_KEY}`);
  console.log(`   Signer         : ${signer.address}`);
  console.log(`   Dashboard      : ${SERVER_URL}`);
  console.log('\n   Listening for ScanComplete events...\n');

  // Try to connect to dashboard (optional — watcher works without it)
  connectDashboard();

  agent.on('ScanComplete', async (scanId, target, briefingSummary, scopeDegraded, timestamp, event) => {
    console.log(`\n🔔 ScanComplete received — Scan #${scanId}`);
    console.log(`   Target : ${target}`);
    console.log(`   Block  : ${event.log.blockNumber}`);

    try {
      const intel = await agent.getScanIntelligence(scanId);
      const onChainContext = {
        exploitHistory: intel[3],
        scopeData:      intel[4],
        briefing:       intel[5],
        scopeDegraded:  intel[2],
      };

      const report = await runAnalysisPipeline(scanId, target, onChainContext);
      if (!report) return;

      const review = await humanReviewGate(scanId, report);

      if (review.shouldAnchor) {
        await anchorFindingsOnChain(scanId, report, review.riskLevel, review.findingCount);
      } else {
        console.log('\n   ℹ️  Anchoring skipped. Report saved locally.');
        dashLog('Anchoring skipped by researcher. Report saved locally.', 'info');
        dashStage('stage-5', 'complete');
        report.humanReviewed = true;
        writeReport(report.reportFile, report);
      }

      console.log(`\n${'═'.repeat(60)}`);
      console.log(`  ✅ Scan #${scanId} complete`);
      console.log(`${'═'.repeat(60)}\n`);

    } catch (err) {
      console.error(`\n❌ Pipeline error for scan #${scanId}: ${err.message}`);
      console.error(err);
      dashLog(`Pipeline error: ${err.message}`, 'error');
    }
  });

  agent.on('ScanRequested', (scanId, target) => {
    console.log(`\n📡 Scan #${scanId} initiated — ${target}`);
    dashLog(`Scan #${scanId} initiated on Somnia testnet`, 'agent');
    dashStage('stage-1', 'active');
  });

  process.on('SIGINT', () => {
    console.log('\n\n👁️  R4qib Watcher stopped.\n');
    process.exit(0);
  });
}

// ── Trigger Scan (CLI) ────────────────────────────────────────

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
