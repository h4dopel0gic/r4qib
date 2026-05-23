// ============================================================
// R4qib — Server v1.0
// WebSocket bridge between dashboard UI and analysis pipeline
//
// Listens on ws://localhost:3001
// Receives scan requests from the dashboard
// Streams real-time events back to the UI
// Runs full analyseContract() pipeline per request
//
// Usage: node core/r4qib-server.js
// Then open assets/r4qib-dashboard.html in browser
//
// Human-in-the-Loop throughout. AI amplifies. Human decides.
// ============================================================

import { WebSocketServer, WebSocket } from 'ws';
import { analyseContract, ACTIVE_CATEGORIES } from './r4qib-analyst.js';
import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT      = 3001;
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

// ── Ensure reports dir exists ─────────────────────────────────
if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR);

// ── WebSocket Server ──────────────────────────────────────────
const wss = new WebSocketServer({ port: PORT });

console.log(`\n👁️  R4qib Server v1.0`);
console.log(`   WebSocket : ws://localhost:${PORT}`);
console.log(`   Reports   : ${REPORTS_DIR}`);
console.log(`   Pipeline  : ${ACTIVE_CATEGORIES.length} active categories`);
console.log(`\n   Waiting for dashboard connection...\n`);

// Track active scan per client so we don't double-fire
const activeScans = new Map();

wss.on('connection', (ws) => {
  console.log(`[+] Dashboard connected`);

  // Send immediate status
  send(ws, 'status', {
    online: true,
    categories: ACTIVE_CATEGORIES.length,
    version: '1.0',
    message: 'R4qib server online — ready to scan'
  });

  ws.on('message', async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      send(ws, 'error', { message: 'Invalid message format' });
      return;
    }

    switch (msg.type) {
      case 'ping':
        send(ws, 'pong', { ts: Date.now() });
        break;

      case 'scan':
        await handleScan(ws, msg);
        break;

      case 'cancel':
        send(ws, 'log', { tag: 'warn', message: 'Scan cancellation requested — pipeline will complete current category' });
        break;

      default:
        send(ws, 'error', { message: `Unknown message type: ${msg.type}` });
    }
  });

  ws.on('close', () => {
    console.log(`[-] Dashboard disconnected`);
    activeScans.delete(ws);
  });

  ws.on('error', (err) => {
    console.error(`[!] WebSocket error: ${err.message}`);
  });
});

// ── Scan Handler ──────────────────────────────────────────────

async function handleScan(ws, msg) {
  const { address, chain, targetName, notes, attackAngle } = msg;

  if (!address || !address.startsWith('0x')) {
    send(ws, 'error', { message: 'Invalid contract address' });
    return;
  }

  if (activeScans.get(ws)) {
    send(ws, 'error', { message: 'Scan already in progress — wait for completion' });
    return;
  }

  activeScans.set(ws, true);

  const scanId   = Date.now();
  const chainKey = chain || 'somnia-testnet';

  // ── Broadcast helpers ───────────────────────────────────────
  const log     = (message, tag = 'info') => send(ws, 'log',   { tag, message });
  const stage   = (id, state)             => send(ws, 'stage', { id, state });
  const finding = (data)                  => send(ws, 'finding', data);
  const intel   = (key, value)            => send(ws, 'intel',  { key, value });

  // ── Start ───────────────────────────────────────────────────
  send(ws, 'scan_start', { scanId, address, chain: chainKey, targetName });

  stage('stage-idle', 'complete');
  stage('stage-4',    'active');

  log(`Scan #${scanId} initiated`, 'info');
  log(`Target: ${targetName || address}`, 'info');
  log(`Address: ${address}`, 'info');
  log(`Chain: ${chainKey}`, 'info');
  if (notes)       log(`Note: ${notes}`, 'info');
  if (attackAngle) log(`Attack angle: ${attackAngle}`, 'reason');

  // ── On-chain context (if Somnia — placeholder for live pipeline) ──
  // For non-Somnia chains: skip agent calls, go straight to analysis
  // For Somnia: the watcher handles agent calls and fires events back
  const isSomnia = chainKey.startsWith('somnia');

  if (isSomnia) {
    log(`Somnia chain detected — on-chain agent pipeline active`, 'agent');
    log(`Note: R4qibAgent.sol handles DeFiLlama + Immunefi + Qwen3-30B agents`, 'agent');
    log(`Deploy contract and fund wallet to activate full pipeline`, 'warn');
    log(`Proceeding with off-chain analysis only for now...`, 'info');
  } else {
    log(`EVM chain — off-chain analysis pipeline`, 'info');
    log(`On-chain intelligence: not available on ${chainKey}`, 'info');
    log(`Deploy to Somnia for full three-agent context layer`, 'info');
  }

  // ── DeepSeek Analysis ────────────────────────────────────────
  log(`Fetching contract source via Blockscout/Etherscan...`, 'info');

  let result;
  try {
    // Patch analyseContract to emit per-category progress
    result = await analyseContractWithProgress(
      address, chainKey, ACTIVE_CATEGORIES, ws, { log, stage, finding, intel }
    );
  } catch (err) {
    log(`Analysis error: ${err.message}`, 'error');
    stage('stage-4', 'failed');
    send(ws, 'scan_error', { scanId, error: err.message });
    activeScans.delete(ws);
    return;
  }

  if (!result.success) {
    log(`Fetch failed: ${result.error}`, 'error');
    stage('stage-4', 'failed');
    send(ws, 'scan_error', { scanId, error: result.error });
    activeScans.delete(ws);
    return;
  }

  // ── Save report ───────────────────────────────────────────────
  const reportFile = path.join(
    REPORTS_DIR,
    `scan-${scanId}-${address.slice(0,8)}.json`
  );
  const report = { ...result, scanId, targetName, notes, attackAngle };
  fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
  log(`Report saved: ${path.basename(reportFile)}`, 'success');

  // ── Complete ──────────────────────────────────────────────────
  stage('stage-4', 'complete');
  stage('stage-5', 'active');

  send(ws, 'scan_complete', {
    scanId,
    address,
    contractName:  result.contractName,
    overallRisk:   result.overallRisk,
    totalFindings: result.totalFindings,
    reportFile:    path.basename(reportFile),
  });

  log(`Analysis complete — ${result.totalFindings} findings`, 'success');
  log(`Overall risk: ${result.overallRisk}`, result.overallRisk === 'Critical' || result.overallRisk === 'High' ? 'warn' : 'success');
  log(`Human review required before any submission`, 'human');

  activeScans.delete(ws);
}

// ── Analysis with per-category progress streaming ─────────────

async function analyseContractWithProgress(address, chainKey, categories, ws, { log, stage, finding }) {
  const { fetchContractForAnalysis } = await import('./somnia-connector.js');
  const { analyseCategory }          = await import('./r4qib-analyst.js');

  // Fetch contract
  log(`Connecting to ${chainKey}...`, 'agent');
  const contract = await fetchContractForAnalysis(address, chainKey);

  if (!contract.success) return { success: false, error: contract.error };

  if (!contract.hasSource) {
    return {
      success: false,
      error: `Source not verified on explorer. Analysis requires verified Solidity source.`,
    };
  }

  log(`Source verified — ${contract.name} (${contract.bytecodeSize} bytes)`, 'success');
  log(`Running ${categories.length} vulnerability categories...`, 'info');

  const results = [];
  let totalFindings = 0;

  for (let i = 0; i < categories.length; i++) {
    const cat = categories[i];
    log(`[${i+1}/${categories.length}] ${cat.name} (${cat.swc})...`, 'agent');

    const result = await analyseCategory(contract.sourceCode, cat, contract.name);
    results.push(result);

    const count = result.findings?.length || 0;
    totalFindings += count;

    if (result.vulnerable && count > 0) {
      log(`${cat.name}: ${count} finding(s)`, 'warn');
      // Stream each finding to dashboard as it arrives
      result.findings.forEach(f => {
        finding({
          severity:    f.severity,
          title:       f.title,
          location:    f.location,
          description: f.description,
          category:    cat.name,
          swc:         cat.swc,
          confidence:  f.confidence,
        });
      });
    } else {
      log(`${cat.name}: clean`, 'success');
    }
  }

  // Build summary
  const severities       = results.flatMap(r => r.findings?.map(f => f.severity) || []);
  const hasCritical      = severities.includes('Critical');
  const hasHigh          = severities.includes('High');
  const vulnerableCount  = results.filter(r => r.vulnerable === true).length;
  const overallRisk      = hasCritical ? 'Critical' : hasHigh ? 'High' :
                           vulnerableCount > 0 ? 'Medium' : 'Low';

  return {
    success: true,
    address,
    chain: chainKey,
    contractName:        contract.name,
    compilerVersion:     contract.compilerVersion,
    bytecodeSize:        contract.bytecodeSize,
    analysedAt:          new Date().toISOString(),
    overallRisk,
    vulnerableCategories: vulnerableCount,
    totalFindings,
    results,
    reviewRequired: true,
  };
}

// ── Send helper ───────────────────────────────────────────────

function send(ws, type, data = {}) {
  if (ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify({ type, ...data, ts: Date.now() }));
    } catch (err) {
      console.error(`[!] Send error: ${err.message}`);
    }
  }
}
