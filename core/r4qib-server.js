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

import 'dotenv/config';
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

// ── Broadcast to all dashboard clients ───────────────────────
// Used by the watcher relay to push live pipeline events
function broadcastAll(type, data = {}) {
  const msg = JSON.stringify({ type, ...data, ts: Date.now() });
  wss.clients.forEach(client => {
    if (client.readyState === 1) { // OPEN
      try { client.send(msg); } catch { /* silent */ }
    }
  });
}

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

      case 'watcher_relay':
        // Watcher sends live pipeline events — relay to all dashboard clients
        broadcastAll(msg.relayType, msg.relayData || {});
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

// ── Deduplication ─────────────────────────────────────────────
// Groups findings by root location. If 3+ categories flag the
// same function for the same root cause, consolidates into one
// finding with multiple SWC tags. Reduces classification noise
// without touching recall.

function deduplicateFindings(result, log) {
  const allFindings = result.results.flatMap(r =>
    (r.findings || []).map(f => ({
      ...f,
      swc:      r.swc,
      category: r.category,
    }))
  );

  if (allFindings.length === 0) return result;

  // Group by normalised location
  const groups = {};
  allFindings.forEach(f => {
    const key = normaliseLocation(f.location);
    if (!groups[key]) groups[key] = [];
    groups[key].push(f);
  });

  let consolidated = 0;
  const deduped = [];

  Object.entries(groups).forEach(([location, findings]) => {
    if (findings.length >= 3) {
      // Same location flagged by 3+ categories — consolidate
      const severityRank = ['Critical','High','Medium','Low','Informational'];
      const topSeverity  = findings.reduce((best, f) => {
        return severityRank.indexOf(f.severity) < severityRank.indexOf(best)
          ? f.severity : best;
      }, 'Informational');

      const swcTags = [...new Set(findings.map(f => f.swc))].join(', ');
      const primary = findings.find(f => f.severity === topSeverity) || findings[0];

      deduped.push({
        ...primary,
        severity:     topSeverity,
        swc:          swcTags,
        consolidated: true,
        consolidatedFrom: findings.length,
        title: primary.title,
        note: `Consolidated from ${findings.length} category flags at same location (${swcTags})`,
      });
      consolidated += findings.length - 1;
    } else {
      findings.forEach(f => deduped.push({ ...f, consolidated: false }));
    }
  });

  if (consolidated > 0) {
    log(`Deduplication: ${consolidated} redundant finding(s) consolidated`, 'info');
    log(`Findings: ${allFindings.length} raw → ${deduped.length} after dedupe`, 'info');
  }

  // Rebuild result with deduped findings
  return {
    ...result,
    totalFindings:     deduped.length,
    rawFindingsCount:  allFindings.length,
    consolidatedCount: consolidated,
    dedupedFindings:   deduped,
    overallRisk: recalcRisk(deduped),
  };
}

function normaliseLocation(location) {
  if (!location) return 'unknown';
  return location
    .replace(/,?\s*(line\s*\d+|l\.\s*\d+)/gi, '') // strip line references
    .replace(/\(.*?\)/g, '')                        // strip parameter lists
    .replace(/in\s+\S+\.sol/gi, '')                 // strip file references
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function recalcRisk(findings) {
  const severities = findings.map(f => f.severity);
  if (severities.includes('Critical')) return 'Critical';
  if (severities.includes('High'))     return 'High';
  if (severities.includes('Medium'))   return 'Medium';
  if (severities.includes('Low'))      return 'Low';
  return 'Informational';
}

// ── Scan Handler ──────────────────────────────────────────────

async function handleScan(ws, msg) {
  const { address, chain, targetName, notes, attackAngle, sourceUrl, category, groundTruth } = msg;

  // Validate address
  if (!address) {
    send(ws, 'error', { message: 'No address provided' });
    return;
  }

  // SOURCE mode — calibration scan from raw URL, no RPC needed
  const isSourceMode = address === 'SOURCE';

  if (!isSourceMode && !address.startsWith('0x')) {
    send(ws, 'error', { message: 'Invalid contract address — must start with 0x or be SOURCE' });
    return;
  }

  if (activeScans.get(ws)) {
    send(ws, 'error', { message: 'Scan already in progress — wait for completion' });
    return;
  }

  activeScans.set(ws, true);

  const scanId   = Date.now();
  const chainKey = chain || 'ethereum-mainnet';

  const log     = (message, tag = 'info') => send(ws, 'log',    { tag, message });
  const stage   = (id, state)             => send(ws, 'stage',  { id, state });
  const finding = (data)                  => send(ws, 'finding', data);

  send(ws, 'scan_start', { scanId, address, chain: chainKey, targetName });
  stage('stage-idle', 'complete');
  stage('stage-4',    'active');

  log(`Scan #${scanId} initiated`, 'info');
  log(`Target: ${targetName || address}`, 'info');
  if (notes)       log(`Note: ${notes}`, 'info');
  if (attackAngle) log(`Angle: ${attackAngle}`, 'reason');
  if (groundTruth) log(`Ground truth: ${groundTruth}`, 'reason');

  let result;

  if (isSourceMode) {
    // ── SOURCE MODE — calibration from raw URL ──────────────────
    if (!sourceUrl) {
      log('SOURCE mode requires sourceUrl in target JSON', 'error');
      send(ws, 'scan_error', { scanId, error: 'Missing sourceUrl' });
      activeScans.delete(ws);
      return;
    }

    log(`Calibration mode — fetching source from URL`, 'agent');
    log(`${sourceUrl}`, 'info');

    try {
      result = await analyseSourceUrl(
        sourceUrl, targetName, scanId, ws, { log, stage, finding }
      );
    } catch (err) {
      log(`Source fetch error: ${err.message}`, 'error');
      stage('stage-4', 'failed');
      send(ws, 'scan_error', { scanId, error: err.message });
      activeScans.delete(ws);
      return;
    }

  } else {
    // ── CHAIN MODE — fetch from RPC + explorer ──────────────────
    const isSomnia = chainKey.startsWith('somnia');
    if (isSomnia) {
      log(`Somnia chain — on-chain agent pipeline`, 'agent');
    } else {
      log(`EVM chain — off-chain analysis pipeline`, 'info');
      log(`Deploy to Somnia for full three-agent context layer`, 'info');
    }

    log(`Fetching contract source via Blockscout/Etherscan...`, 'info');

    try {
      result = await analyseContractWithProgress(
        address.toLowerCase(), chainKey, ACTIVE_CATEGORIES, ws, { log, stage, finding }
      );
    } catch (err) {
      log(`Analysis error: ${err.message}`, 'error');
      stage('stage-4', 'failed');
      send(ws, 'scan_error', { scanId, error: err.message });
      activeScans.delete(ws);
      return;
    }
  }

  if (!result.success) {
    log(`Scan failed: ${result.error}`, 'error');
    stage('stage-4', 'failed');
    send(ws, 'scan_error', { scanId, error: result.error });
    activeScans.delete(ws);
    return;
  }

  // ── Deduplication — consolidate same-root findings ────────────
  result = deduplicateFindings(result, log);

  // ── Save report ───────────────────────────────────────────────
  const label      = isSourceMode ? targetName.replace(/[^a-z0-9]/gi, '-').toLowerCase() : address.slice(0,8);
  const reportFile = path.join(REPORTS_DIR, `scan-${scanId}-${label}.json`);
  const report     = {
    ...result,
    scanId,
    targetName,
    notes,
    attackAngle,
    groundTruth:    groundTruth || null,
    expectedCategory: category  || null,
    sourceUrl:      sourceUrl   || null,
    mode:           isSourceMode ? 'calibration' : 'chain',
  };

  fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
  log(`Report saved: ${path.basename(reportFile)}`, 'success');

  // Stream deduplicated findings to dashboard
  const findingsToStream = result.dedupedFindings || [];
  findingsToStream.forEach(f => {
    send(ws, 'finding', {
      severity:    f.severity,
      title:       f.title + (f.consolidated ? ` [consolidated ×${f.consolidatedFrom}]` : ''),
      location:    f.location,
      description: f.description,
      category:    f.category,
      swc:         f.swc,
      confidence:  f.confidence,
      consolidated: f.consolidated || false,
    });
  });

  stage('stage-4', 'complete');
  stage('stage-5', 'active');

  send(ws, 'scan_complete', {
    scanId,
    address,
    contractName:      result.contractName,
    overallRisk:       result.overallRisk,
    totalFindings:     result.totalFindings,
    rawFindingsCount:  result.rawFindingsCount  || result.totalFindings,
    consolidatedCount: result.consolidatedCount || 0,
    reportFile:        path.basename(reportFile),
    groundTruth:       groundTruth || null,
  });

  log(`Analysis complete — ${result.rawFindingsCount || result.totalFindings} raw → ${result.totalFindings} after dedupe`, 'success');
  log(`Overall risk: ${result.overallRisk}`,
    result.overallRisk === 'Critical' || result.overallRisk === 'High' ? 'warn' : 'success');
  if (result.consolidatedCount > 0) {
    log(`Consolidated ${result.consolidatedCount} redundant classification(s)`, 'info');
  }
  if (groundTruth) {
    log(`Expected: ${groundTruth} — review findings to score calibration`, 'human');
  }
  log(`Human review required`, 'human');

  activeScans.delete(ws);
}

// ── Source URL Analysis — calibration mode ────────────────────

async function analyseSourceUrl(sourceUrl, targetName, scanId, ws, { log, stage, finding }) {
  const { analyseCategory } = await import('./r4qib-analyst.js');
  const https = await import('https');
  const http  = await import('http');

  // Fetch source from URL
  const sourceCode = await new Promise((resolve, reject) => {
    const client = sourceUrl.startsWith('https') ? https.default : http.default;
    client.get(sourceUrl, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} fetching source`));
        return;
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });

  if (!sourceCode || sourceCode.length < 10) {
    return { success: false, error: 'Empty source returned from URL' };
  }

  const contractName = targetName || 'CalibrationContract';
  const byteSize     = Buffer.byteLength(sourceCode, 'utf8');

  log(`Source fetched — ${contractName} (${byteSize} bytes)`, 'success');
  log(`Running ${ACTIVE_CATEGORIES.length} vulnerability categories...`, 'info');

  const results      = [];
  let totalFindings  = 0;

  for (let i = 0; i < ACTIVE_CATEGORIES.length; i++) {
    const cat = ACTIVE_CATEGORIES[i];
    log(`[${i+1}/${ACTIVE_CATEGORIES.length}] ${cat.name} (${cat.swc})...`, 'agent');

    const result = await analyseCategory(sourceCode, cat, contractName);
    results.push(result);

    const count = result.findings?.length || 0;
    totalFindings += count;

    if (result.vulnerable && count > 0) {
      log(`${cat.name}: ${count} finding(s)`, 'warn');
      result.findings.forEach(f => {
        finding({
          severity:   f.severity,
          title:      f.title,
          location:   f.location,
          description: f.description,
          category:   cat.name,
          swc:        cat.swc,
          confidence: f.confidence,
        });
      });
    } else if (result.vulnerable === null) {
      log(`${cat.name}: parse error — empty response`, 'error');
    } else {
      log(`${cat.name}: clean`, 'success');
    }
  }

  const severities     = results.flatMap(r => r.findings?.map(f => f.severity) || []);
  const hasCritical    = severities.includes('Critical');
  const hasHigh        = severities.includes('High');
  const vulnerableCount = results.filter(r => r.vulnerable === true).length;
  const parseErrors    = results.filter(r => r.vulnerable === null).length;
  const overallRisk    = hasCritical ? 'Critical' : hasHigh ? 'High' :
                         vulnerableCount > 0 ? 'Medium' : 'Low';

  if (parseErrors > 0) {
    log(`⚠ ${parseErrors} categories returned empty — context window may be too small`, 'warn');
  }

  return {
    success: true,
    address:          'SOURCE',
    chain:            'calibration',
    contractName,
    sourceUrl,
    byteSize,
    analysedAt:       new Date().toISOString(),
    model:            process.env.LLM_MODEL || 'qwen/qwen2.5-coder-14b',
    overallRisk,
    vulnerableCategories: vulnerableCount,
    parseErrors,
    totalFindings,
    results,
    reviewRequired:   true,
  };
}

// ── Chain Analysis with per-category progress streaming ────────

async function analyseContractWithProgress(address, chainKey, categories, ws, { log, stage, finding }) {

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
