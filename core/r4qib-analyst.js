// ============================================================
// R4qib — Contract Analyst v1.2
// Added: source chunking for large contracts (>8000 tokens)
// Splits by contract/interface/library boundaries
// Each chunk analysed independently, findings merged
// Context window safe at 16384 tokens
// ============================================================

import { fetchContractForAnalysis } from './somnia-connector.js';

// ── LMStudio Config ───────────────────────────────────────────
const LLM_HOST        = '127.0.0.1';
const LLM_PORT        = 1234;
const LLM_MODEL       = process.env.LLM_MODEL || 'deepseek-coder-v2-lite-instruct';
const LLM_TEMPERATURE = 0.15;

// Approximate token budget for source code per call
// System prompt ~800 tokens, category prompt ~200 tokens,
// context prefix ~300 tokens, response budget ~600 tokens
// 16384 - 800 - 200 - 300 - 600 = ~14284 remaining for source
// At ~4 chars/token: 14284 * 4 = ~57136 chars
// Being conservative: 10000 token budget = 40000 chars
const MAX_SOURCE_CHARS = 28000;

// ── System Prompt ─────────────────────────────────────────────
const SYSTEM_PROMPT = `You are R4qib — an autonomous smart contract security analyst.
You observe with precision, honesty, and diligence.
You reason carefully. You do not hallucinate findings. When uncertain, set vulnerable: false.
You distinguish confirmed vulnerabilities from potential issues and informational observations.

FALSE POSITIVE RULES — apply before every finding:

RULE 1 — INHERITANCE: Check ALL imports before flagging access control.
  OZ Ownable/Ownable2Step/AccessControl provide inherited modifiers.
  onlyOwner IS protected even if not defined in this file.
  OZ Ownable transferOwnership() has built-in zero-address protection. Do NOT flag it.

RULE 2 — CALL GRAPH: private/internal functions need no nonReentrant if ALL callers have it.
  Trace the call graph before flagging reentrancy on private/internal functions.

RULE 3 — ROUNDING: Only flag if rounding direction causes demonstrable fund loss.
  Protocol unit conversions (wei/gwei, token decimals) are design choices, not bugs.

RULE 4 — EVENTS: Only flag missing events if the omission creates concrete security risk.
  Do not speculate about events that might be missing.

RULE 5 — CALLER VALIDATION: require/revert/if checks on msg.sender in the function body
  IS access control. Check the body, not just modifiers.

RULE 6 — tx.origin: Only flag if used for authentication or authorisation, not logging.

RULE 7 — TRUSTED ENTRY POINTS: Functions restricted to onlyOwner/onlyGovernance/onlyAgent
  cannot be called directly by attackers. Do NOT flag reentrancy on these.

RULE 8 — BALANCE PATTERNS: balanceBefore/balanceAfter is correct safe accounting.
  Do NOT flag as missing validation.

RULE 9 — SLITHER COMMENTS: slither-disable indicates conscious developer decision.
  Verify the mitigation is actually present before flagging.

RULE 10 — DESIGN COMMENTS: Code comments explaining design choices are not vulnerabilities
  unless the design itself creates a concrete exploitable risk.

RULE 11 — DIAMOND PROXY FACETS: If this contract is a diamond proxy facet,
  access control is enforced at the diamond level, not the facet level.
  Do NOT flag unprotected functions in facets without verifying the diamond
  access manager does not gate the call.

OUTPUT FORMAT — valid JSON only, no prose outside this structure:
{
  "category": "category_id",
  "swc": "SWC-XXX or R4qib-00X",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or line reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker exploits this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}

You operate on behalf of a human security researcher who reviews all findings before action.`;

// ── Vulnerability Categories ──────────────────────────────────
export const VULNERABILITY_CATEGORIES = [
  {
    id: 'reentrancy',
    name: 'Reentrancy',
    swc: 'SWC-107',
    prompt: `Analyse for REENTRANCY (SWC-107). category="reentrancy" swc="SWC-107"

Check:
- CEI violations — external call before state update
- Missing nonReentrant on state-changing functions with external calls
- Cross-function reentrancy via shared state
- Read-only reentrancy on view functions used by price oracles`
  },
  {
    id: 'integer_overflow',
    name: 'Integer Overflow / Underflow',
    swc: 'SWC-101',
    prompt: `Analyse for INTEGER OVERFLOW/UNDERFLOW (SWC-101). category="integer_overflow" swc="SWC-101"

Check:
- Solidity < 0.8.x: missing SafeMath
- Solidity >= 0.8.x: unchecked blocks — verify justification
- Unsafe type casting (uint256 → uint8/uint128 etc)
- Underflow in subtraction before version check`
  },
  {
    id: 'access_control',
    name: 'Access Control',
    swc: 'SWC-105',
    prompt: `Analyse for ACCESS CONTROL vulnerabilities (SWC-105). category="access_control" swc="SWC-105"

Check:
- Unprotected initialize() — proxy takeover vector
- Public functions that should be internal or private
- Missing modifiers on sensitive state-changing functions
- Ownership transfer without zero-address check (apply Rule 1 first)
- Role assignment without proper guards`
  },
  {
    id: 'unchecked_calls',
    name: 'Unchecked External Calls',
    swc: 'SWC-104',
    prompt: `Analyse for UNCHECKED EXTERNAL CALLS (SWC-104). category="unchecked_calls" swc="SWC-104"

Check:
- call() or send() return value not checked
- transfer() with complex receivers (fixed 2300 gas breaks)
- Execution continues silently after failed external call
- Low-level calls without error handling`
  },
  {
    id: 'flash_loan',
    name: 'Flash Loan Attack Vectors',
    swc: 'DeFi-specific',
    prompt: `Analyse for FLASH LOAN attack vectors. category="flash_loan" swc="DeFi-specific"

Check:
- Single DEX spot price used as oracle (no TWAP)
- Governance voting power acquirable via flash loan
- Reserve ratio assumptions manipulable atomically
- Callback patterns vulnerable to atomic manipulation
- Price-sensitive logic executable within one transaction`
  },
  {
    id: 'logic_errors',
    name: 'Logic Errors & Business Logic Flaws',
    swc: 'SWC-110',
    prompt: `Analyse for LOGIC ERRORS and BUSINESS LOGIC FLAWS (SWC-110). category="logic_errors" swc="SWC-110"

Check:
- Division before multiplication (precision loss)
- Off-by-one in loops, ranges, array bounds
- Non-18 decimal ERC-20 assumptions
- Invalid state machine transitions
- Reward/distribution calculation errors
- Incorrect accounting in deposit/withdraw/redeem flows`
  },
  {
    id: 'front_running',
    name: 'Front-Running & MEV Exposure',
    swc: 'SWC-114',
    prompt: `Analyse for FRONT-RUNNING and MEV EXPOSURE (SWC-114). category="front_running" swc="SWC-114"

Check:
- Missing commit-reveal for sensitive value submission
- Insufficient slippage protection in DEX interactions
- block.timestamp or block.number as randomness source
- Auction mechanisms vulnerable to last-block sniping
- Predictable on-chain randomness (no Chainlink VRF)`
  },
  {
    id: 'upgradability',
    name: 'Upgradability & Proxy Vulnerabilities',
    swc: 'SWC-112',
    prompt: `Analyse for UPGRADABILITY and PROXY PATTERN vulnerabilities (SWC-112). category="upgradability" swc="SWC-112"

Check:
- Storage layout collision between proxy and implementation
- delegatecall to user-controlled or untrusted contracts
- Uninitialised proxy (takeover via initialize())
- Upgrade authority — who controls it, is it timelocked?
- selfdestruct in implementation (destroys all proxy instances)
- Function selector clashes between proxy and implementation
- Diamond facet storage isolation (EIP-2535 pattern)`
  },
  {
    id: 'intent_mismatch',
    name: 'Semantic Intent Mismatch',
    swc: 'R4qib-001',
    prompt: `Analyse for SEMANTIC INTENT MISMATCH (R4qib-001). category="intent_mismatch" swc="R4qib-001"

This novel category compares what the code SAYS it does against what it ACTUALLY does.

Check:
- NatSpec claiming restrictions not enforced in code
- Function names implying safety without corresponding checks
- "Called once" or "initialisation only" claims without enforcement
- Immutable-named variables (MAX_, FIXED_) that are actually mutable
- @param/@return constraints documented but not required()
- Error/event names that misrepresent the actual condition
- Any divergence between documented and actual behaviour that could mislead auditors or integrators

Flag only divergences that create security risk — not trivial naming inconsistencies.`
  },
  {
    id: 'somnia_assumptions',
    name: 'Somnia High-TPS Assumption Violations',
    swc: 'R4qib-002',
    active: false,
    prompt: `Analyse for HIGH-TPS CHAIN ASSUMPTION VIOLATIONS (R4qib-002). category="somnia_assumptions" swc="R4qib-002"

This contract may be deployed on Somnia — 1,000,000 TPS, sub-second finality.

Check:
- block.timestamp for time-locks or vesting (sub-second = sequencer manipulation)
- block.number for time calculations (1000 blocks = seconds not days at 1M TPS)
- Rate limiting bypassable at high throughput
- Cooldown periods assuming Ethereum block times
- Front-running protections that fail at high speed
- Flash loan atomicity assumptions that differ at 1M TPS

For each finding: explain specifically how high-TPS changes the risk vs Ethereum.`
  }
];

export const ACTIVE_CATEGORIES = VULNERABILITY_CATEGORIES.filter(c => c.active !== false);

// ── Source Chunker ────────────────────────────────────────────
// Splits Solidity source at contract/interface/library boundaries.
// Returns array of chunks, each under MAX_SOURCE_CHARS.
// Falls back to line-based splitting if boundaries aren't found.

function chunkSource(sourceCode) {
  // If it fits, no chunking needed
  if (sourceCode.length <= MAX_SOURCE_CHARS) {
    return [{ code: sourceCode, label: 'full', index: 0, total: 1 }];
  }

  // Split on top-level contract/interface/library/abstract contract declarations
  const boundaryRe = /^(?:abstract\s+)?(?:contract|interface|library)\s+\w+/mg;
  const boundaries = [];
  let match;

  while ((match = boundaryRe.exec(sourceCode)) !== null) {
    boundaries.push(match.index);
  }

  // If no boundaries found — fall back to line-based splitting
  if (boundaries.length <= 1) {
    return lineBasedChunks(sourceCode);
  }

  // Build chunks from boundaries
  const rawChunks = [];
  for (let i = 0; i < boundaries.length; i++) {
    const start = boundaries[i];
    const end   = boundaries[i + 1] ?? sourceCode.length;
    rawChunks.push(sourceCode.slice(start, end));
  }

  // Prepend file-level pragmas/imports to first chunk
  const fileHeader = sourceCode.slice(0, boundaries[0]);
  if (fileHeader.trim()) {
    rawChunks[0] = fileHeader + rawChunks[0];
  }

  // Merge small adjacent chunks, split oversized ones
  const finalChunks = [];
  let current = '';

  for (const chunk of rawChunks) {
    if (chunk.length > MAX_SOURCE_CHARS) {
      // Oversized single contract — split by lines
      if (current.trim()) {
        finalChunks.push(current);
        current = '';
      }
      lineBasedChunks(chunk).forEach(c => finalChunks.push(c.code));
    } else if ((current + chunk).length > MAX_SOURCE_CHARS) {
      if (current.trim()) finalChunks.push(current);
      current = chunk;
    } else {
      current += '\n\n' + chunk;
    }
  }
  if (current.trim()) finalChunks.push(current);

  return finalChunks.map((code, i) => ({
    code,
    label: `chunk ${i + 1}/${finalChunks.length}`,
    index: i,
    total: finalChunks.length,
  }));
}

function lineBasedChunks(sourceCode) {
  const lines  = sourceCode.split('\n');
  const chunks = [];
  let current  = '';

  for (const line of lines) {
    if ((current + line).length > MAX_SOURCE_CHARS && current.trim()) {
      chunks.push(current);
      current = line + '\n';
    } else {
      current += line + '\n';
    }
  }
  if (current.trim()) chunks.push(current);

  return chunks.map((code, i) => ({
    code,
    label: `lines chunk ${i + 1}/${chunks.length}`,
    index: i,
    total: chunks.length,
  }));
}

// ── Merge findings from multiple chunks ───────────────────────
// If any chunk is vulnerable, the category is vulnerable.
// Deduplicates findings by title+location.

function mergeChunkResults(chunkResults, categoryId) {
  const allFindings = [];
  const seen        = new Set();
  let   vulnerable  = false;
  let   confidence  = 'Low';
  const summaries   = [];

  for (const r of chunkResults) {
    if (r.vulnerable === true) vulnerable = true;
    if (r.confidence === 'High')   confidence = 'High';
    else if (r.confidence === 'Medium' && confidence !== 'High') confidence = 'Medium';

    if (r.summary && !r.summary.startsWith('Failed')) summaries.push(r.summary);

    for (const f of (r.findings || [])) {
      const key = `${f.title}|${f.location}`;
      if (!seen.has(key)) {
        seen.add(key);
        allFindings.push(f);
      }
    }
  }

  return {
    category:   categoryId,
    vulnerable,
    confidence,
    findings:   allFindings,
    summary:    summaries.join(' | ') || (vulnerable ? 'Issues found across chunks' : 'No issues found'),
    chunked:    chunkResults.length > 1,
    chunkCount: chunkResults.length,
  };
}

// ── LLM Call ─────────────────────────────────────────────────
async function callLLM(systemPrompt, userMessage) {
  const body = JSON.stringify({
    model:       LLM_MODEL,
    temperature: LLM_TEMPERATURE,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user',   content: userMessage  }
    ],
    stream: false,
  });

  const { default: http } = await import('http');

  return new Promise((resolve, reject) => {
    const options = {
      hostname: LLM_HOST,
      port:     LLM_PORT,
      path:     '/v1/chat/completions',
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data',  chunk => data += chunk);
      res.on('end',   () => {
        try {
          const parsed  = JSON.parse(data);
          const content = parsed.choices?.[0]?.message?.content || '';
          resolve(content);
        } catch (e) {
          reject(new Error(`LLM response parse error: ${e.message}`));
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Parse LLM Response ────────────────────────────────────────
function parseLLMResponse(content, categoryId) {
  try {
    const clean = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(clean);
  } catch (e) {
    return {
      category:    categoryId,
      vulnerable:  null,
      confidence:  'Low',
      findings:    [],
      summary:     'Failed to parse LLM response as JSON.',
      parseError:  e.message,
      rawResponse: content.slice(0, 500),
    };
  }
}

// ── Analyse Single Category (with chunking) ───────────────────
export async function analyseCategory(sourceCode, category, contractName = 'Unknown', contextPrefix = '') {
  const chunks = chunkSource(sourceCode);

  if (chunks.length > 1) {
    console.log(`   📦 ${category.name}: ${chunks.length} chunks (${Math.round(sourceCode.length / 1024)}KB source)`);
  } else {
    console.log(`   🔍 Analysing: ${category.name} (${category.swc})...`);
  }

  const chunkResults = [];

  for (const chunk of chunks) {
    const chunkLabel = chunks.length > 1 ? ` [${chunk.label}]` : '';

    const context = contextPrefix
      ? `${contextPrefix}\n\nContract name: ${contractName}${chunkLabel}\n\nSource code:\n\`\`\`solidity\n${chunk.code}\n\`\`\`\n\n${category.prompt}`
      : `Contract name: ${contractName}${chunkLabel}\n\nSource code:\n\`\`\`solidity\n${chunk.code}\n\`\`\`\n\n${category.prompt}`;

    if (chunks.length > 1) {
      console.log(`      → ${chunk.label} (${Math.round(chunk.code.length / 1024)}KB)`);
    }

    try {
      const response = await callLLM(SYSTEM_PROMPT, context);
      const result   = parseLLMResponse(response, category.id);
      chunkResults.push(result);
    } catch (e) {
      console.log(`      ❌ Chunk failed: ${e.message}`);
      chunkResults.push({
        category:   category.id,
        vulnerable: null,
        confidence: 'Low',
        findings:   [],
        summary:    `Chunk analysis failed: ${e.message}`,
      });
    }
  }

  const merged = chunks.length > 1
    ? mergeChunkResults(chunkResults, category.id)
    : chunkResults[0];

  const status = merged.vulnerable ? '⚠️  Potential issue' : '✅ Clean';
  console.log(`      ${status} — ${merged.summary || ''}`);

  return merged;
}

// ── Full Contract Analysis ────────────────────────────────────
export async function analyseContract(address, chainKey = 'somnia-testnet', categories = ACTIVE_CATEGORIES, contextPrefix = '') {
  console.log(`\n👁️  R4qib v1.2 — Beginning analysis`);
  console.log(`   Address    : ${address}`);
  console.log(`   Chain      : ${chainKey}`);
  console.log(`   Categories : ${categories.length}`);
  console.log(`   Model      : ${LLM_MODEL}`);

  const contract = await fetchContractForAnalysis(address, chainKey);
  if (!contract.success) return { success: false, error: contract.error };

  if (!contract.hasSource) {
    return {
      success:      false,
      error:        'Source not verified. Analysis requires verified Solidity source.',
      address,
      bytecodeSize: contract.bytecodeSize,
    };
  }

  const sourceSize = contract.sourceCode.length;
  const chunks     = chunkSource(contract.sourceCode);

  console.log(`\n   Contract : ${contract.name} (${contract.bytecodeSize} bytes)`);
  console.log(`   Source   : ${Math.round(sourceSize / 1024)}KB — ${chunks.length} chunk(s)`);
  console.log(`   Running ${categories.length} categories...\n`);

  const results = [];
  for (const category of categories) {
    const result = await analyseCategory(contract.sourceCode, category, contract.name, contextPrefix);
    results.push(result);
  }

  const allFindings     = results.flatMap(r => r.findings || []);
  const vulnerableCount = results.filter(r => r.vulnerable === true).length;
  const severities      = allFindings.map(f => f.severity);
  const overallRisk     = severities.includes('Critical') ? 'Critical' :
                          severities.includes('High')     ? 'High'     :
                          vulnerableCount > 0             ? 'Medium'   : 'Low';

  console.log(`\n📋 Analysis complete`);
  console.log(`   Contract  : ${contract.name}`);
  console.log(`   Risk      : ${overallRisk}`);
  console.log(`   Flagged   : ${vulnerableCount}/${categories.length} categories`);
  console.log(`   Findings  : ${allFindings.length} total`);

  return {
    success:              true,
    address,
    chain:                chainKey,
    contractName:         contract.name,
    compilerVersion:      contract.compilerVersion,
    bytecodeSize:         contract.bytecodeSize,
    analysedAt:           new Date().toISOString(),
    model:                LLM_MODEL,
    overallRisk,
    vulnerableCategories: vulnerableCount,
    totalFindings:        allFindings.length,
    results,
    reviewRequired:       true,
    reviewNote:           'R4qib findings are for human review only. Verify before reporting or acting.',
  };
}
