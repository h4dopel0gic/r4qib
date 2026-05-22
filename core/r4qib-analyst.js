// ============================================================
// R4qib — Contract Analyst v1.0
// Feeds verified Solidity source to the Code Analyst LLM role.
// Analyses one vulnerability category at a time.
// Returns structured findings ready for report generation.
// ============================================================

import { fetchContractForAnalysis } from './somnia-connector.js';

// ── LMStudio Config ──────────────────────────────────────────
const LLM_HOST = '127.0.0.1';
const LLM_PORT = 1234;
const LLM_MODEL = 'deepseek-coder-v2-lite-instruct'; // must match LMStudio loaded model name
const LLM_TEMPERATURE = 0.15; // low — precision over creativity for security analysis

// ── System Prompt — Code Analyst Role ────────────────────────
// This is the anchor. It defines R4qib's identity and reasoning discipline.
const SYSTEM_PROMPT = `You are R4qib — an autonomous smart contract security analyst.
Your name means "The Watcher" — you observe with precision, honesty, and diligence.

Your role is to analyse Solidity smart contract source code for security vulnerabilities.
You reason carefully. You do not hallucinate findings. If you are uncertain, you say so.
You distinguish between confirmed vulnerabilities, potential issues, and informational observations.

CRITICAL RULES TO PREVENT FALSE POSITIVES:

RULE 1 — INHERITANCE: Before flagging ANY access control issue, check ALL imports.
  If the contract imports OpenZeppelin Ownable, Ownable2Step, AccessControl or similar,
  those provide onlyOwner/onlyRole as inherited modifiers. A function declared with
  onlyOwner IS protected even if the modifier is not defined in this file.
  If a contract inherits OZ Ownable, transferOwnership() already has zero-address
  protection built in. Do NOT flag this.

RULE 2 — PRIVATE/INTERNAL CALL GRAPH: private and internal functions do NOT need
  their own nonReentrant modifier if ALL their callers already have it.
  Before flagging reentrancy on a private/internal function, trace the call graph:
  find every function that calls it and check if those callers are protected.
  If all callers have nonReentrant, the private function IS protected. Do not flag it.

RULE 3 — ROUNDING: Only flag rounding errors if you can identify a specific attack
  scenario where rounding direction causes fund loss. Protocol-defined unit conversions
  (e.g. AMG to UBA, wei to gwei) are deliberate design choices, not vulnerabilities.
  Do NOT flag rounding in conversion functions unless the direction is provably wrong.

RULE 4 — EVENT EMISSION: Only flag missing events if you can identify a specific
  state change that has NO corresponding event and where the omission creates a
  concrete security risk. Do NOT speculate about "might be missing" events.

RULE 5 — CALLER VALIDATION: If a function validates its caller inside the body
  (require, revert, if/revert checks on msg.sender) it IS access-controlled.
  Check the function body, not just the modifier list.

RULE 6 — tx.origin: Only flag tx.origin if used for AUTHENTICATION or AUTHORISATION.
  Using it for logging or informational purposes is not a vulnerability.

RULE 7 — ACCESS-RESTRICTED ENTRY POINTS: If a function is restricted to a specific
  trusted caller via a modifier (onlyAssetManager, onlyOwner, onlyGovernance, onlyAgent
  or similar), reentrancy and most attack scenarios require compromising that caller first.
  Do NOT flag reentrancy on functions that can only be called by governed/trusted contracts.
  The attacker cannot call these functions directly. Note the restriction in your summary.

RULE 8 — BALANCE-BEFORE/AFTER PATTERNS: If a function captures a balance before an
  external call and computes the difference after (balanceBefore/balanceAfter pattern),
  this IS a validation mechanism. Do NOT flag it as missing validation.
  This is the correct and safe pattern for accounting external transfers.

RULE 9 — SLITHER DISABLE COMMENTS: If the contract contains slither-disable comments
  specifically addressing a vulnerability class (e.g. //slither-disable reentrancy),
  this indicates the developers have consciously addressed it. Check that the mitigation
  they claim (e.g. nonReentrant) is actually present before flagging.

RULE 10 — DELIBERATE DESIGN COMMENTS: If the code contains comments explaining WHY
  something is implemented a certain way (e.g. "practically immutable because there
  is no setter"), this is a documented design decision, not a vulnerability.
  Only flag if the design decision itself creates a concrete, exploitable risk.

When genuinely uncertain, set vulnerable: false and explain in the summary.

For each analysis you produce:
1. A clear vulnerability assessment — present or not present
2. The specific code location (function name, line reference if visible)
3. The attack scenario — how could this be exploited?
4. Severity: Critical | High | Medium | Low | Informational
5. Confidence: High | Medium | Low
6. A concise remediation recommendation

You output valid JSON only. No prose outside the JSON structure.
You are operating on behalf of a human security researcher who will review your findings before any action is taken.`;

// ── Vulnerability Categories ──────────────────────────────────
export const VULNERABILITY_CATEGORIES = [
  {
    id: 'reentrancy',
    name: 'Reentrancy',
    swc: 'SWC-107',
    prompt: `Analyse this Solidity contract for REENTRANCY vulnerabilities.

Check for:
- External calls made before state updates (CEI pattern violations)
- Missing reentrancy guards (nonReentrant modifier)
- Cross-function reentrancy across shared state variables
- Read-only reentrancy (view functions called by price oracles)

Respond with this exact JSON structure:
{
  "category": "reentrancy",
  "swc": "SWC-107",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },
  {
    id: 'integer_overflow',
    name: 'Integer Overflow / Underflow',
    swc: 'SWC-101',
    prompt: `Analyse this Solidity contract for INTEGER OVERFLOW and UNDERFLOW vulnerabilities.

Check for:
- Solidity version — pre-0.8.x lacks built-in overflow protection
- Missing SafeMath usage in pre-0.8.x contracts
- Unchecked blocks in 0.8.x+ (intentional overflow — verify justification)
- Unsafe type casting (uint256 to uint8, etc.)

Respond with this exact JSON structure:
{
  "category": "integer_overflow",
  "swc": "SWC-101",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },
  {
    id: 'access_control',
    name: 'Access Control',
    swc: 'SWC-105',
    prompt: `Analyse this Solidity contract for ACCESS CONTROL vulnerabilities.

Check for:
- Functions missing onlyOwner or role-based modifiers
- Unprotected initialize() functions (proxy pattern attack surface)
- tx.origin used instead of msg.sender for authentication (SWC-115)
- Ownership transfer to zero address (burns control permanently)
- Functions public when they should be internal or private
- Missing access control on sensitive state-changing functions

Respond with this exact JSON structure:
{
  "category": "access_control",
  "swc": "SWC-105",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },
  {
    id: 'unchecked_calls',
    name: 'Unchecked External Calls',
    swc: 'SWC-104',
    prompt: `Analyse this Solidity contract for UNCHECKED EXTERNAL CALL vulnerabilities.

Check for:
- Return values of call() and send() not checked
- transfer() usage (fixed 2300 gas — breaks with complex receivers)
- Silent failure patterns where execution continues after failed transfer
- Missing pull-over-push payment patterns
- Low-level calls without error handling

Respond with this exact JSON structure:
{
  "category": "unchecked_calls",
  "swc": "SWC-104",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },
  {
    id: 'flash_loan',
    name: 'Flash Loan Attack Vectors',
    swc: 'DeFi-specific',
    prompt: `Analyse this Solidity contract for FLASH LOAN attack vectors.

Check for:
- Price oracle reliance on single on-chain DEX spot price
- Governance voting power acquirable via flash loan
- Liquidity pool manipulation via reserve ratio assumptions
- Missing TWAP (Time-Weighted Average Price) oracle usage
- Callback patterns vulnerable to atomic manipulation

Respond with this exact JSON structure:
{
  "category": "flash_loan",
  "swc": "DeFi-specific",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },
  {
    id: 'logic_errors',
    name: 'Logic Errors & Business Logic Flaws',
    swc: 'SWC-110',
    prompt: `Analyse this Solidity contract for LOGIC ERRORS and BUSINESS LOGIC FLAWS.

Check for:
- Rounding errors (division before multiplication, precision loss)
- Off-by-one errors in loops, ranges, array bounds
- Incorrect token decimal assumptions (non-18 decimal ERC-20s)
- Invalid state machine transitions
- Incorrect event emission (state changes without events)
- Reward/distribution calculation errors
- Incorrect assumptions baked into contract logic

Respond with this exact JSON structure:
{
  "category": "logic_errors",
  "swc": "SWC-110",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },
  {
    id: 'front_running',
    name: 'Front-Running & MEV Exposure',
    swc: 'SWC-114',
    prompt: `Analyse this Solidity contract for FRONT-RUNNING and MEV EXPOSURE vulnerabilities.

Check for:
- Missing commit-reveal schemes for sensitive value submission
- Insufficient slippage protection in DEX interactions
- block.timestamp or block.number used as randomness source (SWC-120)
- Auction mechanisms vulnerable to last-minute sniping
- Predictable on-chain randomness (not using Chainlink VRF or equivalent)
- Transaction ordering dependencies

Respond with this exact JSON structure:
{
  "category": "front_running",
  "swc": "SWC-114",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },
  {
    id: 'upgradability',
    name: 'Upgradability & Proxy Vulnerabilities',
    swc: 'SWC-112',
    prompt: `Analyse this Solidity contract for UPGRADABILITY and PROXY PATTERN vulnerabilities.

Check for:
- Storage layout collisions between proxy and implementation
- delegatecall to untrusted or user-controlled contracts (SWC-112)
- Uninitialised proxy contracts (takeover via initialize())
- Upgrade authority — who can upgrade, is it time-locked, multisig?
- selfdestruct in implementation contracts (destroys all proxy instances)
- Function selector clashes between proxy and implementation

If this is not an upgradeable contract, note that clearly.

Respond with this exact JSON structure:
{
  "category": "upgradability",
  "swc": "SWC-112",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what the issue is",
      "attack_scenario": "how an attacker could exploit this",
      "remediation": "how to fix it",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },

  // ── Category 9 — Semantic Intent Mismatch ────────────────────
  // Novel R4qib category. Invisible to all static analysis tools.
  // Requires language understanding to compare intent vs implementation.
  {
    id: 'intent_mismatch',
    name: 'Semantic Intent Mismatch',
    swc: 'R4qib-001',
    prompt: `Analyse this Solidity contract for SEMANTIC INTENT MISMATCH vulnerabilities.

This is a novel vulnerability class that requires comparing what the code SAYS it does
(via NatSpec comments, function names, variable names, and documentation)
against what the code ACTUALLY does (the implementation logic).

Check for:
- NatSpec @dev or @notice comments that describe restrictions not enforced in code
  (e.g. "only callable by owner" with no onlyOwner modifier)
- Function names that imply safety but lack the corresponding checks
  (e.g. "safeTransfer" that doesn't check return values)
- Comments claiming a function is "called once" or "initialisation only" 
  with no enforcement (no initializer modifier, no boolean flag)
- Variable names implying immutability (e.g. "MAX_SUPPLY", "FIXED_RATE") 
  that are actually mutable state variables
- @param or @return documentation describing constraints that code doesn't enforce
  (e.g. "@param amount must be > 0" with no require(amount > 0))
- Event names or error names that misrepresent the actual condition
- Functions named "emergency" or "safe" that lack corresponding safety logic
- Any place where the documented behaviour and actual behaviour diverge
  in a way that could mislead auditors, integrators, or users

This analysis requires careful reading of ALL comments alongside the implementation.
Do not flag trivial naming inconsistencies — focus on divergences that create 
security risk or that could mislead someone integrating with this contract.

Respond with this exact JSON structure:
{
  "category": "intent_mismatch",
  "swc": "R4qib-001",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what was promised vs what is implemented",
      "attack_scenario": "how this divergence could be exploited or cause harm",
      "remediation": "how to align implementation with documented intent",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  },

  // ── Category 10 — Somnia High-TPS Assumption Violations ──────
  // Chain-specific. Activate before hackathon submission.
  // Contracts written for Ethereum may break on 1M TPS sub-second finality.
  // STATUS: TRACKED — not active in default scan. Set active: true to enable.
  {
    id: 'somnia_assumptions',
    name: 'Somnia High-TPS Assumption Violations',
    swc: 'R4qib-002',
    active: false, // ← flip to true before hackathon submission
    prompt: `Analyse this Solidity contract for HIGH-TPS CHAIN ASSUMPTION VIOLATIONS.

This contract will be deployed on Somnia — a 1,000,000 TPS blockchain with 
sub-second finality. Many contracts are written with Ethereum assumptions 
(~12 second block times, ~15-50 tx/block, predictable ordering) that break
or create novel vulnerabilities on a high-throughput chain.

Check for:
- block.timestamp used for randomness, vesting, or time-locks
  (sub-second finality = finer-grained sequencer manipulation)
- block.number used for time calculations
  (at 1M TPS, "1000 blocks" is seconds not days — schedules collapse)
- Assumptions about transaction ordering or predictable sequencing
- Rate limiting logic based on blocks or timestamps that becomes trivially bypassable
- Cooldown periods that assume Ethereum block times
- Any logic where "time passing" is measured in blocks
- Flash loan assumptions — at 1M TPS, atomicity and ordering dynamics differ
- Front-running protections designed for slow chains that fail at high speed

For each finding, explain specifically how the high-TPS environment 
changes the risk profile compared to Ethereum deployment.

Respond with this exact JSON structure:
{
  "category": "somnia_assumptions",
  "swc": "R4qib-002",
  "vulnerable": true|false,
  "confidence": "High|Medium|Low",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "location": "function name or code reference",
      "description": "what assumption is made and why it breaks on Somnia",
      "attack_scenario": "how this could be exploited on a 1M TPS chain",
      "remediation": "how to make this chain-agnostic or Somnia-safe",
      "confidence": "High|Medium|Low"
    }
  ],
  "summary": "one sentence summary"
}`
  }
];

// ── Active Categories Filter ──────────────────────────────────
// Categories with active: false are tracked but excluded from default scans.
// This allows staged rollout without removing tracked work.
export const ACTIVE_CATEGORIES = VULNERABILITY_CATEGORIES.filter(c => c.active !== false);

// ── LLM Call ─────────────────────────────────────────────────
async function callLLM(systemPrompt, userMessage) {
  const body = JSON.stringify({
    model: LLM_MODEL,
    temperature: LLM_TEMPERATURE,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage }
    ],
    stream: false,
  });

  const { default: http } = await import('http');

  return new Promise((resolve, reject) => {
    const options = {
      hostname: LLM_HOST,
      port: LLM_PORT,
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
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

// ── Parse LLM JSON response safely ───────────────────────────
function parseLLMResponse(content, categoryId) {
  try {
    // Strip markdown code fences if present
    const clean = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(clean);
  } catch (e) {
    return {
      category: categoryId,
      vulnerable: null,
      confidence: 'Low',
      findings: [],
      summary: 'Failed to parse LLM response as JSON.',
      parseError: e.message,
      rawResponse: content.slice(0, 500),
    };
  }
}

// ── Analyse Single Category ───────────────────────────────────
export async function analyseCategory(sourceCode, category, contractName = 'Unknown') {
  const userMessage = `Contract name: ${contractName}

Source code:
\`\`\`solidity
${sourceCode}
\`\`\`

${category.prompt}`;

  console.log(`   🔍 Analysing: ${category.name} (${category.swc})...`);

  try {
    const response = await callLLM(SYSTEM_PROMPT, userMessage);
    const result = parseLLMResponse(response, category.id);
    const status = result.vulnerable ? '⚠️  Potential issue found' : '✅ No issues found';
    console.log(`      ${status} — ${result.summary || ''}`);
    return result;
  } catch (e) {
    console.log(`      ❌ Analysis failed: ${e.message}`);
    return {
      category: category.id,
      vulnerable: null,
      confidence: 'Low',
      findings: [],
      summary: `Analysis failed: ${e.message}`,
    };
  }
}

// ── Full Contract Analysis ────────────────────────────────────
// Runs all 8 categories sequentially, returns complete report
export async function analyseContract(address, chainKey = 'somnia-testnet', categories = ACTIVE_CATEGORIES) {
  console.log(`\n👁️  R4qib — Beginning full analysis`);
  console.log(`   Address : ${address}`);
  console.log(`   Chain   : ${chainKey}`);
  console.log(`   Categories: ${categories.length}`);

  // Step 1: Fetch contract
  const contract = await fetchContractForAnalysis(address, chainKey);
  if (!contract.success) {
    return { success: false, error: contract.error };
  }

  if (!contract.hasSource) {
    return {
      success: false,
      error: 'Contract source not verified. Analysis requires verified source code.',
      address,
      bytecodeSize: contract.bytecodeSize,
    };
  }

  console.log(`\n   Running ${categories.length} vulnerability checks on ${contract.name}...\n`);

  // Step 2: Run each category
  const results = [];
  for (const category of categories) {
    const result = await analyseCategory(contract.sourceCode, category, contract.name);
    results.push(result);
  }

  // Step 3: Build summary
  const vulnerableCount = results.filter(r => r.vulnerable === true).length;
  const totalFindings = results.reduce((acc, r) => acc + (r.findings?.length || 0), 0);
  const severities = results.flatMap(r => r.findings?.map(f => f.severity) || []);
  const hasCritical = severities.includes('Critical');
  const hasHigh = severities.includes('High');

  const overallRisk = hasCritical ? 'Critical' :
                      hasHigh ? 'High' :
                      vulnerableCount > 0 ? 'Medium' : 'Low';

  console.log(`\n📋 Analysis complete`);
  console.log(`   Contract    : ${contract.name}`);
  console.log(`   Risk level  : ${overallRisk}`);
  console.log(`   Categories  : ${vulnerableCount}/${categories.length} flagged`);
  console.log(`   Findings    : ${totalFindings} total`);

  return {
    success: true,
    address,
    chain: chainKey,
    contractName: contract.name,
    compilerVersion: contract.compilerVersion,
    bytecodeSize: contract.bytecodeSize,
    analysedAt: new Date().toISOString(),
    overallRisk,
    vulnerableCategories: vulnerableCount,
    totalFindings,
    results,
    // Human-in-the-Loop gate — findings are for review, not auto-action
    reviewRequired: true,
    reviewNote: 'R4qib findings are for human review only. Verify before reporting or acting.',
  };
}
