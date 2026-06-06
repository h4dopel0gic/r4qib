# R4qib — الرقيب

<p align="center">
  <img src="assets/r4qib-logo.png" alt="R4qib — The Watcher" width="180"/>
</p>

<p align="center">
  <strong>Autonomous Smart Contract Investigation</strong><br/>
  Built natively on Somnia's Agentic L1
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Somnia-Agentic%20L1-00d4ff?style=flat-square"/>
  <img src="https://img.shields.io/badge/Chain-Ethereum%20Mainnet-627EEA?style=flat-square"/>
  <img src="https://img.shields.io/badge/Model-DeepSeek%20Coder%20v2-00ffaa?style=flat-square"/>
  <img src="https://img.shields.io/badge/Status-Live-00ffaa?style=flat-square"/>
</p>

---

> *"He is الرقيب — The Watcher. Nothing escapes His sight."*
> — Qur'an 4:1
>
> *We do not compare our work to His watching. But we build with that standard in mind: diligence, honesty, and trust.*

---

## What R4qib Does

R4qib is an autonomous smart contract security agent. It is not a static analyser. It is a **reasoning agent** — it understands context, intent, and attack narratives, not just pattern matches.

Before any analysis begins, R4qib orchestrates three Somnia native agent calls in sequence — gathering live exploit history, protocol scope, and an adversarial attack briefing via chain-of-thought reasoning on Qwen3-30B, all consensus-validated on-chain. This context then informs a deep, sovereign analysis pipeline running locally with no cloud dependency.

**Human-in-the-Loop throughout. AI amplifies. Human decides.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Somnia Agentic L1                      │
│                                                         │
│  Agent 1: JSON API → DeFiLlama exploit history         │
│  Agent 2: LLM Parse → Immunefi protocol scope          │
│  Agent 3: LLM Infer → Adversarial briefing (Qwen3-30B) │
│                                                         │
│  R4qibAgent.sol — consensus-validated on-chain         │
│  FindingsAnchored — SHA-256 report hash immutable      │
└──────────────────────────┬──────────────────────────────┘
                           │ ScanComplete event
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Local Sovereign Pipeline                   │
│                                                         │
│  somnia-connector.js — Ethereum mainnet source fetch   │
│  r4qib-analyst.js — DeepSeek Coder v2, 9 categories   │
│  Source chunker — 28KB chunks, 16K context safe        │
│  r4qib-watcher.js — event orchestration               │
│  r4qib-server.js — WebSocket bridge                   │
│  Dashboard — live pipeline UI                          │
│                                                         │
│  ⚠️  HUMAN REVIEW GATE — non-negotiable               │
│                                                         │
│  Reports — sovereign, off-chain, gitignored            │
└─────────────────────────────────────────────────────────┘
```

**What stays on-chain:** contract address, timestamp, scan ID, risk level, findings count, SHA-256 report hash.

**What stays off-chain:** full findings, attack narratives, exploit paths, remediation. Security intelligence belongs to the researcher, not the blockchain.

---

## Vulnerability Categories

### Core (9 Active)

| # | Category | Notes |
|---|---|---|
| 1 | Reentrancy | SWC-107 |
| 2 | Integer Overflow / Underflow | SWC-101 |
| 3 | Access Control Flaws | SWC-105, 106 |
| 4 | Unchecked External Calls | SWC-104 |
| 5 | Flash Loan Attack Vectors | DeFi-specific |
| 6 | Logic Errors & Business Logic | SWC-110, 123 |
| 7 | Front-Running & MEV Exposure | SWC-114 |
| 8 | Upgradability & Proxy Vulnerabilities | SWC-112 |
| 9 | **Semantic Intent Mismatch** | R4qib-001 — NatSpec vs implementation |

### Novel Categories (R4qib Original Research)

**R4qib-001 — Semantic Intent Mismatch**
The gap between what a function name or NatSpec comment claims and what the code actually enforces. Invisible to static analysis tools. Discovered in production DeFi protocols during live scanning.

**R4qib-004 — Unconstrained Off-Chain Completion Authority**
A privileged role calls `complete*()` with a signed output amount. Contract validates the signature but not the amount's relationship to deposited collateral, oracle price, or any hard cap. Confirmed in Resolv Protocol — root cause of the $25M March 2026 exploit.

**R4qib-003 — Agent Trust Boundary Violations**
Novel threat class for on-chain agent architectures. No SWC reference exists. Covers parameter injection, identity spoofing, quorum hijacking, context poisoning, and response fabrication in multi-agent systems.

---

## Live Research Results

R4qib has completed 22 scans on live Ethereum mainnet contracts including post-exploit protocols.

**Resolv Protocol — $25M exploit (March 22, 2026)**
- Scanned `TheCounter.sol` — post-exploit implementation
- Independently confirmed the unfixed architectural flaw: `completeSwap()` still accepts `_targetAmount` with no on-chain collateral ratio validation
- Correctly identified Immunefi scope exclusion — zero false reports submitted
- Confirmed same pattern in `ExternalRequestsManager.completeBurn()` with auditor-acknowledged `slither-disable-next-line` comment

**Parallel Protocol — Certora-verified Diamond proxy**
- Independently corroborated findings matching the protocol's own documented known issues — without access to that documentation
- Demonstrates correct threat modelling sensitivity on formally verified code

**USDT0 — $6M Immunefi bounty**
- Scanned `OAdapterUpgradeable` implementation
- Flash loan vector flagged for source verification

---

## Deployed Contract

**R4qibAgent.sol on Somnia Testnet**

```
Address:  0xaFe929149BD912296F3665a4299F65f76BBCf402
Chain:    Somnia Testnet (Chain ID 50312)
TX:       0x12179d5b108a1bf2446a2b62a2396e97d2217cc518e9d9c015e3f79ea0f3df64
```

---

## Quick Start

**Prerequisites**
- Node.js 18+
- LMStudio with `deepseek-coder-v2-lite-instruct` loaded (16GB VRAM)
- Foundry (for contract deployment)

**Setup**

```bash
git clone https://github.com/h4dopel0gic/r4qib
cd r4qib
npm install
cp .env.example .env
# Fill in your keys — see .env.example
```

**Start (Windows)**

```
Double-click start-r4qib.bat
```

Or manually:

```powershell
node core/r4qib-server.js   # Terminal 1
node core/r4qib-watcher.js  # Terminal 2
```

Open `assets/r4qib-dashboard.html` in browser.

**Trigger a scan**

```powershell
node --input-type=module --eval "
import { triggerScan } from './core/r4qib-watcher.js';
await triggerScan('0xYOUR_TARGET_ADDRESS');
"
```

---

## Environment Variables

```env
R4QIB_AGENT_ADDRESS=    # Deployed R4qibAgent.sol address
R4QIB_SIGNER_KEY=       # Wallet private key (testnet only)
SOMNIA_RPC_URL=         # https://dream-rpc.somnia.network
ALCHEMY_ETH_URL=        # Alchemy Ethereum mainnet endpoint
ETHERSCAN_API_KEY=      # Etherscan V2 API key
LMSTUDIO_BASE_URL=      # http://localhost:1234/v1
LLM_MODEL=              # deepseek-coder-v2-lite-instruct
R4QIB_CHAIN=            # ethereum-mainnet
```

---

## Somnia Agent IDs

| Agent | ID | Purpose |
|---|---|---|
| LLM Inference | `12847293847561029384` | Adversarial briefing — Qwen3-30B |
| LLM Parse Website | `12875401142070969085` | Immunefi protocol scope |
| JSON API Request | `13174292974160097713` | DeFiLlama exploit history |

---

## Design Principles

**Sovereign Intelligence** — Sensitive findings stay off the public record. Metadata proves. Intelligence stays with the researcher.

**Human Gate Non-Negotiable** — R4qib surfaces candidates. The human researcher decides what is real and what is reported. No automated submissions.

**Tool over Demo** — Every design decision filtered through real-world function. This is not a demo. This is a tool.

**Graceful Degradation** — If Somnia agents return unavailable, the pipeline degrades to two-agent mode and continues. Same handling for all failure cases. Scan never hangs.

---

## Hackathon

**Somnia Agentathon via Encode Club** — May 18 – June 7, 2026

Track: *Build the most novel and high-impact agent-driven application on Somnia*

---

## Built By

**h4dopel0gic** — Tobias Stevenson
Sakin.AI · Safina Ecosystem

---

*"The Watcher sees what tools miss. Build accordingly."*
