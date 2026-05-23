# R4qib — Autonomous Smart Contract Investigation (ASCI)

<p align="center">
  <img src="assets/r4qib-logo.png" alt="R4qib" width="160"/>
</p>

> *"He is الرقيب — The Watcher. Nothing escapes His sight."* — Qur'an 4:1

A context-informed on-chain security agent, built natively on Somnia's Agentic L1.

---

## What R4qib Does

Before any analysis begins, R4qib orchestrates three Somnia native agent calls
in sequence — gathering live exploit history, protocol scope, and an adversarial
attack briefing via chain-of-thought reasoning on Qwen3-30B, all
consensus-validated on-chain.

This context informs a deep, sovereign analysis pipeline running locally
with no cloud dependency.

R4qib introduces novel vulnerability categories not covered by any existing
security tool or SWC reference.

Findings metadata and a report hash are anchored on-chain. Full findings stay
off-chain — by design. Security intelligence belongs to the researcher, not
the blockchain.

**Human-in-the-Loop throughout. AI amplifies. Human decides.**

---

## Architecture

```
On-Chain Intelligence Layer (Somnia Agents)
├── JSON API Request    → Live exploit history (DeFiLlama)
├── LLM Parse Website  → Protocol scope (Immunefi)
└── LLM Inference      → Adversarial briefing (Qwen3-30B, chain-of-thought)

Off-Chain Analysis Layer (Local, Sovereign)
├── somnia-connector.js  → Chain-agnostic EVM connector
├── r4qib-analyst.js     → Multi-category LLM reasoning pipeline
└── R4qibAgent.sol       → On-chain agent identity + task anchoring (WIP)
```

---

## Built On

- Somnia Agentic L1 — EVM-compatible, 1M TPS, sub-second finality
- DeepSeek Coder v2 Lite via LMStudio (local inference)
- ethers.js + Node.js + Blockscout API

---

## Submission

Somnia Agentathon via Encode Club — May–June 2026
Built by [@h4dopel0gic](https://github.com/h4dopel0gic)

---

*The Watcher sees what tools miss. Build accordingly.*
