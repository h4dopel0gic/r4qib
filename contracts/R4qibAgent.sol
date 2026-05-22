// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// R4qibAgent.sol — Autonomous Smart Contract Investigation
// Somnia Agentic L1 — Native Agent Integration
//
// Pipeline (sequential):
//   1. JSON API Request   → DeFiLlama hacks API (exploit history)
//   2. LLM Parse Website  → Immunefi scope (with graceful degradation)
//   3. LLM Inference      → Adversarial briefing (Qwen3-30B, CoT)
//
// On-chain: scan metadata + report hash anchored per scan
// Off-chain: full findings stay sovereign — belong to the researcher
//
// Human-in-the-Loop throughout. AI amplifies. Human decides.
//
// Built by @h4dopel0gic — Sakin.AI / Safina Ecosystem
// Somnia Agentathon — May–June 2026
// ============================================================

// ── Somnia Agent Interface ────────────────────────────────────

enum ConsensusType { Majority, Threshold }

enum ResponseStatus {
    None,       // 0 - uninitialized
    Pending,    // 1 - awaiting responses
    Success,    // 2 - consensus reached
    Failed,     // 3 - validators reported failure
    TimedOut    // 4 - request timed out
}

struct Response {
    address validator;
    bytes   result;
    ResponseStatus status;
    uint256 receipt;
    uint256 timestamp;
    uint256 executionCost;
}

struct Request {
    uint256  id;
    address  requester;
    address  callbackAddress;
    bytes4   callbackSelector;
    address[] subcommittee;
    Response[] responses;
    uint256  responseCount;
    uint256  failureCount;
    uint256  threshold;
    uint256  createdAt;
    uint256  deadline;
    ResponseStatus status;
    ConsensusType  consensusType;
    uint256  remainingBudget;
    uint256  perAgentBudget;
}

interface IAgentRequester {
    event RequestCreated(
        uint256 indexed requestId,
        uint256 indexed agentId,
        uint256 perAgentBudget
    );

    function createRequest(
        uint256 agentId,
        bytes   calldata payload,
        bytes4  callbackSelector
    ) external payable returns (uint256 requestId);

    function getRequestDeposit(
        uint256 agentId,
        uint256 numRunners
    ) external view returns (uint256 deposit);

    function handleResponse(
        uint256        requestId,
        Response[]     memory responses,
        ResponseStatus status,
        Request        memory details
    ) external;
}

// ── R4qibAgent ────────────────────────────────────────────────

contract R4qibAgent {

    // ── Constants ──────────────────────────────────────────────

    address public constant PLATFORM =
        0x037Bb9C718F3f7fe5eCBDB0b600D607b52706776; // Somnia testnet

    uint256 public constant AGENT_JSON_API  = 13174292974160097713; // JSON API Request
    uint256 public constant AGENT_LLM_PARSE = 12875401142070969085; // LLM Parse Website
    uint256 public constant AGENT_LLM_INFER = 12847293847561029384; // LLM Inference (Qwen3-30B)

    uint256 public constant MAX_PARSE_RETRIES = 2;

    // ── Scan State ─────────────────────────────────────────────

    enum ScanStage {
        None,
        AwaitingExploitHistory,   // JSON API → DeFiLlama
        AwaitingScope,            // LLM Parse → Immunefi (attempt 1)
        RetryScopeRequest,        // LLM Parse → Immunefi (attempt 2)
        AwaitingBriefing,         // LLM Inference → adversarial briefing
        Complete
    }

    struct ScanContext {
        address  target;           // contract being investigated
        ScanStage stage;
        uint8    scopeRetries;
        bool     scopeDegraded;    // true if Immunefi scrape gave up
        string   exploitHistory;   // from DeFiLlama
        string   scopeData;        // from Immunefi (may be empty)
        string   briefing;         // from Qwen3-30B
        uint256  startedAt;
        uint256  completedAt;
        // Anchored finding summary (set by owner after off-chain analysis)
        string   riskLevel;        // Critical / High / Medium / Low / Informational
        uint256  findingCount;
        bytes32  reportHash;       // SHA-256 of full off-chain report
        bool     anchored;
    }

    // scanId → context
    mapping(uint256 => ScanContext) public scans;

    // requestId → scanId (so callbacks know which scan they belong to)
    mapping(uint256 => uint256) private _requestToScan;

    uint256 public scanCount;
    address public owner;

    // ── Events ─────────────────────────────────────────────────

    event ScanRequested(uint256 indexed scanId, address indexed target, uint256 timestamp);
    event StageAdvanced(uint256 indexed scanId, ScanStage stage);
    event ScopeDegraded(uint256 indexed scanId, string reason);
    event ScanComplete(
        uint256 indexed scanId,
        address indexed target,
        string  briefingSummary,
        bool    scopeDegraded,
        uint256 timestamp
    );
    event FindingsAnchored(
        uint256 indexed scanId,
        address indexed target,
        string  riskLevel,
        uint256 findingCount,
        bytes32 reportHash,
        uint256 timestamp
    );

    // ── Constructor ────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "R4qib: not owner");
        _;
    }

    modifier onlyPlatform() {
        require(msg.sender == PLATFORM, "R4qib: only platform");
        _;
    }

    receive() external payable {}

    // ── Scan Entry Point ───────────────────────────────────────

    /// @notice Initiate a full R4qib scan pipeline for a target contract
    /// @param target The contract address to investigate
    function requestScan(address target) external onlyOwner returns (uint256 scanId) {
        require(target != address(0), "R4qib: zero address");

        scanId = ++scanCount;

        scans[scanId] = ScanContext({
            target:        target,
            stage:         ScanStage.None,
            scopeRetries:  0,
            scopeDegraded: false,
            exploitHistory: "",
            scopeData:     "",
            briefing:      "",
            startedAt:     block.timestamp,
            completedAt:   0,
            riskLevel:     "",
            findingCount:  0,
            reportHash:    bytes32(0),
            anchored:      false
        });

        emit ScanRequested(scanId, target, block.timestamp);

        // Stage 1: fetch exploit history from DeFiLlama
        _requestExploitHistory(scanId);
    }

    // ── Stage 1: Exploit History (JSON API → DeFiLlama) ────────

    function _requestExploitHistory(uint256 scanId) internal {
        string memory url = "https://api.llama.fi/hacks";
        string memory selector = "$.data[0].name"; // top recent hack — adjust selector as needed

        bytes memory payload = abi.encode(url, selector);

        uint256 deposit = IAgentRequester(PLATFORM).getRequestDeposit(AGENT_JSON_API, 3);

        uint256 requestId = IAgentRequester(PLATFORM).createRequest{value: deposit}(
            AGENT_JSON_API,
            payload,
            this.handleExploitHistory.selector
        );

        _requestToScan[requestId] = scanId;
        scans[scanId].stage = ScanStage.AwaitingExploitHistory;

        emit StageAdvanced(scanId, ScanStage.AwaitingExploitHistory);
    }

    function handleExploitHistory(
        uint256        requestId,
        Response[]     memory responses,
        ResponseStatus status,
        Request        memory /* details */
    ) external onlyPlatform {
        uint256 scanId = _requestToScan[requestId];
        ScanContext storage scan = scans[scanId];

        if (status == ResponseStatus.Success && responses.length > 0) {
            scan.exploitHistory = abi.decode(responses[0].result, (string));
        } else {
            scan.exploitHistory = "unavailable";
        }

        // Advance to Stage 2: scope request
        _requestScope(scanId, false);
    }

    // ── Stage 2: Protocol Scope (LLM Parse → Immunefi) ─────────

    function _requestScope(uint256 scanId, bool isRetry) internal {
        ScanContext storage scan = scans[scanId];

        // Build Immunefi URL — generic hacks page if no specific protocol known
        string memory url      = "https://immunefi.com/explore/";
        string memory key      = "scope";
        string memory desc     = "Extract the current in-scope contracts and maximum bounty amount";
        string memory prompt   = "Return the in-scope contract addresses and max payout as plain text";

        bytes memory payload = abi.encode(
            key,    // key
            desc,   // description
            new string[](0), // options — open-ended
            prompt, // prompt
            url,    // url
            true,   // resolveUrl
            uint8(3), // numPages
            uint8(40) // confidenceThreshold — low enough to get something back
        );

        uint256 deposit = IAgentRequester(PLATFORM).getRequestDeposit(AGENT_LLM_PARSE, 3);

        uint256 requestId = IAgentRequester(PLATFORM).createRequest{value: deposit}(
            AGENT_LLM_PARSE,
            payload,
            this.handleScope.selector
        );

        _requestToScan[requestId] = scanId;

        ScanStage stage = isRetry ? ScanStage.RetryScopeRequest : ScanStage.AwaitingScope;
        scan.stage = stage;

        emit StageAdvanced(scanId, stage);
    }

    function handleScope(
        uint256        requestId,
        Response[]     memory responses,
        ResponseStatus status,
        Request        memory /* details */
    ) external onlyPlatform {
        uint256 scanId = _requestToScan[requestId];
        ScanContext storage scan = scans[scanId];

        bool gotData = (
            status == ResponseStatus.Success &&
            responses.length > 0 &&
            responses[0].result.length > 0
        );

        if (gotData) {
            string memory result = abi.decode(responses[0].result, (string));
            // Treat empty or whitespace-only string as failure
            if (bytes(result).length > 5) {
                scan.scopeData = result;
                _requestBriefing(scanId);
                return;
            }
        }

        // Failed or empty — retry logic
        scan.scopeRetries++;

        if (scan.scopeRetries < MAX_PARSE_RETRIES) {
            // Retry once
            _requestScope(scanId, true);
        } else {
            // Degrade gracefully — proceed without scope data
            scan.scopeDegraded = true;
            scan.scopeData     = "";
            emit ScopeDegraded(scanId, "Scope data unavailable after max retries — proceeding with two-agent mode");
            _requestBriefing(scanId);
        }
    }

    // ── Stage 3: Adversarial Briefing (LLM Inference → Qwen3-30B) ──

    function _requestBriefing(uint256 scanId) internal {
        ScanContext storage scan = scans[scanId];

        // Build context-aware prompt from what we gathered
        string memory contextBlock = string(abi.encodePacked(
            "Exploit history context: ", scan.exploitHistory,
            scan.scopeDegraded ? "" : string(abi.encodePacked(" | Scope: ", scan.scopeData))
        ));

        string memory prompt = string(abi.encodePacked(
            "You are a smart contract security researcher. ",
            contextBlock,
            " Given this context, what are the three most likely attack vectors for this protocol? ",
            "Be specific. Format: VECTOR_1 | VECTOR_2 | VECTOR_3"
        ));

        string memory system =
            "You are an adversarial smart contract security analyst. "
            "Respond with exactly three attack vectors separated by | pipes. "
            "No preamble. No explanation. Just the three vectors.";

        bytes memory payload = abi.encode(
            prompt,    // prompt
            system,    // system
            true,      // chainOfThought
            new string[](0) // allowedValues — open-ended for briefing
        );

        uint256 deposit = IAgentRequester(PLATFORM).getRequestDeposit(AGENT_LLM_INFER, 3);

        uint256 requestId = IAgentRequester(PLATFORM).createRequest{value: deposit}(
            AGENT_LLM_INFER,
            payload,
            this.handleBriefing.selector
        );

        _requestToScan[requestId] = scanId;
        scan.stage = ScanStage.AwaitingBriefing;

        emit StageAdvanced(scanId, ScanStage.AwaitingBriefing);
    }

    function handleBriefing(
        uint256        requestId,
        Response[]     memory responses,
        ResponseStatus status,
        Request        memory /* details */
    ) external onlyPlatform {
        uint256 scanId = _requestToScan[requestId];
        ScanContext storage scan = scans[scanId];

        if (status == ResponseStatus.Success && responses.length > 0) {
            scan.briefing = abi.decode(responses[0].result, (string));
        } else {
            scan.briefing = "Briefing unavailable";
        }

        scan.stage       = ScanStage.Complete;
        scan.completedAt = block.timestamp;

        emit ScanComplete(
            scanId,
            scan.target,
            scan.briefing,
            scan.scopeDegraded,
            block.timestamp
        );
    }

    // ── Anchor Findings (called by owner after off-chain analysis) ──

    /// @notice Anchor the findings summary on-chain after human review
    /// @param scanId       The scan to anchor
    /// @param riskLevel    Overall risk: Critical / High / Medium / Low / Informational
    /// @param findingCount Number of confirmed findings
    /// @param reportHash   SHA-256 hash of the full off-chain report (bytes32)
    function anchorFindings(
        uint256 scanId,
        string  calldata riskLevel,
        uint256 findingCount,
        bytes32 reportHash
    ) external onlyOwner {
        ScanContext storage scan = scans[scanId];
        require(scan.stage == ScanStage.Complete, "R4qib: scan not complete");
        require(!scan.anchored, "R4qib: already anchored");

        scan.riskLevel    = riskLevel;
        scan.findingCount = findingCount;
        scan.reportHash   = reportHash;
        scan.anchored     = true;

        emit FindingsAnchored(
            scanId,
            scan.target,
            riskLevel,
            findingCount,
            reportHash,
            block.timestamp
        );
    }

    // ── View Helpers ───────────────────────────────────────────

    /// @notice Returns the on-chain intelligence gathered for a scan
    function getScanIntelligence(uint256 scanId) external view returns (
        address target,
        ScanStage stage,
        bool    scopeDegraded,
        string  memory exploitHistory,
        string  memory scopeData,
        string  memory briefing,
        uint256 startedAt,
        uint256 completedAt
    ) {
        ScanContext storage s = scans[scanId];
        return (
            s.target,
            s.stage,
            s.scopeDegraded,
            s.exploitHistory,
            s.scopeData,
            s.briefing,
            s.startedAt,
            s.completedAt
        );
    }

    /// @notice Returns the anchored findings summary for a scan
    function getAnchoredFindings(uint256 scanId) external view returns (
        string  memory riskLevel,
        uint256 findingCount,
        bytes32 reportHash,
        bool    anchored
    ) {
        ScanContext storage s = scans[scanId];
        return (s.riskLevel, s.findingCount, s.reportHash, s.anchored);
    }

    /// @notice Withdraw remaining SOMI (owner only)
    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
