// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// R4qibAgent.sol - Autonomous Smart Contract Investigation
// Somnia Agentic L1 - Native Agent Integration
//
// Pipeline (sequential):
//   1. JSON API Request   -> DeFiLlama hacks API (exploit history)
//   2. LLM Parse Website  -> Immunefi scope (with graceful degradation)
//   3. LLM Inference      -> Adversarial briefing (Qwen3-30B, CoT)
//
// On-chain: scan metadata + report hash anchored per scan
// Off-chain: full findings stay sovereign - belong to the researcher
//
// Human-in-the-Loop throughout. AI amplifies. Human decides.
//
// Built by @h4dopel0gic - Sakin.AI / Safina Ecosystem
// Somnia Agentathon - May-June 2026
// ============================================================

// -- Somnia Agent Interface (official spec) --------------------

enum ConsensusType { Majority, Threshold }

enum ResponseStatus {
    None,
    Pending,
    Success,
    Failed,
    TimedOut
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
    function createRequest(
        uint256 agentId,
        address callbackAddress,
        bytes4  callbackSelector,
        bytes   calldata payload
    ) external payable returns (uint256 requestId);

    function getRequestDeposit() external view returns (uint256);
}

// -- R4qibAgent ------------------------------------------------

contract R4qibAgent {

    // -- Constants ----------------------------------------------

    address public constant PLATFORM =
        0x037Bb9C718F3f7fe5eCBDB0b600D607b52706776;

    uint256 public constant AGENT_JSON_API  = 13174292974160097713;
    uint256 public constant AGENT_LLM_PARSE = 12875401142070969085;
    uint256 public constant AGENT_LLM_INFER = 12847293847561029384;

    uint256 public constant MAX_PARSE_RETRIES = 2;

    // -- Scan State ---------------------------------------------

    enum ScanStage {
        None,
        AwaitingExploitHistory,
        AwaitingScope,
        RetryScopeRequest,
        AwaitingBriefing,
        Complete
    }

    struct ScanContext {
        address   target;
        ScanStage stage;
        uint8     scopeRetries;
        bool      scopeDegraded;
        string    exploitHistory;
        string    scopeData;
        string    briefing;
        uint256   startedAt;
        uint256   completedAt;
        string    riskLevel;
        uint256   findingCount;
        bytes32   reportHash;
        bool      anchored;
    }

    mapping(uint256 => ScanContext) public scans;
    mapping(uint256 => uint256) private _requestToScan;

    uint256 public scanCount;
    address public owner;

    // -- Events -------------------------------------------------

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

    // -- Constructor --------------------------------------------

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

    // -- Scan Entry Point ---------------------------------------

    function requestScan(address target) external onlyOwner returns (uint256 scanId) {
        require(target != address(0), "R4qib: zero address");

        scanId = ++scanCount;

        scans[scanId] = ScanContext({
            target:         target,
            stage:          ScanStage.None,
            scopeRetries:   0,
            scopeDegraded:  false,
            exploitHistory: "",
            scopeData:      "",
            briefing:       "",
            startedAt:      block.timestamp,
            completedAt:    0,
            riskLevel:      "",
            findingCount:   0,
            reportHash:     bytes32(0),
            anchored:       false
        });

        emit ScanRequested(scanId, target, block.timestamp);
        _requestExploitHistory(scanId);
    }

    // -- Stage 1: Exploit History (JSON API -> DeFiLlama) ------

    function _requestExploitHistory(uint256 scanId) internal {
        bytes memory payload = abi.encode(
            "https://api.llama.fi/hacks",
            "$.data[0].name"
        );

        uint256 deposit = IAgentRequester(PLATFORM).getRequestDeposit();

        uint256 requestId = IAgentRequester(PLATFORM).createRequest{value: deposit}(
            AGENT_JSON_API,
            address(this),
            this.handleExploitHistory.selector,
            payload
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

        _requestScope(scanId, false);
    }

    // -- Stage 2: Protocol Scope (LLM Parse -> Immunefi) -------

    function _requestScope(uint256 scanId, bool isRetry) internal {
        bytes memory payload = abi.encode(
            "scope",
            "Extract the current in-scope contracts and maximum bounty amount",
            new string[](0),
            "Return the in-scope contract addresses and max payout as plain text",
            "https://immunefi.com/explore/",
            true,
            uint8(3),
            uint8(40)
        );

        uint256 deposit = IAgentRequester(PLATFORM).getRequestDeposit();

        uint256 requestId = IAgentRequester(PLATFORM).createRequest{value: deposit}(
            AGENT_LLM_PARSE,
            address(this),
            this.handleScope.selector,
            payload
        );

        _requestToScan[requestId] = scanId;
        ScanStage stage = isRetry ? ScanStage.RetryScopeRequest : ScanStage.AwaitingScope;
        scans[scanId].stage = stage;
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
            if (bytes(result).length > 5) {
                scan.scopeData = result;
                _requestBriefing(scanId);
                return;
            }
        }

        scan.scopeRetries++;

        if (scan.scopeRetries < MAX_PARSE_RETRIES) {
            _requestScope(scanId, true);
        } else {
            scan.scopeDegraded = true;
            scan.scopeData     = "";
            emit ScopeDegraded(scanId, "Scope unavailable after max retries - two-agent mode");
            _requestBriefing(scanId);
        }
    }

    // -- Stage 3: Adversarial Briefing (LLM Inference -> Qwen3-30B) --

    function _requestBriefing(uint256 scanId) internal {
        ScanContext storage scan = scans[scanId];

        string memory contextBlock = string(abi.encodePacked(
            "Exploit history: ", scan.exploitHistory,
            scan.scopeDegraded
                ? ""
                : string(abi.encodePacked(" | Scope: ", scan.scopeData))
        ));

        string memory prompt = string(abi.encodePacked(
            "You are a smart contract security researcher. ",
            contextBlock,
            " What are the three most likely attack vectors? ",
            "Format: VECTOR_1 | VECTOR_2 | VECTOR_3"
        ));

        bytes memory payload = abi.encode(
            prompt,
            "You are an adversarial smart contract security analyst. "
            "Respond with exactly three attack vectors separated by | pipes. "
            "No preamble. No explanation.",
            true,
            new string[](0)
        );

        uint256 deposit = IAgentRequester(PLATFORM).getRequestDeposit();

        uint256 requestId = IAgentRequester(PLATFORM).createRequest{value: deposit}(
            AGENT_LLM_INFER,
            address(this),
            this.handleBriefing.selector,
            payload
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

        scan.briefing = (status == ResponseStatus.Success && responses.length > 0)
            ? abi.decode(responses[0].result, (string))
            : "Briefing unavailable";

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

    // -- Anchor Findings ----------------------------------------

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

    // -- View Helpers -------------------------------------------

    function getScanIntelligence(uint256 scanId) external view returns (
        address   target,
        ScanStage stage,
        bool      scopeDegraded,
        string memory exploitHistory,
        string memory scopeData,
        string memory briefing,
        uint256   startedAt,
        uint256   completedAt
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

    function getAnchoredFindings(uint256 scanId) external view returns (
        string memory riskLevel,
        uint256 findingCount,
        bytes32 reportHash,
        bool    anchored
    ) {
        ScanContext storage s = scans[scanId];
        return (s.riskLevel, s.findingCount, s.reportHash, s.anchored);
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
