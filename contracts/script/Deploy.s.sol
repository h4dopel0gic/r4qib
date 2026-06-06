// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/R4qibAgent.sol";

contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("R4QIB_SIGNER_KEY");
        vm.startBroadcast(deployerKey);
        R4qibAgent agent = new R4qibAgent();
        console.log("R4qibAgent deployed:", address(agent));
        vm.stopBroadcast();
    }
}