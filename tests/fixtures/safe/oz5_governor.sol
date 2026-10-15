// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
contract MyGovernor is Governor, GovernorSettings, GovernorCountingSimple, GovernorVotes, GovernorVotesQuorumFraction {
    constructor(IVotes t) Governor("MyGovernor") GovernorSettings(7200, 50400, 0) GovernorVotes(t) GovernorVotesQuorumFraction(4) {}
    function votingDelay() public view override(Governor, GovernorSettings) returns (uint256) { return super.votingDelay(); }
    function votingPeriod() public view override(Governor, GovernorSettings) returns (uint256) { return super.votingPeriod(); }
    function quorum(uint256 b) public view override(Governor, GovernorVotesQuorumFraction) returns (uint256) { return super.quorum(b); }
    function proposalThreshold() public view override(Governor, GovernorSettings) returns (uint256) { return super.proposalThreshold(); }
}
