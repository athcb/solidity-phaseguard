// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IPhaseGuard
/// @notice Minimal standard interface for PhaseGuard lifecycle contracts.
interface IPhaseGuard {

    /// @notice Emitted when the contract transitions to a new phase.
    /// @param fromPhase Phase being exited. 
    /// @param toPhase  Phase being entered.
    event PhaseTransition(uint8 indexed fromPhase, uint8 indexed toPhase);

    /// @notice Returns the current global phase of the contract.
    /// @return The active phase identifier.
    function phase() external view returns (uint8);

    /// @notice Returns the policy bitmask for a given phase.
    /// @param phase_ Phase whose policy is being queried.
    /// @return The policy bitmask (bit 0 = ALLOW_USER, bit 1 = ALLOW_ADMIN, bit 2 = ALLOW_VIEWS).
    function getPolicy(uint8 phase_) external pure returns (uint8); 

    /// @notice Evaluates whether a forward transition between two phases is allowed.
    /// @param from Phase being exited.
    /// @param to Phase being entered.
    /// @return True if the transition is permitted by the transition matrix.
    function isTransitionAllowed(uint8 from, uint8 to) external pure returns (bool);
}