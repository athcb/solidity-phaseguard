// SPDX-License-Identifier: MIT
pragma solidity 0.8.30; 

import { PhaseGuard } from "../../src/PhaseGuard.sol";

/// @dev PhaseGuard implementation that exposes internal functions for unit testing.
contract PhaseGuardMock is PhaseGuard {

    address public owner;
    uint256 public counter;

    error AccessDenied();

    constructor() {
        owner = msg.sender;

        // Initialize PhaseGuard
        _phaseGuardInit();
    }

    // Override for access control 
    function _checkAdmin() internal view override {
        if (msg.sender != owner) revert AccessDenied();
    }

    /*//////////////////////////////////////////////////////////////
                            EXPOSE MODIFIERS
    //////////////////////////////////////////////////////////////*/

    function dummyMutating() external withMutating {
        counter += 1;   
    }

    function dummyView() external view withView returns (uint256) {
        return counter;
    }

    /*//////////////////////////////////////////////////////////////
                           COMPOSITE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Happy path: READY -> MUTATING -> EXTERNALIZING -> MUTATING -> READY 
    function mutatingWithExternalCall() external withMutating {
        _startExternalizing();
        _endExternalizing();
    }

    /// @dev Happy path: READY -> MUTATING -> EXTERNALIZING -> CALLBACKING -> EXTERNALIZING -> MUTATING -> READY 
    function mutatingWithCallback() external withMutating {
        _startExternalizingWithCallback();
        _endExternalizingWithCallback();
    }

    /// @dev Happy path: Multiple READY -> MUTATING -> EXTERNALIZING -> MUTATING -> READY 
    function mutatingWithMultipleExternalCalls() external withMutating {
        // First external call
        _startExternalizing();
        _endExternalizing();

        // Second external call
        _startExternalizing();
        _endExternalizing();
    }


    /// @dev Happy path: external call then external call with callback
    function mutatingWithMixedExternalCalls() external withMutating {
        // First external call
        _startExternalizing();
        _endExternalizing();

        // Second external call
        _startExternalizingWithCallback();
        _endExternalizingWithCallback();
    }

    /// @dev Should revert: EXTERNALIZING -> EXTERNALIZING not allowed
    function mutatingWithNestedExternalCalls() external withMutating {
        _startExternalizing();
        _startExternalizing(); 
        _endExternalizing();
        _endExternalizing();
    }

    /// @dev Should revert: missing state unwinding via `_endExternalizing`
    function missingNestedExternalCalls() external withMutating {
        _startExternalizing();
    }

    /// @dev Should revert: _startExternalizingWithCallback needs _endExternalizingWithCallback to pop two stack frames
    function incorrectEndHelperPairing() external withMutating {
        _startExternalizingWithCallback();
        _endExternalizing();
    }

    /// @dev Should revert: _startExternalizing needs _endExternalizing to pop one stack frame
    function incorrectStartHelperPairing() external withMutating {
        _startExternalizing();
        _endExternalizingWithCallback();
    }

    /// @dev Should revert: double initialization
    function doubleInit() external {
        _phaseGuardInit();
    }

    /// @dev Should revert: externalizing from READY
    function externalizingFromReady() external {
        _startExternalizing();
    }

    /// @dev Should revert: calling _startCallbacking from READY (not EXTERNALIZING)
    function callbackingFromReady() external {
        _startCallbacking();
    }

    /// @dev Simulates an external call to a target during EXTERNALIZING
    function mutatingWithExternalCallTo(address target, bytes calldata data) external withMutating {
        _startExternalizing();
        (bool success,) = target.call(data);
        require(success, "external call failed");
        _endExternalizing();
    }

    /// @dev Simulates an external call with callback to a target
    function mutatingWithCallbackTo(address target, bytes calldata data) external withMutating {
        _startExternalizingWithCallback();
        (bool success,) = target.call(data);
        require(success, "external call failed");
        _endExternalizingWithCallback();
    }


}
