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

    /// @dev Simulates an external call to a target during MUTATING.
    function mutatingWithExternalCallTo(address target, bytes calldata data) external withMutating {
        (bool success,) = target.call(data);
        require(success, "external call failed");
    }

    /// @dev Should revert: double initialization
    function doubleInit() external {
        _phaseGuardInit();
    }

    /*//////////////////////////////////////////////////////////////
                     ERC-7201 NAMESPACE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns the raw storage slot for the `_phase` field.
    /// The ERC-7201 base slot is the struct root; `_phase` is at offset 0,
    /// and `_phaseStack` is at offset 1 (keccak256 of that for dynamic array data).
    function phaseSlot() external pure returns (bytes32) {
        // keccak256(abi.encode(uint256(keccak256("phaseguard.storage.PhaseGuard")) - 1)) & ~bytes32(uint256(0xff))
        return 0x1b9524599e3b924a74c6b86d062db59fe7ffb1495cb93298113271b051cd8600;
    }

    /// @dev Reads `_phase` directly from the ERC-7201 storage slot (offset 0).
    function rawPhase() external view returns (uint8) {
        bytes32 slot = 0x1b9524599e3b924a74c6b86d062db59fe7ffb1495cb93298113271b051cd8600;
        uint256 value;
        assembly { value := sload(slot) }
        return uint8(value);
    }

    /// @dev Reads the `_phaseStack` array length from the ERC-7201 storage slot (offset 1).
    function rawPhaseStackLength() external view returns (uint256) {
        bytes32 slot = 0x1b9524599e3b924a74c6b86d062db59fe7ffb1495cb93298113271b051cd8600;
        bytes32 stackLengthSlot;
        assembly { stackLengthSlot := add(slot, 1) }
        uint256 length;
        assembly { length := sload(stackLengthSlot) }
        return length;
    }

}
