// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { PhaseGuardMock } from "./PhaseGuardMock.sol";

/// @dev Simulates an ERC721 receiver that returns the expected selector on callback.
/// Represents the legitimate `onERC721Received` pattern: receive token, return selector, done.
contract ERC721Receiver {
    bytes4 public constant ERC721_RECEIVED = bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
    bool public called;

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        called = true;
        return ERC721_RECEIVED;
    }
}

/// @dev Simulates an ERC1155 receiver that returns the expected selector on callback.
/// Represents the legitimate `onERC1155Received` pattern.
contract ERC1155Receiver {
    bytes4 public constant ERC1155_RECEIVED = bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
    bool public called;

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4) {
        called = true;
        return ERC1155_RECEIVED;
    }
}

/// @dev Simulates an ERC777 `tokensReceived` hook that simply acknowledges receipt.
/// Represents the legitimate callback: log the event and return.
contract ERC777Receiver {
    bool public called;

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        called = true;
    }
}

/// @dev Simulates a flash loan borrower that executes logic on a *separate* target (not the lender).
/// Represents the legitimate pattern: receive callback, do arbitrage elsewhere, return.
contract FlashLoanBorrower {
    bool public called;
    address public arbTarget;
    bytes public arbData;

    /// @dev Configure the external arbitrage call the borrower will make.
    function setArbCall(address target, bytes calldata data) external {
        arbTarget = target;
        arbData = data;
    }

    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32) {
        called = true;

        // Legitimate: the borrower calls a *different* contract for arbitrage, not the lender.
        if (arbTarget != address(0)) {
            (bool success,) = arbTarget.call(arbData);
            require(success, "arb call failed");
        }

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

/// @dev Malicious receiver that attempts to re-enter the PhaseGuard contract during a callback.
/// Used to prove that views and mutating calls are blocked during CALLBACKING.
contract MaliciousCallbackReceiver {
    PhaseGuardMock public target;
    enum AttackType { VIEW, MUTATING }
    AttackType public attackType;

    constructor(address _target) {
        target = PhaseGuardMock(_target);
    }

    function setAttackType(AttackType _type) external {
        attackType = _type;
    }

    /// @dev Called as onERC721Received — but tries to re-enter the guarded contract.
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        if (attackType == AttackType.VIEW) {
            target.dummyView();
        } else {
            target.dummyMutating();
        }
        return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
    }
}
