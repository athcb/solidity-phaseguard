// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ERC20} from "@openzeppelin/token/ERC20/ERC20.sol";

/// @dev ERC20 that calls a hook on a target contract during `transferFrom`.
/// Simulates ERC777-style `tokensToSend` / `tokensReceived` hooks or
/// fee-on-transfer tokens that make external calls mid-transfer.
contract ERC20WithTransferHook is ERC20 {
    address public hookTarget;
    bytes public hookData;

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @dev Set the hook target and calldata. When set, every `transferFrom`
    /// will call `hookTarget` with `hookData` before executing the transfer.
    function setHook(address target, bytes calldata data) external {
        hookTarget = target;
        hookData = data;
    }

    /// @dev Override `_update` to fire the hook before the transfer executes.
    /// `_update` is called by both `transfer` and `transferFrom` in OZ v5.
    function _update(address from, address to, uint256 value) internal virtual override {
        if (hookTarget != address(0)) {
            (bool success, bytes memory returnData) = hookTarget.call(hookData);
            // Bubble up the revert reason so the test can catch it
            if (!success) {
                assembly {
                    revert(add(returnData, 32), mload(returnData))
                }
            }
        }
        super._update(from, to, value);
    }
}
