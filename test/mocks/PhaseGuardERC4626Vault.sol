// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { PhaseGuardERC4626 } from "../../src/extensions/PhaseGuardERC4626.sol";
import { IERC20 } from "@openzeppelin/token/ERC20/IERC20.sol";
import { ERC20 } from "@openzeppelin/token/ERC20/ERC20.sol";
import { ERC4626 } from "@openzeppelin/token/ERC20/extensions/ERC4626.sol";

contract PhaseGuardERC4626Vault is PhaseGuardERC4626 {

    error AccessDenied();

    address public owner;

    constructor(IERC20 _asset) 
        ERC4626(_asset)
        ERC20("PhaseGuard Vault Share", "pgvSHARE") 
    {
        owner = msg.sender;

        _phaseGuardInit();
    }

    /// @dev Implement _checkAdmin() with custom access control.
    function _checkAdmin() internal view override {
        if(msg.sender != owner) revert AccessDenied();
    }
}