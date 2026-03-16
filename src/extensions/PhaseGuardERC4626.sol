// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {PhaseGuard} from "../PhaseGuard.sol";
import {ERC20} from "@openzeppelin/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/token/ERC20/IERC20.sol";
import {ERC4626} from "@openzeppelin/token/ERC20/extensions/ERC4626.sol";
import {Math} from "@openzeppelin/utils/math/Math.sol";

/// @title PhaseGuardERC4626
/// @author 0xathcb
/// @notice ERC4626 vault with PhaseGuard lifecycle protection.
/// @dev Handles all PhaseGuard wiring internally:
/// - Public entry points (deposit, mint, withdraw, redeem) are gated with `withMutating`.
/// - External asset transfers occur during MUTATING — re-entry is blocked by `PhaseStabilityInvariant`.
/// - External views (totalAssets, totalSupply, convertToShares, convertToAssets) are gated with `withView`.
/// - Internal share math uses unguarded helpers to avoid breaking the ERC4626 call chain.
///
/// Usage:
/// ```solidity
/// contract ExampleVault is PhaseGuardERC4626 {
///     constructor(IERC20 asset)
///         ERC4626(asset)
///         ERC20("Vault Share Name", "SYMBOL")
///     {
///         _phaseGuardInit();
///     }
///
///     function _checkAdmin() internal view override {
///         require(msg.sender == owner);
///     }
/// }
/// ```
abstract contract PhaseGuardERC4626 is ERC4626, PhaseGuard {
    using Math for uint256;

    /*//////////////////////////////////////////////////////////////
                PUBLIC ENTRY POINTS: withMutating
    //////////////////////////////////////////////////////////////*/

    function deposit(uint256 assets, address receiver) public virtual override withMutating returns (uint256) {
        return super.deposit(assets, receiver);
    }

    function mint(uint256 shares, address receiver) public virtual override withMutating returns (uint256) {
        return super.mint(shares, receiver);
    }

    function withdraw(uint256 assets, address receiver, address _owner)
        public
        virtual
        override
        withMutating
        returns (uint256)
    {
        return super.withdraw(assets, receiver, _owner);
    }

    function redeem(uint256 shares, address receiver, address _owner)
        public
        virtual
        override
        withMutating
        returns (uint256)
    {
        return super.redeem(shares, receiver, _owner);
    }

    /*//////////////////////////////////////////////////////////////
        PUBLIC VIEW FUNCTIONS: withView
        Guard against read-only reentrancy.
    //////////////////////////////////////////////////////////////*/

    function totalAssets() public view virtual override withView returns (uint256) {
        return _totalAssets();
    }

    function totalSupply() public view virtual override(ERC20, IERC20) withView returns (uint256) {
        return _totalSupply();
    }

    function convertToShares(uint256 assets) public view virtual override withView returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    function convertToAssets(uint256 shares) public view virtual override withView returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /*//////////////////////////////////////////////////////////////
        INTERNAL VIEW FUNCTIONS: Unguarded
        Used internally for share math to avoid triggering
        withView during deposit / mint / withdraw / redeem.
    //////////////////////////////////////////////////////////////*/

    /// @dev Unguarded total assets helper.
    function _totalAssets() internal view virtual returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    /// @dev Unguarded total supply helper.
    /// Calls `super.totalSupply()` to bypass the `withView` guard on the public `totalSupply()` override.
    function _totalSupply() internal view virtual returns (uint256) {
        return super.totalSupply();
    }

    /// @dev Overridden to use `_totalAssets()` and `_totalSupply()` instead of `totalAssets()` and `totalSupply()`.
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view virtual override returns (uint256) {
        return shares.mulDiv(_totalAssets() + 1, _totalSupply() + 10 ** _decimalsOffset(), rounding);
    }

    /// @dev Overridden to use `_totalAssets()` and `_totalSupply()` instead of `totalAssets()` and `totalSupply()`.
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual override returns (uint256) {
        return assets.mulDiv(_totalSupply() + 10 ** _decimalsOffset(), _totalAssets() + 1, rounding);
    }
}
