// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { PhaseGuardERC4626Mock } from "../mocks/PhaseGuardERC4626Mock.sol";
import { ERC20Mock } from "../mocks/ERC20Mock.sol";
import { ERC20WithTransferHook } from "../mocks/ERC20WithTransferHook.sol";
import { PhaseGuard } from "../../src/PhaseGuard.sol";
import { PhaseGuardERC4626 } from "../../src/extensions/PhaseGuardERC4626.sol";
import { IERC20 } from "@openzeppelin/token/ERC20/IERC20.sol";
import { Test, console2 } from "forge-std/Test.sol";


contract PhaseGuardERC4626Test is Test {
    PhaseGuardERC4626Mock public pgVault;
    ERC20Mock public asset;

    address public owner;
    address public user;

    // Phases
    PhaseGuard.Phase constant UNINITIALIZED = PhaseGuard.Phase.UNINITIALIZED;
    PhaseGuard.Phase constant READY = PhaseGuard.Phase.READY;
    PhaseGuard.Phase constant MUTATING = PhaseGuard.Phase.MUTATING;
    PhaseGuard.Phase constant EXTERNALIZING = PhaseGuard.Phase.EXTERNALIZING;
    PhaseGuard.Phase constant CALLBACKING = PhaseGuard.Phase.CALLBACKING;
    PhaseGuard.Phase constant FINALIZED = PhaseGuard.Phase.FINALIZED;
    PhaseGuard.Phase constant PAUSED = PhaseGuard.Phase.PAUSED;
    PhaseGuard.Phase constant MAINTENANCE = PhaseGuard.Phase.MAINTENANCE;
    
    // Phase array
    PhaseGuard.Phase[8] public phaseArray = [UNINITIALIZED, READY, MUTATING, EXTERNALIZING, CALLBACKING, FINALIZED, PAUSED, MAINTENANCE];

    // Policy bit flags
    uint8 constant ALLOW_USER        = 1 << 0;
    uint8 constant ALLOW_ADMIN       = 1 << 1;
    uint8 constant ALLOW_EXTERNAL    = 1 << 2;
    uint8 constant ALLOW_VALUE       = 1 << 3;
    uint8 constant ALLOW_VIEWS       = 1 << 4;
    uint8 constant ALLOW_WRITES      = 1 << 5;
    uint8 constant ALLOW_CALLBACKS   = 1 << 6;
    uint8 constant ALLOW_DELEGATECALL = 1 << 7;

    function setUp() public {
        // Underlying asset
        asset = new ERC20Mock("My Asset", "ASSET");
        // Deploy vault with asset
        pgVault = new PhaseGuardERC4626Mock(asset);
        
        owner = address(this);
        user = makeAddr("user");

        // Mint tokens to user and approve vault
        asset.mint(user, 10_000_000);
        vm.prank(user);
        asset.approve(address(pgVault), 10_000_000);

        // Mint tokens to owner and approve vault
        asset.mint(owner, 10_000_000);
        vm.prank(owner);
        asset.approve(address(pgVault), 10_000_000);
    }

    /*//////////////////////////////////////////////////////////////
                             INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @dev PhaseGuard vault is in phase READY after deployment with the 
    // correct underlying asset, name and symbol
    function test_VaultIsDeployedCorrectly() public view {
        assertEq(uint8(pgVault.phase()), uint8(READY));
        assertEq(pgVault.asset(), address(asset));
        assertEq(pgVault.name(), "PhaseGuard Vault Share");
        assertEq(pgVault.symbol(), "pgvSHARE");
    }

    /*//////////////////////////////////////////////////////////////
                                DEPOSIT
    //////////////////////////////////////////////////////////////*/

    /// @dev When a user deposits assets and receives shares the PhaseGuard events 
    // are correctly emitted (happy path)
    // READY -> MUTATING -> EXTERNALIZING (`_transferIn`) -> MUTATING -> READY
    function test_DepositCorrectlyEmitsEvents() public {
        uint256 amount = 1_000;
        uint256 balanceAssetsBefore = asset.balanceOf(user);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(user);
       
        // Assert that events for the following phase transitions are emitted:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        // 2. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 3. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
        // 4. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);

        vm.prank(user);
        pgVault.deposit(amount, user);
        uint256 balanceAssetsAfter = asset.balanceOf(user);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(user);
      
        // Assert that `deposit` correctly transferred assets in and transferred vault shares out
        assertEq(balanceAssetsAfter, balanceAssetsBefore - amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore + amount);
    }

    /// @dev MAINTENANCE phase: deposit should succeed for admins
    function test_DepositInMaintenanceSucceedsForAdmins() public {
        uint256 amount = 1_000;
        uint256 balanceAssetsBefore = asset.balanceOf(owner);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(user);
        vm.startPrank(owner);
        pgVault.transitionTo(MAINTENANCE);

        pgVault.deposit(amount, user);
        vm.stopPrank();
        uint256 balanceAssetsAfter = asset.balanceOf(owner);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(user);

        // Assert that `deposit` correctly transferred assets in and transferred vault shares out
        assertEq(balanceAssetsAfter, balanceAssetsBefore - amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore + amount);
    }

    /// @dev MAINTENANCE phase: deposit should revert for non-admins 
    function test_DepositInMaintenanceRevertsForNonAdmins() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(MAINTENANCE);

        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.deposit(amount, user);
    }

    /// @dev PAUSED phase: deposit should revert
    function test_DepositInPausedReverts() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(PAUSED);

        // Non-admin: blocked by _checkAdmin(). Reverts with `AccessDenied`
        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.deposit(amount, user);

        // Admin: passes _checkAdmin() but PAUSED → MUTATING is not allowed in the transition matrix
        // reverts with `TransitionGateLocked`
        vm.expectRevert(PhaseGuard.TransitionGateLocked.selector);
        vm.prank(owner);
        pgVault.deposit(amount, user);
    }

    /// @dev FINALIZED phase: ALLOW_USER and ALLOW_ADMIN are off so deposit reverts with `PolicyGateLocked` 
    function test_DepositInFinalizedReverts() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(FINALIZED);

        // Non-admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(user);
        pgVault.deposit(amount, user);

        // Admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(owner);
        pgVault.deposit(amount, user);
    }

    /*//////////////////////////////////////////////////////////////
                                  MINT
    //////////////////////////////////////////////////////////////*/

    /// @dev When a user mints shares the PhaseGuard events are correctly emitted (happy path)
    // READY -> MUTATING -> EXTERNALIZING (`_transferIn`) -> MUTATING -> READY

    function test_MintCorrectlyEmitsEvents() public {
        uint256 amount = 1_000;
        uint256 balanceAssetsBefore = asset.balanceOf(user);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(user);
       
        // Assert that events for the following phase transitions are emitted:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        // 2. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 3. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
        // 4. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);

        vm.prank(user);
        pgVault.mint(amount, user);
        uint256 balanceAssetsAfter = asset.balanceOf(user);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(user);
      
        // Assert that `mint` correctly transferred assets in and transferred vault shares out
        assertEq(balanceAssetsAfter, balanceAssetsBefore - amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore + amount);
    }

    /// @dev MAINTENANCE phase: mint should succeed for admins
    function test_MintInMaintenanceSucceedsForAdmins() public {
        uint256 amount = 1_000;
        uint256 balanceAssetsBefore = asset.balanceOf(owner);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(user);
        vm.startPrank(owner);
        pgVault.transitionTo(MAINTENANCE);

        pgVault.mint(amount, user);
        vm.stopPrank();
        uint256 balanceAssetsAfter = asset.balanceOf(owner);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(user);

        // Assert that `mint` correctly transferred assets in and transferred vault shares out
        assertEq(balanceAssetsAfter, balanceAssetsBefore - amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore + amount);
    }

    /// @dev MAINTENANCE phase: mint should revert for non-admins 
    function test_MintInMaintenanceRevertsForNonAdmins() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(MAINTENANCE);

        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.mint(amount, user);
    }

    /// @dev PAUSED phase: mint should revert
    function test_MintInPausedReverts() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(PAUSED);

        // Non-admin: blocked by _checkAdmin(). Reverts with `AccessDenied`
        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.mint(amount, user);

        // Admin: passes _checkAdmin() but PAUSED → MUTATING is not allowed in the transition matrix
        // reverts with `TransitionGateLocked`
        vm.expectRevert(PhaseGuard.TransitionGateLocked.selector);
        vm.prank(owner);
        pgVault.mint(amount, user);
    }

    /// @dev FINALIZED phase: ALLOW_USER and ALLOW_ADMIN are off so mint reverts with `PolicyGateLocked` 
    function test_MintInFinalizedReverts() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(FINALIZED);

        // Non-admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(user);
        pgVault.mint(amount, user);

        // Admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(owner);
        pgVault.mint(amount, user);
    } 

    /*//////////////////////////////////////////////////////////////
                                WITHDRAW
    //////////////////////////////////////////////////////////////*/

    /// @dev When a user withdraws assets and their vault shares are burned 
    // the PhaseGuard events are correctly emitted (happy path)
    // READY -> MUTATING -> EXTERNALIZING (`_transferOut`) -> MUTATING -> READY
    function test_WithdrawCorrectlyEmitsEvents() public {
        uint256 amount = 1_000;
        vm.prank(user);
        pgVault.deposit(amount, user);
       
        // Assert that events for the following phase transitions are emitted:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        // 2. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 3. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
        // 4. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);

        uint256 balanceAssetsBefore = asset.balanceOf(user);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(user);
        
        vm.prank(user);
        pgVault.withdraw(amount, user, user);

        uint256 balanceAssetsAfter = asset.balanceOf(user);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(user);
      
        // Assert that `withdraw` correctly transferred assets in and transferred vault shares out
        assertEq(balanceAssetsAfter, balanceAssetsBefore + amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore - amount);
    }

    /// @dev MAINTENANCE phase: withdraw should succeed for admins
    function test_WithdrawInMaintenanceSucceedsForAdmins() public {
        uint256 amount = 1_000;
        vm.prank(owner);
        pgVault.deposit(amount, owner);

        uint256 balanceAssetsBefore = asset.balanceOf(owner);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(owner);

        vm.startPrank(owner);
        pgVault.transitionTo(MAINTENANCE);

        pgVault.withdraw(amount, owner, owner);
        vm.stopPrank();
        uint256 balanceAssetsAfter = asset.balanceOf(owner);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(owner);

        // Assert that `withdraw` correctly transferred assets out and burned vault shares
        assertEq(balanceAssetsAfter, balanceAssetsBefore + amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore - amount);
    }

    /// @dev MAINTENANCE phase: withdraw should revert for non-admins 
    function test_WithdrawInMaintenanceRevertsForNonAdmins() public {
        uint256 amount = 1_000;
        vm.prank(user);
        pgVault.mint(amount, user);
        
        vm.prank(owner);
        pgVault.transitionTo(MAINTENANCE);

        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.withdraw(amount, user, user);
    }

    /// @dev PAUSED phase: withdraw should revert
    function test_WithdrawInPausedReverts() public {
        uint256 amount = 1_000;
        vm.prank(user);
        pgVault.mint(amount, user);
        
        vm.prank(owner);
        pgVault.transitionTo(PAUSED);

        // Non-admin: blocked by _checkAdmin(). Reverts with `AccessDenied`
        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.withdraw(amount, user, user);

        // Admin: passes _checkAdmin() but PAUSED → MUTATING is not allowed in the transition matrix
        // reverts with `TransitionGateLocked`
        vm.expectRevert(PhaseGuard.TransitionGateLocked.selector);
        vm.prank(owner);
        pgVault.withdraw(amount, user, user);
    }

    /// @dev FINALIZED phase: ALLOW_USER and ALLOW_ADMIN are off so withdraw reverts with `PolicyGateLocked` 
    function test_WithdrawInFinalizedReverts() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(FINALIZED);

        // Non-admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(user);
        pgVault.withdraw(amount, user, user);

        // Admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(owner);
        pgVault.withdraw(amount, user, user);
    } 
    

    /*//////////////////////////////////////////////////////////////
                                 REDEEM
    //////////////////////////////////////////////////////////////*/

    // function redeem(uint256 shares, address receiver, address owner) public virtual returns (uint256) {
    /// @dev When a user redeems shares they receive the corresponding assets, their vault shares are burned 
    // the PhaseGuard events are correctly emitted (happy path)
    // READY -> MUTATING -> EXTERNALIZING (`_transferOut`) -> MUTATING -> READY
    function test_RedeemCorrectlyEmitsEvents() public {
        uint256 amount = 1_000;
        vm.prank(user);
        pgVault.deposit(amount, user);
       
        // Assert that events for the following phase transitions are emitted:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        // 2. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 3. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
        // 4. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);

        uint256 balanceAssetsBefore = asset.balanceOf(user);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(user);
        
        vm.prank(user);
        pgVault.redeem(amount, user, user);

        uint256 balanceAssetsAfter = asset.balanceOf(user);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(user);
      
        // Assert that `redeem` correctly transferred assets out and burned vault shares
        assertEq(balanceAssetsAfter, balanceAssetsBefore + amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore - amount);
    }

    /// @dev MAINTENANCE phase: redeem should succeed for admins
    function test_RedeemInMaintenanceSucceedsForAdmins() public {
        uint256 amount = 1_000;
        vm.prank(owner);
        pgVault.deposit(amount, owner);

        uint256 balanceAssetsBefore = asset.balanceOf(owner);
        uint256 balanceVaultSharesBefore = pgVault.balanceOf(owner);

        vm.startPrank(owner);
        pgVault.transitionTo(MAINTENANCE);

        pgVault.redeem(amount, owner, owner);
        vm.stopPrank();
        uint256 balanceAssetsAfter = asset.balanceOf(owner);
        uint256 balanceVaultSharesAfter = pgVault.balanceOf(owner);

        // Assert that `redeem` correctly transferred assets out and burned vault shares
        assertEq(balanceAssetsAfter, balanceAssetsBefore + amount);
        assertEq(balanceVaultSharesAfter, balanceVaultSharesBefore - amount);
    }

    /// @dev MAINTENANCE phase: redeem should revert for non-admins 
    function test_RedeemInMaintenanceRevertsForNonAdmins() public {
        uint256 amount = 1_000;
        vm.prank(user);
        pgVault.mint(amount, user);
        
        vm.prank(owner);
        pgVault.transitionTo(MAINTENANCE);

        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.redeem(amount, user, user);
    }

    /// @dev PAUSED phase: redeem should revert
    function test_RedeemInPausedReverts() public {
        uint256 amount = 1_000;
        vm.prank(user);
        pgVault.mint(amount, user);
        
        vm.prank(owner);
        pgVault.transitionTo(PAUSED);

        // Non-admin: blocked by _checkAdmin(). Reverts with `AccessDenied`
        vm.expectRevert(PhaseGuardERC4626Mock.AccessDenied.selector);
        vm.prank(user);
        pgVault.redeem(amount, user, user);

        // Admin: passes _checkAdmin() but PAUSED → MUTATING is not allowed in the transition matrix
        // reverts with `TransitionGateLocked`
        vm.expectRevert(PhaseGuard.TransitionGateLocked.selector);
        vm.prank(owner);
        pgVault.redeem(amount, user, user);
    }

    /// @dev FINALIZED phase: ALLOW_USER and ALLOW_ADMIN are off so redeem reverts with `PolicyGateLocked` 
    function test_RedeemInFinalizedReverts() public {
        uint256 amount = 1_000;
        
        vm.prank(owner);
        pgVault.transitionTo(FINALIZED);

        // Non-admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(user);
        pgVault.redeem(amount, user, user);

        // Admin: reverts with `PolicyGateLocked` 
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        vm.prank(owner);
        pgVault.redeem(amount, user, user);
    } 
    

    /*//////////////////////////////////////////////////////////////
                             VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev totalAssets, totalSupply, convertToAssets, convertToShares: 
    // should return correct value in stable phases (ALLOW_VIEWS on): READY, PAUSED, MAINTENANCE, FINALIZED
    function test_ViewFunctionsSucceedInStablePhases() public {
        // Deposit 1_000 assets to vault and mint 1_000 vault shares to user
        uint256 amount = 1_000;
        vm.prank(user);
        pgVault.deposit(amount, user);

        // READY (already in READY after deposit)
        _assertViewsReturn(amount);

        // PAUSED (READY -> PAUSED)
        vm.prank(owner);
        pgVault.transitionTo(PAUSED);
        _assertViewsReturn(amount);

        // MAINTENANCE (PAUSED -> MAINTENANCE)
        vm.prank(owner);
        pgVault.transitionTo(MAINTENANCE);
        _assertViewsReturn(amount);

        // FINALIZED (MAINTENANCE -> READY -> FINALIZED) 
        vm.prank(owner);
        pgVault.transitionTo(READY);
        vm.prank(owner);
        pgVault.transitionTo(FINALIZED);
        _assertViewsReturn(amount);
    }

    /// @dev totalAssets, totalSupply, convertToAssets, convertToShares: 
    // should each revert with `ViewsLocked` when called via a transfer hook 
    // during an unstable phase (ALLOW_VIEWS off): MUTATING, EXTERNALIZING, CALLBACKING.
    // Each iteration deploys a fresh token+vault so the hook selector is the only variable.
    function test_ViewFunctionsRevertInUnstablePhases() public {
        bytes4[4] memory selectors = [
            PhaseGuardERC4626.totalAssets.selector,
            PhaseGuardERC4626.totalSupply.selector,
            PhaseGuardERC4626.convertToShares.selector,
            PhaseGuardERC4626.convertToAssets.selector
        ];

        for (uint256 i = 0; i < selectors.length; i++) {
            // Fresh token + vault per selector so hook state is clean
            ERC20WithTransferHook hookToken = new ERC20WithTransferHook("Hook Token", "HKT");
            PhaseGuardERC4626Mock hookVault = new PhaseGuardERC4626Mock(hookToken);

            uint256 amount = 1_000;
            hookToken.mint(user, amount);
            vm.prank(user);
            hookToken.approve(address(hookVault), amount);

            // Build calldata: totalAssets/totalSupply take no args, convertTo* takes uint256
            bytes memory hookData;
            if (
                selectors[i] == PhaseGuardERC4626.convertToShares.selector || 
                selectors[i] == PhaseGuardERC4626.convertToAssets.selector
            ) {
                hookData = abi.encodeWithSelector(selectors[i], amount);
            } else {
                hookData = abi.encodeWithSelector(selectors[i]);
            }

            hookToken.setHook(address(hookVault), hookData);

            // deposit triggers: READY -> MUTATING -> EXTERNALIZING -> transferFrom -> _update -> hook
            // The hook calls the view while in EXTERNALIZING (ALLOW_VIEWS off) -> ViewsLocked
            vm.prank(user);
            vm.expectRevert(PhaseGuard.ViewsLocked.selector);
            hookVault.deposit(amount, user);
        }
    }

    /// @dev Helper: asserts all four view functions return expected values for a 1:1 vault.
    function _assertViewsReturn(uint256 amount) internal view {
        assertEq(pgVault.totalAssets(), amount);
        assertEq(pgVault.totalSupply(), amount);
        assertEq(pgVault.convertToShares(amount), amount);
        assertEq(pgVault.convertToAssets(amount), amount);
    }

}
