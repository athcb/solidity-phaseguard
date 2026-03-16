// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {PhaseGuard} from "../../src/PhaseGuard.sol";
import {ReentrancyGuard} from "@openzeppelin/utils/ReentrancyGuard.sol";
import {Test} from "forge-std/Test.sol";

/// @title Gas Benchmarks — PhaseGuard vs OZ ReentrancyGuard
/// @notice Isolated gas measurements for the guard overhead on each operation type.
/// Run with `forge test --mc GasBenchmark --gas-report` or `forge snapshot`.

/*//////////////////////////////////////////////////////////////
                      PHASEGUARD VAULT
//////////////////////////////////////////////////////////////*/

contract PhaseGuardVault is PhaseGuard {
    mapping(address => uint256) public balances;

    constructor() {
        _phaseGuardInit();
    }

    function _checkAdmin() internal view override {
        require(msg.sender == address(1), "not admin");
    }

    function deposit() external payable withMutating {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external withMutating {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function totalDeposits(address account) external view withView returns (uint256) {
        return balances[account];
    }
}

/*//////////////////////////////////////////////////////////////
              OZ REENTRANCYGUARD VAULT (BASELINE)
//////////////////////////////////////////////////////////////*/

contract OZGuardVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable nonReentrant {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function totalDeposits(address account) external view returns (uint256) {
        return balances[account];
    }
}

/*//////////////////////////////////////////////////////////////
                  BARE VAULT (NO GUARD AT ALL)
//////////////////////////////////////////////////////////////*/

contract BareVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function totalDeposits(address account) external view returns (uint256) {
        return balances[account];
    }
}

/*//////////////////////////////////////////////////////////////
                          BENCHMARKS
//////////////////////////////////////////////////////////////*/

contract GasBenchmark is Test {
    PhaseGuardVault pg;
    OZGuardVault oz;
    BareVault bare;
    address user;

    function setUp() public {
        pg = new PhaseGuardVault();
        oz = new OZGuardVault();
        bare = new BareVault();
        user = makeAddr("user");
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                       DEPOSIT (COLD → WARM SLOT)
    //////////////////////////////////////////////////////////////*/

    /// @dev First deposit — cold storage slot (balances[user] goes from 0 → value).
    function test_gas_deposit_cold_PhaseGuard() public {
        vm.prank(user);
        pg.deposit{value: 1 ether}();
    }

    function test_gas_deposit_cold_OZGuard() public {
        vm.prank(user);
        oz.deposit{value: 1 ether}();
    }

    function test_gas_deposit_cold_Bare() public {
        vm.prank(user);
        bare.deposit{value: 1 ether}();
    }

    /// @dev Second deposit — warm storage slot.
    function test_gas_deposit_warm_PhaseGuard() public {
        vm.startPrank(user);
        pg.deposit{value: 1 ether}();
        pg.deposit{value: 1 ether}();
        vm.stopPrank();
    }

    function test_gas_deposit_warm_OZGuard() public {
        vm.startPrank(user);
        oz.deposit{value: 1 ether}();
        oz.deposit{value: 1 ether}();
        vm.stopPrank();
    }

    function test_gas_deposit_warm_Bare() public {
        vm.startPrank(user);
        bare.deposit{value: 1 ether}();
        bare.deposit{value: 1 ether}();
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAW (WARM SLOT)
    //////////////////////////////////////////////////////////////*/

    function test_gas_withdraw_PhaseGuard() public {
        vm.startPrank(user);
        pg.deposit{value: 1 ether}();
        pg.withdraw(1 ether);
        vm.stopPrank();
    }

    function test_gas_withdraw_OZGuard() public {
        vm.startPrank(user);
        oz.deposit{value: 1 ether}();
        oz.withdraw(1 ether);
        vm.stopPrank();
    }

    function test_gas_withdraw_Bare() public {
        vm.startPrank(user);
        bare.deposit{value: 1 ether}();
        bare.withdraw(1 ether);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTION
    //////////////////////////////////////////////////////////////*/

    function test_gas_view_PhaseGuard() public {
        vm.prank(user);
        pg.deposit{value: 1 ether}();
        pg.totalDeposits(user);
    }

    function test_gas_view_OZGuard() public {
        vm.prank(user);
        oz.deposit{value: 1 ether}();
        oz.totalDeposits(user);
    }

    function test_gas_view_Bare() public {
        vm.prank(user);
        bare.deposit{value: 1 ether}();
        bare.totalDeposits(user);
    }

    /*//////////////////////////////////////////////////////////////
                     PHASE TRANSITIONS (ADMIN)
    //////////////////////////////////////////////////////////////*/

    function test_gas_transitionTo_PAUSED() public {
        vm.prank(address(1));
        pg.transitionTo(PhaseGuard.Phase.PAUSED);
    }

    function test_gas_transitionTo_MAINTENANCE() public {
        vm.prank(address(1));
        pg.transitionTo(PhaseGuard.Phase.MAINTENANCE);
    }

    function test_gas_transitionTo_FINALIZED() public {
        vm.prank(address(1));
        pg.transitionTo(PhaseGuard.Phase.FINALIZED);
    }

    /*//////////////////////////////////////////////////////////////
                       PURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_gas_phase() public view {
        pg.phase();
    }

    function test_gas_getPolicy() public view {
        pg.getPolicy(1);
    }

    function test_gas_isTransitionAllowed() public view {
        pg.isTransitionAllowed(1, 2);
    }

    function test_gas_isStable() public view {
        pg.isStable(1);
    }

    function test_gas_supportsInterface() public view {
        pg.supportsInterface(0x5ae3f743);
    }
}
