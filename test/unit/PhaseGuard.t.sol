// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { PhaseGuardMock } from "../mocks/PhaseGuardMock.sol";
import { PhaseGuard } from "../../src/PhaseGuard.sol";
import { Test, console2 } from "forge-std/Test.sol";

contract PhaseGuardTest is Test {

    PhaseGuardMock public phaseGuard;

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
        phaseGuard = new PhaseGuardMock();
        owner = address(this);
        user = makeAddr("user");
    }

    /*//////////////////////////////////////////////////////////////
                             INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @dev PhaseGuard initialization should emit the `PhaseTransition` event.
    function test_InitEmitsPhaseTransition() public {
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(UNINITIALIZED, READY);
        new PhaseGuardMock();
    }

    /// @dev Global contract phase should be READY after initialization
    function test_InitSetsPhaseToReady() public view {
        assertEq(uint8(phaseGuard.phase()), uint8(READY));
    }
    
    /// @dev Re-initialization fails with `TransitionGateLocked()`
    function test_ReInitReverts() public {
        vm.expectRevert(PhaseGuard.TransitionGateLocked.selector);
        phaseGuard.doubleInit();
    }

    /// @dev _phaseStack should have length == 1 after initialization
    function test_PhaseStackDepthIsOneAfterInit() public view {
        assertEq(phaseGuard.phaseStackDepth(), 1);
    }

    /// @dev The base phase at the bottom of _phaseStack should be equal to the global contract phase
    function test_PhaseStackFirstElementIsGlobalPhase() public view {
        assertEq(uint8(phaseGuard.phase()), uint8(phaseGuard.phaseStackBase()));
    }

    /*//////////////////////////////////////////////////////////////
                            PURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev `isTransitionAllowed`: test transition matrix
    // 1. `UNINITIALIZED` transitions
    function test_UninitializedTransitions() public view {
        bool[8] memory allowedTo = [
            false,  // UNINITIALIZED
            true, // READY
            false, // MUTATING
            false, // EXTERNALIZING
            false, // CALLBACKING
            false, // FINALIZED
            false, // PAUSED
            false // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(UNINITIALIZED, phaseArray[i]),
                string.concat("UNINITIALIZED -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 2. `READY` transitions
    function test_ReadyTransitions() public view {
        bool[8] memory allowedTo = [
            false,  // UNINITIALIZED
            false, // READY
            true, // MUTATING
            false, // EXTERNALIZING
            false, // CALLBACKING
            true, // FINALIZED
            true, // PAUSED
            true // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(READY, phaseArray[i]),
                string.concat("READY -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 3. `MUTATING` transitions
    function test_MutatingTransitions() public view {
        bool[8] memory allowedTo = [
            false,  // UNINITIALIZED
            false, // READY - only allowed during phase unwinding
            false, // MUTATING
            true, // EXTERNALIZING
            false, // CALLBACKING
            false, // FINALIZED
            false, // PAUSED
            false // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(MUTATING, phaseArray[i]),
                string.concat("MUTATING -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 4. `EXTERNALIZING` transitions
    function test_ExternalizingTransitions() public view {
        bool[8] memory allowedTo = [
            false,  // UNINITIALIZED
            false, // READY 
            false, // MUTATING - only allowed during phase unwinding
            false, // EXTERNALIZING
            true, // CALLBACKING
            false, // FINALIZED
            false, // PAUSED
            false // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(EXTERNALIZING, phaseArray[i]),
                string.concat("EXTERNALIZING -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 5. `CALLBACKING` transitions
    function test_CallbackingTransitions() public view {
        bool[8] memory allowedTo = [
            false, // UNINITIALIZED
            false, // READY 
            false, // MUTATING 
            false, // EXTERNALIZING - only allowed during phase unwinding
            false, // CALLBACKING
            false, // FINALIZED
            false, // PAUSED
            false // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(CALLBACKING, phaseArray[i]),
                string.concat("CALLBACKING -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 6. `FINALIZED` transitions
    function test_FinalizedTransitions() public view {
        bool[8] memory allowedTo = [
            false, // UNINITIALIZED
            false, // READY 
            false, // MUTATING 
            false, // EXTERNALIZING 
            false, // CALLBACKING
            false, // FINALIZED
            false, // PAUSED
            false // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(FINALIZED, phaseArray[i]),
                string.concat("FINALIZED -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 7. `PAUSED` transitions
    function test_PausedTransitions() public view {
        bool[8] memory allowedTo = [
            false, // UNINITIALIZED
            true, // READY 
            false, // MUTATING 
            false, // EXTERNALIZING 
            false, // CALLBACKING
            true, // FINALIZED
            false, // PAUSED
            true // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(PAUSED, phaseArray[i]),
                string.concat("PAUSED -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 7. `MAINTENANCE` transitions
    function test_MaintenanceTransitions() public view {
        bool[8] memory allowedTo = [
            false, // UNINITIALIZED
            true, // READY 
            true, // MUTATING 
            false, // EXTERNALIZING 
            false, // CALLBACKING
            false, // FINALIZED
            false, // PAUSED
            false // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(MAINTENANCE, phaseArray[i]),
                string.concat("MAINTENANCE -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    /// @dev `getPolicy`: test policy per phase
    // 1. `UNINITIALIZED` policy
    function test_UninitializedPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(UNINITIALIZED);

        // Should not be set
        assertEq(policy & ALLOW_USER, 0,        "UNINITIALIZED should not allow users");
        assertEq(policy & ALLOW_ADMIN, 0,       "UNINITIALIZED should not allow admins");
        assertEq(policy & ALLOW_EXTERNAL, 0,    "UNINITIALIZED should not allow external");
        assertEq(policy & ALLOW_VALUE, 0,       "UNINITIALIZED should not allow value");
        assertEq(policy & ALLOW_VIEWS, 0,       "UNINITIALIZED should not allow views");
        assertEq(policy & ALLOW_WRITES, 0,      "UNINITIALIZED should not allow writes");
        assertEq(policy & ALLOW_CALLBACKS, 0,   "UNINITIALIZED should not allow callbacks");
        assertEq(policy & ALLOW_DELEGATECALL, 0,"UNINITIALIZED should not allow delegatecall");
    }

    // 2. `READY` policy
    function test_ReadyPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(READY);

        // Should be set
        assertEq(policy & ALLOW_USER, ALLOW_USER,   "READY should allow users");
        assertEq(policy & ALLOW_ADMIN, ALLOW_ADMIN, "READY should allow admins");
        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS, "READY should allow views");

        // Should not be set
        assertEq(policy & ALLOW_EXTERNAL, 0,    "READY should not allow external");
        assertEq(policy & ALLOW_VALUE, 0,       "READY should not allow value");
        assertEq(policy & ALLOW_WRITES, 0,      "READY should not allow writes");
        assertEq(policy & ALLOW_CALLBACKS, 0,   "READY should not allow callbacks");
        assertEq(policy & ALLOW_DELEGATECALL, 0,"READY should not allow delegatecall");
    }

    // 3. `MUTATING` policy
    function test_MutatingPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(MUTATING);

        // Should be set
        assertEq(policy & ALLOW_WRITES, ALLOW_WRITES, "MUTATING should allow writes");

        // Should not be set
        assertEq(policy & ALLOW_USER, 0,        "MUTATING should not allow users");
        assertEq(policy & ALLOW_ADMIN, 0,       "MUTATING should not allow admins");
        assertEq(policy & ALLOW_EXTERNAL, 0,    "MUTATING should not allow external");
        assertEq(policy & ALLOW_VALUE, 0,       "MUTATING should not allow value");
        assertEq(policy & ALLOW_VIEWS, 0,       "MUTATING should not allow views");
        assertEq(policy & ALLOW_CALLBACKS, 0,   "MUTATING should not allow callbacks");
        assertEq(policy & ALLOW_DELEGATECALL, 0,"MUTATING should not allow delegatecall");
    }

    // 4. `EXTERNALIZING` policy
    function test_ExternalizingPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(EXTERNALIZING);

        // Should be set
        assertEq(policy & ALLOW_EXTERNAL, ALLOW_EXTERNAL, "EXTERNALIZING should allow external");
        assertEq(policy & ALLOW_VALUE, ALLOW_VALUE,       "EXTERNALIZING should allow value");

        // Should not be set
        assertEq(policy & ALLOW_USER, 0,        "EXTERNALIZING should not allow users");
        assertEq(policy & ALLOW_ADMIN, 0,       "EXTERNALIZING should not allow admins");
        assertEq(policy & ALLOW_VIEWS, 0,       "EXTERNALIZING should not allow views");
        assertEq(policy & ALLOW_WRITES, 0,      "EXTERNALIZING should not allow writes");
        assertEq(policy & ALLOW_CALLBACKS, 0,   "EXTERNALIZING should not allow callbacks");
        assertEq(policy & ALLOW_DELEGATECALL, 0,"EXTERNALIZING should not allow delegatecall");
    }

    // 5. `CALLBACKING` policy
    function test_CallbackingPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(CALLBACKING);

        // Should be set
        assertEq(policy & ALLOW_CALLBACKS, ALLOW_CALLBACKS, "CALLBACKING should allow callbacks");

        // Should not be set
        assertEq(policy & ALLOW_USER, 0,        "CALLBACKING should not allow users");
        assertEq(policy & ALLOW_ADMIN, 0,       "CALLBACKING should not allow admins");
        assertEq(policy & ALLOW_EXTERNAL, 0,    "CALLBACKING should not allow external");
        assertEq(policy & ALLOW_VALUE, 0,       "CALLBACKING should not allow value");
        assertEq(policy & ALLOW_VIEWS, 0,       "CALLBACKING should not allow views");
        assertEq(policy & ALLOW_WRITES, 0,      "CALLBACKING should not allow writes");
        assertEq(policy & ALLOW_DELEGATECALL, 0,"CALLBACKING should not allow delegatecall");
    }

    // 6. `FINALIZED` policy
    function test_FinalizedPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(FINALIZED);

        // Should be set
        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS, "FINALIZED should allow views");

        // Should not be set
        assertEq(policy & ALLOW_USER, 0,        "FINALIZED should not allow users");
        assertEq(policy & ALLOW_ADMIN, 0,       "FINALIZED should not allow admins");
        assertEq(policy & ALLOW_EXTERNAL, 0,    "FINALIZED should not allow external");
        assertEq(policy & ALLOW_VALUE, 0,       "FINALIZED should not allow value");
        assertEq(policy & ALLOW_WRITES, 0,      "FINALIZED should not allow writes");
        assertEq(policy & ALLOW_CALLBACKS, 0,   "FINALIZED should not allow callbacks");
        assertEq(policy & ALLOW_DELEGATECALL, 0,"FINALIZED should not allow delegatecall");
    }

    // 7. `PAUSED` policy
    function test_PausedPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(PAUSED);

        // Should be set
        assertEq(policy & ALLOW_ADMIN, ALLOW_ADMIN, "PAUSED should allow admins");
        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS, "PAUSED should allow views");

        // Should not be set
        assertEq(policy & ALLOW_USER, 0,        "PAUSED should not allow users");
        assertEq(policy & ALLOW_EXTERNAL, 0,    "PAUSED should not allow external");
        assertEq(policy & ALLOW_VALUE, 0,       "PAUSED should not allow value");
        assertEq(policy & ALLOW_WRITES, 0,      "PAUSED should not allow writes");
        assertEq(policy & ALLOW_CALLBACKS, 0,   "PAUSED should not allow callbacks");
        assertEq(policy & ALLOW_DELEGATECALL, 0,"PAUSED should not allow delegatecall");
    }

    // 8. `MAINTENANCE` policy
    function test_MaintenancePolicy() public view {
        uint8 policy = phaseGuard.getPolicy(MAINTENANCE);

        // Should be set
        assertEq(policy & ALLOW_ADMIN, ALLOW_ADMIN,             "MAINTENANCE should allow admins");
        assertEq(policy & ALLOW_EXTERNAL, ALLOW_EXTERNAL,       "MAINTENANCE should allow external");
        assertEq(policy & ALLOW_VALUE, ALLOW_VALUE,             "MAINTENANCE should allow value");
        assertEq(policy & ALLOW_WRITES, ALLOW_WRITES,           "MAINTENANCE should allow writes");
        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS,             "MAINTENANCE should allow views");
        assertEq(policy & ALLOW_CALLBACKS, ALLOW_CALLBACKS,     "MAINTENANCE should allow callbacks");
        assertEq(policy & ALLOW_DELEGATECALL, ALLOW_DELEGATECALL,"MAINTENANCE should allow delegatecall");

        // Should not be set
        assertEq(policy & ALLOW_USER, 0, "MAINTENANCE should not allow users");
    }

    /// @dev `isStable` should return true for READY, PAUSED, FINALIZED, MAINTENANCE
    function test_IsStableReturnsTrueForStablePhases() public view {
        bool[8] memory expected = [
            false, // UNINITIALIZED
            true, // READY 
            false, // MUTATING 
            false, // EXTERNALIZING 
            false, // CALLBACKING
            true, // FINALIZED
            true, // PAUSED
            true // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertTrue(phaseGuard.isStable(phaseArray[i]) == expected[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                        EXTERNAL (ADMIN) FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    
    /// @dev `transitionTo` reverts with `AccessDenied` when called by a non-admin

    /// @dev `transitionTo` reverts when `_phaseStack` has a depth > 1 (mid-operation)

    /// @dev `transitionTo` reverts with `PhaseStabilityInvariant` when `_phase` is not stable

    /// @dev `transitionTo` reverts with `TransitionGateLocked` if transition is not allowed

    /// @dev `transitionTo` correctly changes the global `_phase`, updates `_phaseStack` and emits event


}