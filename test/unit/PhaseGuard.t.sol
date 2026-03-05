// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { PhaseGuardMock } from "../mocks/PhaseGuardMock.sol";
import { PhaseGuard } from "../../src/PhaseGuard.sol";
import { Test, console2 } from "forge-std/Test.sol";

/// @dev Helper contract that calls `transitionTo` when triggered, simulating a mid-operation reentrant admin call.
contract AttackerReentrant {
    PhaseGuardMock target;

    constructor(address _target) {
        target = PhaseGuardMock(_target);
    }

    function attackView() external view {
        target.dummyView();
    }

    function attackMutating() external {
        target.dummyMutating();
    }

    fallback() external payable {
        target.transitionTo(PhaseGuard.Phase.PAUSED);
    }
}

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

    // 8. `MAINTENANCE` transitions
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
    function test_TransitionToRevertsWhenCalledByNonAdmin() public {
        vm.prank(user);
        vm.expectRevert(PhaseGuardMock.AccessDenied.selector);
        phaseGuard.transitionTo(PAUSED);
    }

    /// @dev `transitionTo` reverts when `_phaseStack` has a depth > 1 (mid-operation)
    function test_TransitionToRevertsMidOperation() public {
        // Deploy attacker that will call transitionTo(PAUSED) when called
        AttackerReentrant attacker = new AttackerReentrant(address(phaseGuard));

        // mutatingWithExternalCallTo will enter [READY, MUTATING, EXTERNALIZING] (depth 3),
        // then call attacker, which calls transitionTo -> _checkInvariants -> revert StackLengthInvariant
        vm.expectRevert("external call failed");
        phaseGuard.mutatingWithExternalCallTo(address(attacker), "");
    }

    /// @dev `transitionTo` reverts with `PhaseStabilityInvariant` when `_phase` is not stable
    function test_TransitionToRevertsWhenTargetPhaseIsNotStable() public {
        vm.prank(owner);
        // MUTATING is unstable
        vm.expectRevert(PhaseGuard.PhaseStabilityInvariant.selector);
        phaseGuard.transitionTo(MUTATING);
    }

    /// @dev `transitionTo` reverts with `TransitionGateLocked` if transition is not allowed
    function test_TransitionToRevertsWhenTransitionNotAllowed() public {
        vm.startPrank(owner);
        // First transition to the FINALIZED terminal state
        phaseGuard.transitionTo(FINALIZED);
        vm.expectRevert(PhaseGuard.TransitionGateLocked.selector);
        // No transitions are allowed from FINALIZED
        phaseGuard.transitionTo(READY);
        vm.stopPrank();
    }

    /// @dev `transitionTo` correctly changes the global `_phase`, updates `_phaseStack` and emits event
    function test_TransitionToCorrectlyUpdatesPhaseAndStack() public {
        vm.prank(owner);
        // Assert that phase before transition is READY
        assertEq(uint8(phaseGuard.phase()), uint8(READY));
        // Check that event PhaseTransition(currentPhase, toPhase) will be emitted
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, PAUSED);
        // READY -> PAUSED allowed
        phaseGuard.transitionTo(PAUSED);
        // Assert that global phase after transition is PAUSED
        assertEq(uint8(phaseGuard.phase()), uint8(PAUSED));
        // Assert that _phaseStack contains only 1 element
        assertEq(phaseGuard.phaseStackDepth(), 1);
        // Assert that _phaseStack base element is equal to the global phase 
        assertEq(uint8(phaseGuard.phaseStackBase()), uint8(PAUSED));
    }

     /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @dev test withMutating happy path
    function test_withMutatingUpdatesStateAndResetsPhase() public {
        uint256 counterBefore = phaseGuard.counter();
        PhaseGuard.Phase phaseBefore = phaseGuard.phase();
        
        // Assert that the global phase will transition mid-call from 
        // 1. READY -> MUTATING and
        // 2. MUTATING -> READY
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);
        phaseGuard.dummyMutating();
        
        // Assert that state has been updated
        assertTrue(phaseGuard.counter() == counterBefore + 1);
        // Assert that the global phase has been reset back to the initial phase 
        assertTrue(phaseGuard.phase() == phaseBefore);
    }

    /// @dev test withMutating reverts with custom error PolicyGateLocked when phase does not meet entry policy requirements
    function test_withMutatingRevertsWhenPhaseNotAllows() public {
        // FINALIZED has no ALLOW_USER or ALLOW_ADMIN -> PolicyGateLocked
        vm.prank(owner);
        phaseGuard.transitionTo(FINALIZED);
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        phaseGuard.dummyMutating();
    }

    /// @dev withMutating reverts in PAUSED and MAINTENANCE state when called by non-admin
    function test_withMutatingRevertsInPausedOrMaintenanceWhenCalledByNonAdmin() public {
        vm.prank(owner);
        phaseGuard.transitionTo(PAUSED);

        // Non-owners not allowed to call withMutating functions when in PAUSED
        // PAUSED has ALLOW_ADMIN so call fails in _checkAdmin with  AccessDenied before PolicyGateLocked is reached
        vm.prank(user);
        vm.expectRevert(PhaseGuardMock.AccessDenied.selector);
        phaseGuard.dummyMutating();

        phaseGuard.transitionTo(READY);
        phaseGuard.transitionTo(MAINTENANCE);
        vm.stopPrank();

        // Non-owners not allowed to call withMutating functions when in MAINTENANCE
        vm.prank(user);
        vm.expectRevert(PhaseGuardMock.AccessDenied.selector);
        phaseGuard.dummyMutating();
    }

    /// @dev withMutating succeeds in MAINTENANCE when called by admin
    function test_withMutatingSucceedsInMaintenanceWhenCalledByAdmin() public {
        uint256 counterBefore = phaseGuard.counter();
        vm.startPrank(owner);
        phaseGuard.transitionTo(MAINTENANCE);
        phaseGuard.dummyMutating();
        assertEq(phaseGuard.counter(), counterBefore + 1);
        vm.stopPrank();
    }
    
    /// @dev calling a withMutating function mid-operation (in a callback) reverts 
    function test_withMutatingRevertsWhenMidOperation() public {
        AttackerReentrant attacker = new AttackerReentrant(address(phaseGuard));
        vm.expectRevert("external call failed");
        phaseGuard.mutatingWithExternalCallTo(address(attacker), abi.encodeWithSelector(AttackerReentrant.attackMutating.selector));
    }

    /// @dev test withMutating + external call (happy path)
    function test_withMutatingWithExternalCallSucceeds() public {
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
        phaseGuard.mutatingWithExternalCall();

        // Assert that global phase is back at READY
        assertEq(uint8(phaseGuard.phase()), uint8(READY));
        // Assert that phase stack depth is 1
        assertEq(phaseGuard.phaseStackDepth(), 1);
        // Assert that phase stack base is READY
        assertEq(uint8(phaseGuard.phaseStackBase()), uint8(READY));
    }

    /// @dev test withMutating + callback (happy path)
    function test_withMutatingWithCallbackSucceeds() public {
        // Assert that events for the following phase transitions are emitted:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        // 2. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 3. EXTERNALIZING -> CALLBACK
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, CALLBACKING);
        // 4. CALLBACK -> EXTERNALIZING 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(CALLBACKING, EXTERNALIZING);
        // 5. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
        // 6. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);

        phaseGuard.mutatingWithCallback();

        // Assert that global phase is back at READY
        assertEq(uint8(phaseGuard.phase()), uint8(READY));
        // Assert that phase stack depth is 1
        assertEq(phaseGuard.phaseStackDepth(), 1);
        // Assert that phase stack base is READY
        assertEq(uint8(phaseGuard.phaseStackBase()), uint8(READY));
    }


    /// @dev test withMutating + multiple external calls (happy path)
    function test_withMutatingWithMultipleExternalCallsSucceeds() public {
        // Assert that events for the following phase transitions are emitted:
        // First external call:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        // 2. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 3. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
       
        // Second external call:
        // 4. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 5. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
        // 6. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);
        
        phaseGuard.mutatingWithMultipleExternalCalls();

        // Assert that global phase is back at READY
        assertEq(uint8(phaseGuard.phase()), uint8(READY));
        // Assert that phase stack depth is 1
        assertEq(phaseGuard.phaseStackDepth(), 1);
        // Assert that phase stack base is READY
        assertEq(uint8(phaseGuard.phaseStackBase()), uint8(READY));
    }

    /// @dev test withMutating + mixed external calls (happy path)
    function test_withMutatingWithMixedExternalCallsSucceeds() public {
        // Assert that events for the following phase transitions are emitted:
        // First external call:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(READY, MUTATING);
        // 2. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 3. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
       
        // Second external call with callback:
        // 4. MUTATING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, EXTERNALIZING);
        // 5. EXTERNALIZING -> CALLBACKING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, CALLBACKING);
        // 6. CALLBACKING -> EXTERNALIZING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(CALLBACKING, EXTERNALIZING);
        // 7. EXTERNALIZING -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(EXTERNALIZING, MUTATING);
        // 8. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit PhaseGuard.PhaseTransition(MUTATING, READY);
        
        phaseGuard.mutatingWithMixedExternalCalls();

        // Assert that global phase is back at READY
        assertEq(uint8(phaseGuard.phase()), uint8(READY));
        // Assert that phase stack depth is 1
        assertEq(phaseGuard.phaseStackDepth(), 1);
        // Assert that phase stack base is READY
        assertEq(uint8(phaseGuard.phaseStackBase()), uint8(READY));
    }

    /// @dev test that withMutating + nested external calls reverts
    function test_withMutatingWithNestedExternalCallsReverts() public {
        // READY -> MUTATING -> EXTERNALIZING -> EXTERNALIZING etc.
        // EXTERNALIZING -> EXTERNALIZING not allowed: policy should have ALLOW_WRITES to enter EXTERNALIZING
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        phaseGuard.mutatingWithNestedExternalCalls();
    }

    /// @dev test that withMutating + missing nested external call reverts
    function test_withMutatingWithMissingNestedExternalCallsReverts() public {
        // READY -> MUTATING -> EXTERNALIZING -> _exitPhase (pop EXTERNALIZING) -> _exitPhase (pop MUTATING): One _exitPhase is missing
        // _checkInvariants() reverts with PhaseStabilityInvariant(): MUTATING is unstable
        // StackLengthInvariant() would also be triggered if placed first
        vm.expectRevert(PhaseGuard.PhaseStabilityInvariant.selector);
        phaseGuard.missingNestedExternalCalls();
    }

    /// @dev test that withMutating + incorrect incorrect start helper pairing reverts
    function test_withMutatingWithIncorrectStartHelperPairingReverts() public {
        // READY -> MUTATING -> EXTERNALIZING -> _exitPhase (pop EXTERNALIZING) -> _exitPhase (pop MUTATING) -> _exitPhase (pop READY): One extra _exitPhase 
        // _exitPhase reverts with StackSizeError(): 1 element left in stack when at least 2 are expected
        vm.expectRevert(PhaseGuard.StackSizeError.selector);
        phaseGuard.incorrectStartHelperPairing();
    }

     /// @dev test that withMutating + incorrect incorrect end helper pairing reverts
    function test_withMutatingWithIncorrectEndHelperPairingReverts() public {
        // READY -> MUTATING -> EXTERNALIZING -> CALLBACKING -> _exitPhase (pop CALLBACKING) -> _exitPhase (pop EXTERNALIZING) -> One missing _exitPhase to pop MUTATING
        // _checkInvariants reverts with PhaseStabilityInvariant (current phase is MUTATING)
        vm.expectRevert(PhaseGuard.PhaseStabilityInvariant.selector);
        phaseGuard.incorrectEndHelperPairing();
    }

    /// @dev test withView happy path
    function test_withViewReturnsValueOnlyWhenPhaseAllows() public {
        assertEq(phaseGuard.dummyView(), phaseGuard.counter(),  "READY should allow views");

        vm.startPrank(owner);
        phaseGuard.transitionTo(MAINTENANCE);
        assertEq(phaseGuard.dummyView(), phaseGuard.counter(), "MAINTENACE should allow views to admin");

        // reset global phase to READY
        phaseGuard.transitionTo(READY);
        phaseGuard.transitionTo(FINALIZED);
        vm.stopPrank();
        assertEq(phaseGuard.dummyView(), phaseGuard.counter(), "FINALIZED should allow views");
    }

    /// @dev test withView locked phases (custom error ViewsLocked)
    function test_withViewRevertsWhenPhaseLocksViews() public {
        // use external contract to simulate a call to dummyView mid-operation 
        AttackerReentrant attacker = new AttackerReentrant(address(phaseGuard));
        vm.expectRevert("external call failed");
        phaseGuard.mutatingWithExternalCallTo(address(attacker), abi.encodeWithSelector(AttackerReentrant.attackView.selector));
    }

    /*//////////////////////////////////////////////////////////////
                  SCOPED HELPERS WITHOUT WITHMUTATING
    //////////////////////////////////////////////////////////////*/

    /// @dev Trying to enter EXTERNALIZING from READY reverts with PolicyGateLocked
    /// READY does not have ALLOW_WRITES so the policy gate blocks entry before the transition gate is reached.
    function test_ExternalizingFromReadyReverts() public {
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        phaseGuard.externalizingFromReady();
    }

    /// @dev Trying to enter CALLBACKING from READY reverts with PolicyGateLocked
    /// READY does not have ALLOW_EXTERNAL so the policy gate blocks entry before the transition gate is reached.
    function test_CallbackingFromReadyReverts() public {
        vm.expectRevert(PhaseGuard.PolicyGateLocked.selector);
        phaseGuard.callbackingFromReady();
    }

}