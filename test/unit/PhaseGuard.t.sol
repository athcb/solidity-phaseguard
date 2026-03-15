// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { PhaseGuardMock } from "../mocks/PhaseGuardMock.sol";
import { PhaseGuard } from "../../src/PhaseGuard.sol";
import { IPhaseGuard } from "../../src/IPhaseGuard.sol";
import { ERC721Receiver, ERC1155Receiver, ERC777Receiver, FlashLoanBorrower, MaliciousCallbackReceiver } from "../mocks/CallbackReceivers.sol";
import { Test } from "forge-std/Test.sol";

/// @dev Helper contract that calls either `transitionTo` when triggered 
// or the dummy functions `dummyView`, `dummyMutating` in the mock contract implementing PhaseGuard, 
// simulating a mid-operation reentrant admin call.
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
    PhaseGuard.Phase constant FINALIZED = PhaseGuard.Phase.FINALIZED;
    PhaseGuard.Phase constant PAUSED = PhaseGuard.Phase.PAUSED;
    PhaseGuard.Phase constant MAINTENANCE = PhaseGuard.Phase.MAINTENANCE;
    
    // Phase array (6 phases)
    PhaseGuard.Phase[6] public phaseArray = [UNINITIALIZED, READY, MUTATING, FINALIZED, PAUSED, MAINTENANCE];

    // Policy bit flags (3 enforced)
    uint8 constant ALLOW_USER  = 1 << 0;
    uint8 constant ALLOW_ADMIN = 1 << 1;
    uint8 constant ALLOW_VIEWS = 1 << 2;

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
        emit IPhaseGuard.PhaseTransition(uint8(UNINITIALIZED), uint8(READY));
        new PhaseGuardMock();
    }

    /// @dev Global contract phase should be READY after initialization
    function test_InitSetsPhaseToReady() public view {
        assertEq(phaseGuard.phase(), uint8(READY));
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
        assertEq(phaseGuard.phase(), phaseGuard.phaseStackBase());
    }

    /*//////////////////////////////////////////////////////////////
                      ERC-7201 NAMESPACED STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev The PHASEGUARD_STORAGE slot must match the ERC-7201 derivation:
    /// keccak256(abi.encode(uint256(keccak256("phaseguard.storage.PhaseGuard")) - 1)) & ~bytes32(uint256(0xff))
    function test_StorageSlotMatchesERC7201Derivation() public view {
        bytes32 expected = keccak256(
            abi.encode(uint256(keccak256("phaseguard.storage.PhaseGuard")) - 1)
        ) & ~bytes32(uint256(0xff));

        assertEq(
            phaseGuard.phaseSlot(),
            expected,
            "PHASEGUARD_STORAGE slot does not match ERC-7201 derivation"
        );
    }

    /// @dev Reading `_phase` directly from the raw ERC-7201 slot (offset 0)
    /// should return the same value as the public `phase()` getter.
    function test_RawPhaseMatchesPublicGetter() public view {
        assertEq(
            phaseGuard.rawPhase(),
            phaseGuard.phase(),
            "Raw storage phase should match phase()"
        );
    }

    /// @dev After initialization, `_phase` at raw slot offset 0 should be READY (1).
    function test_RawPhaseIsReadyAfterInit() public view {
        assertEq(phaseGuard.rawPhase(), uint8(READY), "Raw phase should be READY (1) after init");
    }

    /// @dev Reading `_phaseStack.length` from raw slot offset 1 should match `phaseStackDepth()`.
    function test_RawPhaseStackLengthMatchesPublicGetter() public view {
        assertEq(
            phaseGuard.rawPhaseStackLength(),
            phaseGuard.phaseStackDepth(),
            "Raw stack length should match phaseStackDepth()"
        );
    }

    /// @dev After initialization, `_phaseStack.length` at raw slot offset 1 should be 1.
    function test_RawPhaseStackLengthIsOneAfterInit() public view {
        assertEq(phaseGuard.rawPhaseStackLength(), 1, "Raw stack length should be 1 after init");
    }

    /// @dev After a transitionTo(PAUSED), the raw phase slot should reflect the new phase.
    function test_RawPhaseUpdatesAfterTransition() public {
        phaseGuard.transitionTo(PAUSED);
        assertEq(phaseGuard.rawPhase(), uint8(PAUSED), "Raw phase should update after transitionTo");
        assertEq(phaseGuard.rawPhaseStackLength(), 1, "Stack length should remain 1 after transitionTo");
    }

    /// @dev Two independent PhaseGuard instances should use the same ERC-7201 slot
    /// but their storage is isolated (different contract addresses).
    function test_StorageIsolationBetweenInstances() public {
        PhaseGuardMock second = new PhaseGuardMock();

        // Both use the same slot constant
        assertEq(phaseGuard.phaseSlot(), second.phaseSlot(), "Slot constant should be identical");

        // Both initialized to READY
        assertEq(phaseGuard.rawPhase(), second.rawPhase(), "Both should start at READY");

        // Transition first instance to PAUSED, second stays READY
        phaseGuard.transitionTo(PAUSED);
        assertEq(phaseGuard.rawPhase(), uint8(PAUSED), "First should be PAUSED");
        assertEq(second.rawPhase(), uint8(READY), "Second should still be READY");
    }

    /*//////////////////////////////////////////////////////////////
                            PURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev `isTransitionAllowed`: test transition matrix
    // 1. `UNINITIALIZED` transitions
    function test_UninitializedTransitions() public view {
        bool[6] memory allowedTo = [
            false, // UNINITIALIZED
            true,  // READY
            false, // MUTATING
            false, // FINALIZED
            false, // PAUSED
            false  // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(uint8(UNINITIALIZED), uint8(phaseArray[i])),
                string.concat("UNINITIALIZED -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 2. `READY` transitions
    function test_ReadyTransitions() public view {
        bool[6] memory allowedTo = [
            false, // UNINITIALIZED
            false, // READY
            true,  // MUTATING
            true,  // FINALIZED
            true,  // PAUSED
            true   // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(uint8(READY), uint8(phaseArray[i])),
                string.concat("READY -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 3. `MUTATING` transitions: no forward transitions
    function test_MutatingTransitions() public view {
        bool[6] memory allowedTo = [
            false, // UNINITIALIZED
            false, // READY (only via stack unwind)
            false, // MUTATING
            false, // FINALIZED
            false, // PAUSED
            false  // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(uint8(MUTATING), uint8(phaseArray[i])),
                string.concat("MUTATING -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 4. `FINALIZED` transitions: terminal, no transitions
    function test_FinalizedTransitions() public view {
        bool[6] memory allowedTo = [
            false, // UNINITIALIZED
            false, // READY 
            false, // MUTATING 
            false, // FINALIZED
            false, // PAUSED
            false  // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(uint8(FINALIZED), uint8(phaseArray[i])),
                string.concat("FINALIZED -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 5. `PAUSED` transitions
    function test_PausedTransitions() public view {
        bool[6] memory allowedTo = [
            false, // UNINITIALIZED
            true,  // READY 
            false, // MUTATING 
            true,  // FINALIZED
            false, // PAUSED
            true   // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(uint8(PAUSED), uint8(phaseArray[i])),
                string.concat("PAUSED -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    // 6. `MAINTENANCE` transitions
    function test_MaintenanceTransitions() public view {
        bool[6] memory allowedTo = [
            false, // UNINITIALIZED
            true,  // READY 
            true,  // MUTATING 
            false, // FINALIZED
            false, // PAUSED
            false  // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertEq(
                allowedTo[i], 
                phaseGuard.isTransitionAllowed(uint8(MAINTENANCE), uint8(phaseArray[i])),
                string.concat("MAINTENANCE -> Phase ", vm.toString(uint8(phaseArray[i])))
            );
        }
    }

    /// @dev `getPolicy`: test policy per phase
    // 1. `UNINITIALIZED` policy: all bits off
    function test_UninitializedPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(uint8(UNINITIALIZED));
        assertEq(policy, 0, "UNINITIALIZED policy should be 0");
    }

    // 2. `READY` policy: ALLOW_USER | ALLOW_ADMIN | ALLOW_VIEWS
    function test_ReadyPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(uint8(READY));

        assertEq(policy & ALLOW_USER, ALLOW_USER,   "READY should allow users");
        assertEq(policy & ALLOW_ADMIN, ALLOW_ADMIN, "READY should allow admins");
        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS, "READY should allow views");
    }

    // 3. `MUTATING` policy: all bits off (unstable, blocks everything)
    function test_MutatingPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(uint8(MUTATING));
        assertEq(policy, 0, "MUTATING policy should be 0");
    }

    // 4. `FINALIZED` policy: ALLOW_VIEWS only
    function test_FinalizedPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(uint8(FINALIZED));

        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS, "FINALIZED should allow views");
        assertEq(policy & ALLOW_USER, 0,  "FINALIZED should not allow users");
        assertEq(policy & ALLOW_ADMIN, 0, "FINALIZED should not allow admins");
    }

    // 5. `PAUSED` policy: ALLOW_ADMIN | ALLOW_VIEWS
    function test_PausedPolicy() public view {
        uint8 policy = phaseGuard.getPolicy(uint8(PAUSED));

        assertEq(policy & ALLOW_ADMIN, ALLOW_ADMIN, "PAUSED should allow admins");
        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS, "PAUSED should allow views");
        assertEq(policy & ALLOW_USER, 0, "PAUSED should not allow users");
    }

    // 6. `MAINTENANCE` policy: ALLOW_ADMIN | ALLOW_VIEWS
    function test_MaintenancePolicy() public view {
        uint8 policy = phaseGuard.getPolicy(uint8(MAINTENANCE));

        assertEq(policy & ALLOW_ADMIN, ALLOW_ADMIN, "MAINTENANCE should allow admins");
        assertEq(policy & ALLOW_VIEWS, ALLOW_VIEWS, "MAINTENANCE should allow views");
        assertEq(policy & ALLOW_USER, 0, "MAINTENANCE should not allow users");
    }

    /// @dev `isStable` should return true for READY, FINALIZED, PAUSED, MAINTENANCE
    function test_IsStableReturnsTrueForStablePhases() public view {
        bool[6] memory expected = [
            false, // UNINITIALIZED
            true,  // READY 
            false, // MUTATING 
            true,  // FINALIZED
            true,  // PAUSED
            true   // MAINTENANCE   
        ];

        for (uint256 i = 0; i < phaseArray.length; i++) {
            assertTrue(phaseGuard.isStable(uint8(phaseArray[i])) == expected[i]);
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

        // mutatingWithExternalCallTo will enter [READY, MUTATING] (depth 2),
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
        assertEq(phaseGuard.phase(), uint8(READY));
        // Check that event PhaseTransition(currentPhase, toPhase) will be emitted
        vm.expectEmit(true, true, false, false);
        emit IPhaseGuard.PhaseTransition(uint8(READY), uint8(PAUSED));
        // READY -> PAUSED allowed
        phaseGuard.transitionTo(PAUSED);
        // Assert that global phase after transition is PAUSED
        assertEq(phaseGuard.phase(), uint8(PAUSED));
        // Assert that _phaseStack contains only 1 element
        assertEq(phaseGuard.phaseStackDepth(), 1);
        // Assert that _phaseStack base element is equal to the global phase 
        assertEq(phaseGuard.phaseStackBase(), uint8(PAUSED));
    }

     /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @dev test withMutating happy path
    function test_withMutatingUpdatesStateAndResetsPhase() public {
        uint256 counterBefore = phaseGuard.counter();
        uint8 phaseBefore = phaseGuard.phase();
        
        // Assert that the global phase will transition mid-call from 
        // 1. READY -> MUTATING and
        // 2. MUTATING -> READY
        vm.expectEmit(true, true, false, false);
        emit IPhaseGuard.PhaseTransition(uint8(READY), uint8(MUTATING));
        vm.expectEmit(true, true, false, false);
        emit IPhaseGuard.PhaseTransition(uint8(MUTATING), uint8(READY));
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

    /// @dev External call to a target during MUTATING succeeds (happy path).
    /// READY -> MUTATING -> (target call succeeds) -> READY
    function test_withMutatingExternalCallToSucceeds() public {
        ERC721Receiver receiver = new ERC721Receiver();

        // Assert that events for the following phase transitions are emitted:
        // 1. READY -> MUTATING
        vm.expectEmit(true, true, false, false);
        emit IPhaseGuard.PhaseTransition(uint8(READY), uint8(MUTATING));
        // 2. MUTATING -> READY 
        vm.expectEmit(true, true, false, false);
        emit IPhaseGuard.PhaseTransition(uint8(MUTATING), uint8(READY));

        phaseGuard.mutatingWithExternalCallTo(
            address(receiver),
            abi.encodeWithSelector(
                ERC721Receiver.onERC721Received.selector,
                address(phaseGuard),
                address(this),
                1,
                ""
            )
        );

        assertTrue(receiver.called(), "Receiver should have been called");
        assertEq(phaseGuard.phase(), uint8(READY), "Phase should return to READY");
        assertEq(phaseGuard.phaseStackDepth(), 1, "Stack depth should be 1");
        assertEq(phaseGuard.phaseStackBase(), uint8(READY), "Stack base should be READY");
    }

    /*//////////////////////////////////////////////////////////////
              CALLBACKS DURING MUTATING: RE-ENTRY BLOCKED
    //////////////////////////////////////////////////////////////*/

    /// @dev Malicious callback attempts to call a withView function during MUTATING → reverts
    function test_CallbackReentrantViewReverts() public {
        MaliciousCallbackReceiver malicious = new MaliciousCallbackReceiver(address(phaseGuard));
        malicious.setAttackType(MaliciousCallbackReceiver.AttackType.VIEW);

        vm.expectRevert("external call failed");
        phaseGuard.mutatingWithExternalCallTo(
            address(malicious),
            abi.encodeWithSelector(
                MaliciousCallbackReceiver.onERC721Received.selector,
                address(phaseGuard),
                address(this),
                1,
                ""
            )
        );
    }

    /// @dev Malicious callback attempts to call a withMutating function during MUTATING → reverts
    function test_CallbackReentrantMutatingReverts() public {
        MaliciousCallbackReceiver malicious = new MaliciousCallbackReceiver(address(phaseGuard));
        malicious.setAttackType(MaliciousCallbackReceiver.AttackType.MUTATING);

        vm.expectRevert("external call failed");
        phaseGuard.mutatingWithExternalCallTo(
            address(malicious),
            abi.encodeWithSelector(
                MaliciousCallbackReceiver.onERC721Received.selector,
                address(phaseGuard),
                address(this),
                1,
                ""
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
          LEGITIMATE CALLBACKS DURING MUTATING (NON-REENTRANT)
    //////////////////////////////////////////////////////////////*/

    /// @dev ERC721 receiver returns selector during an external call in MUTATING (happy path)
    function test_CallbackERC721ReceiverSucceeds() public {
        ERC721Receiver receiver = new ERC721Receiver();

        phaseGuard.mutatingWithExternalCallTo(
            address(receiver),
            abi.encodeWithSelector(
                ERC721Receiver.onERC721Received.selector,
                address(phaseGuard),
                address(this),
                1,
                ""
            )
        );

        assertTrue(receiver.called(), "ERC721 receiver should have been called");
        assertEq(phaseGuard.phase(), uint8(READY), "Phase should return to READY");
    }

    /// @dev ERC1155 receiver returns selector during an external call in MUTATING (happy path)
    function test_CallbackERC1155ReceiverSucceeds() public {
        ERC1155Receiver receiver = new ERC1155Receiver();

        phaseGuard.mutatingWithExternalCallTo(
            address(receiver),
            abi.encodeWithSelector(
                ERC1155Receiver.onERC1155Received.selector,
                address(phaseGuard),
                address(this),
                1,
                100,
                ""
            )
        );

        assertTrue(receiver.called(), "ERC1155 receiver should have been called");
        assertEq(phaseGuard.phase(), uint8(READY), "Phase should return to READY");
    }

    /// @dev ERC777 receiver acknowledges receipt during an external call in MUTATING (happy path)
    function test_CallbackERC777ReceiverSucceeds() public {
        ERC777Receiver receiver = new ERC777Receiver();

        phaseGuard.mutatingWithExternalCallTo(
            address(receiver),
            abi.encodeWithSelector(
                ERC777Receiver.tokensReceived.selector,
                address(phaseGuard),
                address(this),
                address(receiver),
                100,
                "",
                ""
            )
        );

        assertTrue(receiver.called(), "ERC777 receiver should have been called");
        assertEq(phaseGuard.phase(), uint8(READY), "Phase should return to READY");
    }

    /// @dev Flash loan borrower executes arbitrage on a *separate* contract during MUTATING (happy path)
    function test_CallbackFlashLoanBorrowerSucceeds() public {
        FlashLoanBorrower borrower = new FlashLoanBorrower();

        PhaseGuardMock arbTarget = new PhaseGuardMock();
        borrower.setArbCall(
            address(arbTarget),
            abi.encodeWithSelector(PhaseGuardMock.dummyMutating.selector)
        );

        phaseGuard.mutatingWithExternalCallTo(
            address(borrower),
            abi.encodeWithSelector(
                FlashLoanBorrower.onFlashLoan.selector,
                address(this),
                address(0),
                1000,
                0,
                ""
            )
        );

        assertTrue(borrower.called(), "Flash loan borrower should have been called");
        assertEq(arbTarget.counter(), 1, "Arb target should have been mutated");
        assertEq(phaseGuard.phase(), uint8(READY), "Phase should return to READY");
    }

    /*//////////////////////////////////////////////////////////////
                    OUT-OF-RANGE uint8 BOUNDS CHECKS
    //////////////////////////////////////////////////////////////*/

    /// @dev `isTransitionAllowed` returns false when `from` is out of range
    function test_IsTransitionAllowed_OutOfRangeFrom_ReturnsFalse() public view {
        assertFalse(phaseGuard.isTransitionAllowed(6, uint8(READY)), "from=6 should return false");
        assertFalse(phaseGuard.isTransitionAllowed(100, uint8(READY)), "from=100 should return false");
        assertFalse(phaseGuard.isTransitionAllowed(255, uint8(READY)), "from=255 should return false");
    }

    /// @dev `isTransitionAllowed` returns false when `to` is out of range
    function test_IsTransitionAllowed_OutOfRangeTo_ReturnsFalse() public view {
        assertFalse(phaseGuard.isTransitionAllowed(uint8(READY), 6), "to=6 should return false");
        assertFalse(phaseGuard.isTransitionAllowed(uint8(READY), 100), "to=100 should return false");
        assertFalse(phaseGuard.isTransitionAllowed(uint8(READY), 255), "to=255 should return false");
    }

    /// @dev `isTransitionAllowed` returns false when both are out of range
    function test_IsTransitionAllowed_BothOutOfRange_ReturnsFalse() public view {
        assertFalse(phaseGuard.isTransitionAllowed(6, 7), "both out of range should return false");
        assertFalse(phaseGuard.isTransitionAllowed(255, 255), "max uint8 both should return false");
    }

    /// @dev `getPolicy` returns 0 for out-of-range phase IDs
    function test_GetPolicy_OutOfRange_ReturnsZero() public view {
        assertEq(phaseGuard.getPolicy(6), 0, "getPolicy(6) should return 0");
        assertEq(phaseGuard.getPolicy(100), 0, "getPolicy(100) should return 0");
        assertEq(phaseGuard.getPolicy(255), 0, "getPolicy(255) should return 0");
    }

    /// @dev `isStable` returns false for out-of-range phase IDs
    function test_IsStable_OutOfRange_ReturnsFalse() public view {
        assertFalse(phaseGuard.isStable(6), "isStable(6) should return false");
        assertFalse(phaseGuard.isStable(100), "isStable(100) should return false");
        assertFalse(phaseGuard.isStable(255), "isStable(255) should return false");
    }

    /*//////////////////////////////////////////////////////////////
                        ERC-165 SUPPORT
    //////////////////////////////////////////////////////////////*/

    /// @dev supportsInterface returns true for ERC-165 identifier
    function test_SupportsInterface_ERC165() public view {
        assertTrue(phaseGuard.supportsInterface(0x01ffc9a7), "should support ERC-165");
    }

    /// @dev supportsInterface returns true for IPhaseGuard identifier
    function test_SupportsInterface_IPhaseGuard() public view {
        assertTrue(phaseGuard.supportsInterface(0x90e42898), "should support IPhaseGuard");
    }

    /// @dev supportsInterface returns false for unsupported interface
    function test_SupportsInterface_Unsupported() public view {
        assertFalse(phaseGuard.supportsInterface(0xffffffff), "0xffffffff should not be supported");
        assertFalse(phaseGuard.supportsInterface(0x00000000), "0x00000000 should not be supported");
        assertFalse(phaseGuard.supportsInterface(0xdeadbeef), "random selector should not be supported");
    }

}