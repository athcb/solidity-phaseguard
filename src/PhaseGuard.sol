// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title PhaseGuard State Machine
/// @author 0xathcb
/// @notice PhaseGuard eliminates lifecycle security vulnerabilities by enforcing a rigid state machine for every contract call.
/// It uses a unified guard to guarantee that initialization, CEI compliance, pause logic, and context integrity 
/// follow a strict order making reentrancy, re-initialization, and inconsistent state exploits structurally impossible.
/// @dev Abstract contract implementing a stack-based Finite State Machine (FSM).
/// 1. Call `_phaseGuardInit()` during initialization (Constructor or Proxy Init).
/// 2. Override `_checkAdmin()` to enforce access control (e.g., `Ownable`, `AccessControl`).
/// 3. Apply the `withMutating` modifier to all external state-changing functions.
/// 4. Apply the `withView` modifier to all external view functions.
/// 5. Wrap all external calls in `_startExternalizing()` / `_endExternalizing()` or `_startExternalizingWithCallback()` / `_endExternalizingWithCallback()`.
abstract contract PhaseGuard {

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Contract phases.
    /// @dev Contract must return to a stable phase after functions finish executing.
    enum Phase {
        UNINITIALIZED, // 0: Not initialized, unstable
        READY, // 1: Initialized, stable
        MUTATING, // 2: Write phase, unstable
        EXTERNALIZING, // 3: Outbound-call phase, unstable
        CALLBACKING, // 4: Transient hook window, unstable
        FINALIZED, // 5: Terminal locked state, stable
        PAUSED, // 6: Temporary locked state, stable
        MAINTENANCE // 7: Admin-only maintenance/upgrade window, stable
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-7201 NAMESPACED STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev PhaseGuard storage laid out in an ERC-7201 namespace to eliminate
    /// storage-slot collisions when used behind upgradeable proxies.
    /// @custom:storage-location erc7201:phaseguard.storage.PhaseGuard
    struct PhaseGuardStorage {
        /// @dev Global contract phase.
        Phase _phase;
        /// @dev Stack of phases tracked during each function call. Used to unwind nested transitions.
        /// First element is always the resting stable phase.
        /// E.g.,  1. [READY] 2. [READY, MUTATING] 3. [READY, MUTATING, EXTERNALIZING] 4. [READY, MUTATING] 5. [READY]
        Phase[] _phaseStack;
    }

    // keccak256(abi.encode(uint256(keccak256("phaseguard.storage.PhaseGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PHASEGUARD_STORAGE = 0x1b9524599e3b924a74c6b86d062db59fe7ffb1495cb93298113271b051cd8600;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS / BIT FLAGS
    //////////////////////////////////////////////////////////////*/

    /// @dev Allow inbound non-admin callers: bit 0
    uint8 internal constant ALLOW_USER = 1 << 0; 
    /// @dev Allow inbound admin callers: bit 1
    uint8 internal constant ALLOW_ADMIN = 1 << 1;
    /// @dev Allow outbound external calls to other contracts: bit 2
    uint8 internal constant ALLOW_EXTERNAL = 1 << 2;
    /// @dev Allow value / ETH transfers: bit 3
    uint8 internal constant ALLOW_VALUE = 1 << 3;
    /// @dev Allow access to view functions: bit 4
    uint8 internal constant ALLOW_VIEWS = 1 << 4;
    /// @dev Allow writing to storage: bit 5
    uint8 internal constant ALLOW_WRITES = 1 << 5;
    /// @dev Allow callbacks during external calls: bit 6
    uint8 internal constant ALLOW_CALLBACKS = 1 << 6;
    /// @dev Allow delegatecalls: bit 7
    uint8 internal constant ALLOW_DELEGATECALL = 1 << 7;


    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the contract transitions to a new phase.
    /// @param from Phase being exited. 
    /// @param to  Phase being entered.
    event PhaseTransition(Phase from, Phase to);

    /*//////////////////////////////////////////////////////////////
                             CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the required entry policy is not met when entering a new phase. 
    error PolicyGateLocked();
    
    /// @notice Thrown when the phase transition is not allowed based on the transition matrix.
    error TransitionGateLocked();
    
    /// @notice Thrown when the array size of `_phaseStack` is inconsistent with what is expected. 
    error StackSizeError();

    /// @notice Thrown when the global contract phase is not the same as the sole stack element.
    error StackInconsistencyError();

    /// @notice Thrown when entry to a view function is blocked. 
    error ViewsLocked();

    /// @notice Thrown when the contract remains in an unstable phase at the end of a transaction.
    error PhaseStabilityInvariant();
    
    /// @notice Thrown when the stack contains residual states (length != 1) at the end of a transaction.
    error StackLengthInvariant();
    
    /// @notice Thrown when the global phase does not match the resting stack state.
    error StackStateInvariant();

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @notice Bootstraps the contract from UNINITIALIZED to READY.
    /// @dev Must be called during the constructor or proxy `initialize` otherwise the contract will be bricked.
    /// Ensures atomic initialization. 
    ///
    /// Example with a constructor:
    /// ```solidity
    /// constructor() {
    ///     _phaseGuardInit();
    /// }
    /// ```
    ///
    /// Example when using OZ UUPS proxy:
    /// ```solidity
    /// constructor() {
    ///     _disableInitializers(); // disable initializers in the implementation
    /// }
    /// 
    /// function initialize() external initializer {
    ///     __Ownable_init(msg.sender);
    ///     _phaseGuardInit();
    /// }
    /// ```
    /// 
    /// @custom:error `TransitionGateLocked()` if the current phase is not `UNINITIALIZED`: initialization can only occur once.
    /// @custom:error `StackSizeError()` if the `_phaseStack` is not empty.
    function _phaseGuardInit() internal {
        PhaseGuardStorage storage $ = _getStorage();
        if($._phase != Phase.UNINITIALIZED) {
            revert TransitionGateLocked();
        }

        $._phase = Phase.READY;
        // Unreachable error under normal circumstances but added for defense-in-depth:
        if($._phaseStack.length != 0) revert StackSizeError();
        $._phaseStack.push($._phase);
        emit PhaseTransition(Phase.UNINITIALIZED, Phase.READY);
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Top-level entry point for state-changing functions.
    /// @dev Wraps the function body to enforce the MUTATING phase lifecycle:
    /// 1. `_withMutatingBefore()`: Validates permissions, checks invariants, and enters phase.
    /// 2. `_`: Executes function body.
    /// 3. `_withMutatingAfter()`: Unwinds phase and verifies final invariants.
    /// @custom:error `PolicyGateLocked()` if neither user nor admin entry is allowed in the current phase.
    modifier withMutating() {
        _withMutatingBefore();
        _;
        _withMutatingAfter();
    }

    /// @notice Top-level entry point for view functions.
    /// @dev Allows access to view functions only in phases where ALLOW_VIEWS is enabled.
    /// Should be used in all external / public view functions. 
    /// View functions without the modifier should be internal helpers. 
    modifier withView() {
        _withView();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Admin protected function that transitions the global phase.
    /// @dev Protected by _checkAdmin(). 
    /// Does not allow transitioning to an unstable state (invariant check).
    /// Does not allow transitioning while operations are ongoing (invariant check).
    /// Enforces Stable fromPhase -> Stable toPhase.
    /// @param toPhase phase being entered.
    /// @custom:error `TransitionGateLocked()` if the forward path is invalid in the matrix.
    function transitionTo(Phase toPhase) external virtual {
        _checkAdmin();
        _checkInvariants();

        PhaseGuardStorage storage $ = _getStorage();
        Phase currentPhase = $._phase;

        // Fail early: avoids wasting gas on SSTOREs that would be reverted by _checkInvariants().
        if(!isStable(toPhase)) revert PhaseStabilityInvariant();

        // Transition Gate
        bool isAllowed = isTransitionAllowed(currentPhase, toPhase);
        if(!isAllowed) revert TransitionGateLocked();
        
        // State update
        $._phase = toPhase;
        $._phaseStack[0] = toPhase;
        emit PhaseTransition(currentPhase, toPhase);

        _checkInvariants();
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the current global phase of the contract.
    /// @return The current `Phase` enum value.
    function phase() public view returns (Phase) {
        return _getStorage()._phase;
    }

    /// @notice Returns the current depth of the phase stack.
    /// @dev At rest the stack depth is 1 (containing only the base stable phase).
    /// A depth greater than 1 indicates the contract is mid-operation.
    /// @return The number of entries in `_phaseStack`.
    function phaseStackDepth() public view returns (uint256) {
        return _getStorage()._phaseStack.length;
    }

    /// @notice Returns the base (resting) phase at the bottom of the stack.
    /// @dev At rest, this should always equal `phase()`.
    /// @return The first element of `_phaseStack`.
    function phaseStackBase() public view returns (Phase) {
        return _getStorage()._phaseStack[0];
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC PURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Evaluates whether a forward transition from one phase to another is allowed in the transition matrix.
    /// @dev Encodes only forward transitions. Reverse transitions (stack unwinding) are handled
    /// implicitly by `_exitPhase` which restores the previous phase from the stack.
    /// @param from Phase being exited.
    /// @param  to Phase being entered.
    /// @return true if the transition is allowed and false otherwise. 
    function isTransitionAllowed(Phase from, Phase to) public pure virtual returns (bool) {
        // UNINITIALIZED (Phase ID 0) Transitions
        if(from == Phase.UNINITIALIZED) {
            return to == Phase.READY; 
        }

        // READY (Phase ID 1) Transitions
        if(from == Phase.READY) {
            return to == Phase.MUTATING || 
                   to == Phase.FINALIZED || 
                   to == Phase.PAUSED || 
                   to == Phase.MAINTENANCE; 
        }

        // MUTATING (Phase ID 2) Transitions
        if(from == Phase.MUTATING) {
            return to == Phase.EXTERNALIZING; 
        }

        // EXTERNALIZING (Phase ID 3) Transitions
        if(from == Phase.EXTERNALIZING) {
            return to == Phase.CALLBACKING;
        }

        // PAUSED (Phase ID 6) Transitions
        if(from == Phase.PAUSED) {
            return to == Phase.READY || 
                   to == Phase.MAINTENANCE || 
                   to == Phase.FINALIZED; 
        }

        // MAINTENANCE (Phase ID 7) Transitions
        if(from == Phase.MAINTENANCE) {
            return to == Phase.READY || 
                   to == Phase.MUTATING; 
        }

        // CALLBACKING (Phase ID 4): No forward transitions.
        // FINALIZED (Phase ID 5): Terminal state, no transitions allowed.
        return false;
    }

    /// @notice Checks whether a given phase is stable or unstable. 
    /// @dev Contract state MUST both start and end in a stable state when functions are entered or return. 
    /// @param phase_ Phase whose stability is being checked.
    /// @return true if given phase is stable.
    function isStable(Phase phase_) public pure returns (bool) {
        return phase_ == Phase.READY || 
               phase_ == Phase.FINALIZED ||
               phase_ == Phase.PAUSED ||
               phase_ == Phase.MAINTENANCE;
    } 

    /// @notice Returns policy bitmask for a given phase.
    /// @dev Combines the individual bitflags to get the final uint8 bitmask. Override to customize. 
    /// @param phase_ Phase whose policy is being fetched.
    /// @return uint8 policy of the given phase.
    function getPolicy(Phase phase_) public pure virtual returns (uint8) {
        // UNINITIALIZED (Phase ID 0) policy
        if(phase_ == Phase.UNINITIALIZED) return 0; 

        // READY (Phase ID 1) policy
        if(phase_ == Phase.READY) {
            return ALLOW_USER | ALLOW_ADMIN | ALLOW_VIEWS;
        }

        // MUTATING (Phase ID 2) policy
        if(phase_ == Phase.MUTATING) {
            return ALLOW_WRITES;
        }

        // EXTERNALIZING (Phase ID 3) policy
        if(phase_ == Phase.EXTERNALIZING) {
            return ALLOW_EXTERNAL | ALLOW_VALUE;
        }

        // CALLBACKING (Phase ID 4) policy
        if(phase_ == Phase.CALLBACKING) {
            return ALLOW_CALLBACKS;
        }

        // FINALIZED (Phase ID 5) policy
        if(phase_ == Phase.FINALIZED) {
            return ALLOW_VIEWS;
        }

        // PAUSED (Phase ID 6) policy
        if(phase_ == Phase.PAUSED) {
            return ALLOW_ADMIN | ALLOW_VIEWS;
        }

        // MAINTENANCE (Phase ID 7) policy
        if(phase_ == Phase.MAINTENANCE) {
            return ALLOW_ADMIN | ALLOW_EXTERNAL | ALLOW_VALUE | ALLOW_WRITES | ALLOW_VIEWS | ALLOW_CALLBACKS | ALLOW_DELEGATECALL;
        }

        // Unreachable on Solidity ≥0.8.0 (enum bounds are validated at runtime).
        // Kept as defense-in-depth: blocks all entry-points for any unexpected value.
        return 0;
    }
    

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS / ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    /// @notice Admin access control hook. Must revert if `msg.sender` is not authorized.
    /// @dev Must be overridden in inherited contracts.
    /// Used internally by PhaseGuard to gate phase entry. 
    /// Do NOT use for per-function access control: use OZ `onlyOwner()` or `onlyRole()` directly on the function instead.
    /// 
    /// Example using OZ Ownable:
    /// ```solidity
    /// function _checkAdmin() internal view override {
    ///     if(msg.sender != owner()) revert AccessDenied(msg.sender);
    /// }
    /// ```
    /// 
    /// Example using OZ AccessControl:
    /// ```solidity
    /// function _checkAdmin() internal view override {
    ///     _checkRole(DEFAULT_ADMIN_ROLE);
    /// }
    /// ```
    function _checkAdmin() internal view virtual;

    /*//////////////////////////////////////////////////////////////
                           SCOPED HELPERS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                             1. EXTERNALIZING
    //////////////////////////////////////////////////////////////*/

    /// @notice Manually enters the `EXTERNALIZING` phase to permit outbound external calls.
    /// @dev Must be paired with `_endExternalizing()` to safely unwind the state.
    /// Requires the current phase to have `ALLOW_WRITES` (i.e., in MUTATING).
    /// While EXTERNALIZING is active, storage writes are disabled to prevent state changes during the external call.
    function _startExternalizing() internal {
        // Only MUTATING can transition to EXTERNALIZING
        // CALLBACKING can unwind back to EXTERNALIZING
        uint8 requiredEntryPolicy = ALLOW_WRITES;
        _enterPhase(Phase.EXTERNALIZING, requiredEntryPolicy);
    }

    /// @notice Unwinds the `EXTERNALIZING` phase.
    /// @dev Must be paired with `_startExternalizing()`.
    function _endExternalizing() internal {
        _exitPhase();
    }

    /*//////////////////////////////////////////////////////////////
                            2. CALLBACKING
    //////////////////////////////////////////////////////////////*/

    /// @notice Scoped helper that manually enters the `EXTERNALIZING` and then `CALLBACKING` phase to permit outbound external calls with callbacks.
    /// @dev Must be paired with `_endExternalizingWithCallback()` to safely unwind the state.
    /// To enter the `CALLBACKING` phase, current phase has to be `EXTERNALIZING` (i.e., `ALLOW_EXTERNAL`).
    /// While `CALLBACKING` is active, storage writes and entry to user-facing functions are disabled.
    function _startExternalizingWithCallback() internal {
        _startExternalizing();
        _startCallbacking();
    }

    /// @notice Unwinds both the `CALLBACKING` and `EXTERNALIZING` phases (two stack frames).
    /// @dev Must be paired with `_startExternalizingWithCallback()`.
    function _endExternalizingWithCallback() internal {
        // 1. Exit CALLBACKING
        _endCallbacking();
        // 2. Exit EXTERNALIZING
        _endExternalizing();
    }

    /// @notice Manually enters the `CALLBACKING` phase to handle expected reentrant hooks (e.g., `onERC721Received`).
    /// @dev Must be paired with `_endCallbacking()` or used via `_endExternalizingWithCallback()`.
    /// Current phase must be `EXTERNALIZING` (policy allows `ALLOW_EXTERNAL`) otherwise it reverts.
    /// Enables specific reentrancy paths (`ALLOW_CALLBACKS`) while keeping general user entry (`ALLOW_USER`) locked.
    /// Use `_startExternalizingWithCallback()` instead of calling this directly to enforce correct nesting.
    function _startCallbacking() internal {
        // Only EXTERNALIZING can transition to CALLBACKING
        uint8 requiredEntryPolicy = ALLOW_EXTERNAL;
        _enterPhase(Phase.CALLBACKING, requiredEntryPolicy);
    }

    /// @notice Unwinds the `CALLBACKING` phase.
    /// @dev Must be paired with `_startCallbacking()`.
    /// Both `_endCallbacking` and `_endExternalizing` delegate to `_exitPhase` but are kept
    /// as separate functions to mirror their `_start*` counterparts and show intent.
    function _endCallbacking() internal {
        _exitPhase();
    }

    /*//////////////////////////////////////////////////////////////
                            PRIVATE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Internal logic to validate and execute a forward phase transition.
    /// @dev Two gates must pass before the transition is executed:
    /// 1. Policy Gate: Current phase must have the required permission bits. 
    /// 2. Transition Gate: The transition must be allowed in the matrix. 
    /// Updates the global `_phase` and pushes the `toPhase` onto `_phaseStack`.
    /// @param toPhase Phase being entered.
    /// @param requiredEntryPolicy Bitmask of permissions the current phase must possess to allow this transition.
    /// @custom:error `PolicyGateLocked()` if the current phase's policy does not contain the required bitmask of permissions.
    /// @custom:error `TransitionGateLocked()` if the forward path is invalid in the matrix.
    function _enterPhase(Phase toPhase, uint8 requiredEntryPolicy) private {
        PhaseGuardStorage storage $ = _getStorage();
        Phase currentPhase = $._phase;

        // Policy Gate: Check current policy against required permissions 
        uint8 currentPolicy = getPolicy(currentPhase);
        if( (currentPolicy & requiredEntryPolicy) == 0) {
            revert PolicyGateLocked();
        }

        // Transition Gate: Check if transition is allowed in the transition matrix.
        // Unreachable under normal execution as the policy gate above is strict enough 
        // to catch all invalid paths. Kept as defense-in-depth in case policies are overridden.
        bool isAllowed = isTransitionAllowed(currentPhase, toPhase);
        if(!isAllowed) revert TransitionGateLocked();
        
        // State update
        $._phase = toPhase;
        $._phaseStack.push(toPhase);
        emit PhaseTransition(currentPhase, toPhase);
    }

    /// @notice Internal logic to unwind the phase stack and return to the previous phase.
    /// @dev Reverses the action of `_enterPhase` by popping the stack.
    /// No transition matrix check needed: the reverse path is guaranteed valid because the forward path was validated by `_enterPhase` on entry.
    /// @custom:error `StackSizeError()` if operation attempts to pop the base state.
    /// @custom:error `StackInconsistencyError()` if global `_phase` desynchronized from the stack.
    function _exitPhase() private {
        PhaseGuardStorage storage $ = _getStorage();

        // Stack size check: stack should contain at least the current and previous phases for _exitPhase to work. 
        uint256 stackSize = $._phaseStack.length;
        if(stackSize < 2) revert StackSizeError();

        // Phase at top of the stack should be the same as global phase:
        // Unreachable under normal execution (`_phase` is always kept in sync with the stack top)
        // but kept as defense-in-depth as it guards against raw storage corruption.
        Phase fromPhase = $._phaseStack[stackSize - 1];
        if(fromPhase != $._phase) revert StackInconsistencyError();

        // Get previous phase from stack.
        Phase toPhase = $._phaseStack[stackSize - 2];

        // Pop the current phase.
        $._phaseStack.pop();

        // Restore the previous phase.
        $._phase = toPhase;
        emit PhaseTransition(fromPhase, toPhase);
    }

    /// @notice Ensures the contract is in a valid resting state.
    /// @dev Checks three conditions required for a valid resting state:
    /// 1. Stability: Global phase functions must return to a `Stable` state (e.g., READY, MAINTENANCE).
    /// 2. Stack Cleanliness: Stack length must be exactly 1 (containing only the base state).
    /// 3. Consistency: The stack's single element must match the global `_phase`.
    /// @custom:error `PhaseStabilityInvariant()` if the contract ends in an unstable state.
    /// @custom:error `StackLengthInvariant()` if the stack was not unwound correctly.
    /// @custom:error `StackStateInvariant()` if global phase desynchronized from the base stack.
    function _checkInvariants() private view {
        PhaseGuardStorage storage $ = _getStorage();
        Phase currentPhase = $._phase;
        if(!isStable(currentPhase)) revert PhaseStabilityInvariant();
        // The following two checks are defense-in-depth: under correct usage the
        // stability check above will catch misuse first, because unstable phases
        // are always pushed/popped together with the stack.
        if($._phaseStack.length != 1) revert StackLengthInvariant();
        if(currentPhase != $._phaseStack[0]) revert StackStateInvariant();
    }

    /// @notice Pre-execution guard logic for the Mutating modifier.
    /// @dev Performed steps:
    /// 1. Checks pre-execution invariants to ensure atomic start state.
    /// 2. Evaluates current policy permissions:
    ///    - If `ALLOW_USER` bit is set: Access granted.
    ///    - If only `ALLOW_ADMIN` bit is set: Calls `_checkAdmin()` (must revert if unauthorized).
    ///    - If neither: Reverts with `PolicyGateLocked`.
    /// 3. Calls `_enterPhase` to transition to `Phase.MUTATING`.
    function _withMutatingBefore() private {
        _checkInvariants();
        
        Phase currentPhase = _getStorage()._phase;
        uint8 currentPolicy = getPolicy(currentPhase);

        // Check access rights:
        bool isUserAllowed = (currentPolicy & ALLOW_USER) != 0;
        bool isAdminAllowed = (currentPolicy & ALLOW_ADMIN) != 0;

        // Pass if isUserAllowed == true
        if(!isUserAllowed) {
            if (isAdminAllowed) {
                // If only admin entry is allowed check access rights (reverts if not admin):
                _checkAdmin();
            } else {
                // If no users / admins are allowed revert:
                revert PolicyGateLocked();
            }
        }
        
        // Require ALLOW_USER or ALLOW_ADMIN on the current phase to enter MUTATING.
        // Only READY (user + admin) and MAINTENANCE (admin only) satisfy both the policy
        // and the transition matrix. PAUSED has ALLOW_ADMIN but PAUSED -> MUTATING is
        // blocked by the transition gate inside `_enterPhase`.
        uint8 requiredEntryPolicy = ALLOW_USER | ALLOW_ADMIN;
        _enterPhase(Phase.MUTATING, requiredEntryPolicy);
    }

    /// @notice Post-execution cleanup logic for the Mutating modifier.
    /// @dev Performed steps:
    /// 1. Calls `_exitPhase` to pop the stack and return to the previous stable phase.
    /// 2. Checks post-execution invariants to ensure the contract is not left in a dirty state.
    function _withMutatingAfter() private {
        _exitPhase();
        _checkInvariants();
    }

    /// @dev Internal helper for `withView`. Wraps logic to reduce bytecode size.
    function _withView() private view {
        if( (getPolicy(_getStorage()._phase) & ALLOW_VIEWS) != ALLOW_VIEWS) revert ViewsLocked();
    }

    /// @dev Returns a pointer to the ERC-7201 namespaced storage struct.
    function _getStorage() private pure returns (PhaseGuardStorage storage $) {
        bytes32 slot = PHASEGUARD_STORAGE;
        assembly {
            $.slot := slot
        }
    }

}
