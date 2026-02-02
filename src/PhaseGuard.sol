// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title PhaseGuard State Machine
/// @author 0xathcb
/// @notice Abstract contract for managing phase transitions and security policies:
/// Eliminates security vulnerabilities originating from unguarded phase transitions (e.g., reentrancy, read-only reentrancy, uninitialized state, callback / delegatecall loopholes etc.).
/// @dev Inheriting contracts must override `_checkAdmin()` with their access control policy (e.g., Ownable, AccessControl).
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
        MAINTENANCE // 7: dmin-only maintenance/upgrade window, stable
    }
    
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    
    /// @dev Global contract phase.
    Phase internal _phase;
    
    /// @dev Stack of phases tracked during each function call. Always contains the current _phase as the first element.
    /// E.g., 
    /// ```text
    ///.    READY 
    ///            -> MUTATING 
    ///                        -> EXTERNALIZING 
    ///            <- MUTATING <-
    ///  <- READY
    /// ```
    /// _phaseStack: 1. [READY] 2. [READY, MUTATING] 3. [READY, MUTATING, EXTERNALIZING] 4. [READY, MUTATING] 5. [READY]
    Phase[] internal _phaseStack;

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

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @notice Bootstraps the contract from UNINITIALIZED to READY.
    /// @dev Must be called during the constructor or proxy intitialize otherwise the contract will be bricked.
    /// Ensures atomic initialization. 
    function __PhaseGuard_init() internal {
        if(_phase != Phase.UNINITIALIZED) {
            revert TransitionGateLocked();
        }

        _phase = Phase.READY;
        if(_phaseStack.length != 0) revert StackSizeError();
        _phaseStack.push(_phase);
        emit PhaseTransition(Phase.UNINITIALIZED, Phase.READY);
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Top-level entry point for state-changing functions.
    /// @dev Wraps the entire function with start / end logic:
    /// 1. Checks if invariants hold at function entry.
    /// 2. Checks access rights based on the current phase's policy.
    /// 3. If valid, it attempts to enter `Phase.MUTATING` and execute `_enterPhase`.
    /// 4. Unwinds stack back to previous phase.
    /// 5. Checks if invariants hold at function exit. 
    modifier withMutating() {
        _checkInvariants();
        
        Phase currentPhase = _phase;
        uint8 currentPolicy = getPolicy(currentPhase);

        isUserAllowed = (currentPolicy & ALLOW_USER) != 0;
        isAdminAllowed = (currentPolicy & ALLOW_ADMIN) != 0;

        if(isUserAllowed) {
            // Pass if user entry is allowed
        } else if {isAdminAllowed} {
            // If only admin entry is allowed check access rights
            // Reverts if not admin
            _checkAdmin();
        } else {
            // If no users / admins are allowed revert
            revert PolicyGateLocked();
        }
        
        // Only READY and MAINTENANCE can transition to Mutating (forward transitions)
        // Externalizing can go back to mutating but during the unwinding phase (controlled exit)
        // ALLOW_ADMIN is also enabled in PAUSED but the transition from PAUSED to MUTATING is not allowed so it reverts in _enterPhase
        uint8 requiredEntryPolicy = ALLOW_USER | ALLOW_ADMIN;
        _enterPhase(Phase.MUTATING, requiredEntryPolicy);

        _;

        _exitPhase();
        _checkInvariants();
    }

    /// @notice Top-level entry point for view functions.
    /// @dev Allows access to view functions only in phases where ALLOW_VIEWS is enabled.
    modifier withView() {
        if(getPolicy(_phase) & ALLOW_VIEWS != ALLOW_VIEWS) revert ViewsLocked();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Evaluates whether a transition from one state to another is allowed in the transition matrix.
    /// @dev 
    /// @param
    /// @param 
    /// @returns 
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
            return to == Phase.READY ||
                   to == Phase.EXTERNALIZING ||
                   to == Phase.MAINTENANCE;
        }

        // CALLBACKING (Phase ID 3) Transitions
        if(from == Phase.CALLBACKING) {
            return to == Phase.EXTERNALIZING;
        }

        // EXTERNALIZING (Phase ID 4) Transitions
        if(from == Phase.EXTERNALIZING) {
            return to == Phase.MUTATING ||
                   to == Phase.CALLBACKING;
        }

        // FINALIZED (Phase ID 5) Transitions
        if(from == Phase.FINALIZED) {
            return false;
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

        return false;
    }

    /// @notice Returns true if given phase is stable.
    /// @dev Contract state MUST be in a stable state when functions return. 
    function isStable(Phase phase) public pure returns (bool) {
        if(
            phase == Phase.READY || 
            phase == Phase.FINALIZED ||
            phase == Phase.PAUSED ||
            phase == MAINTENANCE
        ) {
            return true;
        }

        return false;
    } 

    /// @notice Returns policy bitmask for a given phase.
    /// @dev Combines the individual bitflags to get the final uint8 bitmask. Override to customize. 
    function getPolicy(Phase phase) public pure virtual returns (uint8) {
        // UNINITIALIZED (Phase ID 0) policy
        if(phase == Phase.UNINITIALIZED) return 0; 

        // READY (Phase ID 1) policy
        if(phase == Phase.READY) {
            return ALLOW_USER | ALLOW_ADMIN | ALLOW_VIEWS;
        }

        // MUTATING (Phase ID 2) policy
        if(phase == Phase.MUTATING) {
            return ALLOW_WRITES;
        }

        // CALLBACKING (Phase ID 3) policy
        if(phase == Phase.CALLBACKING) {
            return ALLOW_CALLBACKS;
        }

        // EXTERNALIZING (Phase ID 4) policy
        if(phase == Phase.EXTERNALIZING) {
            return ALLOW_EXTERNAL | ALLOW_VALUE;
        }

        // FINALIZED (Phase ID 5) policy
        if(phase == Phase.FINALIZED) {
            return 0;
        }

        // PAUSED (Phase ID 6) policy
        if(phase == Phase.PAUSED) {
            return ALLOW_ADMIN | ALLOW_VIEWS;
        }

        // MAINTENANCE (Phase ID 7) policy
        if(phase == Phase.MAINTENANCE) {
            return ALLOW_ADMIN | ALLOW_EXTERNAL | ALLOW_VALUE | ALLOW_WRITES | ALLOW_VIEWS | ALLOW_CALLBACKS | ALLOW_DELEGATECALL;
        }

        // else block all entry-points
        return 0;
    }
    
    /// @notice 
    /// @dev
    function transitionTo(Phase toPhase) external {
        _checkAdmin();
        _checkInvariants();

        Phase currentPhase = _phase;

        // Check Transition Matrix 
        bool isAllowed = isTransitionAllowed(currentPhase, toPhase);
        if(!isAllowed) revert TransitionGateLocked();
        
        // State update
        _phase = toPhase;
        _phaseStack.pop();
        _phaseStack.push(toPhase);
        emit PhaseTransition(currentPhase, toPhase);

        _checkInvariants();
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL SCOPED HELPERS
    //////////////////////////////////////////////////////////////*/


    /*//////////////////////////////////////////////////////////////
                             1. EXTERNALIZING
    //////////////////////////////////////////////////////////////*/
    function _startExternalizing() internal {
        // Only MUTATING can transition to EXTENRNALIZING
        // CALLBACKING can unwind back to EXTENRNALIZING
        uint8 requiredEntryPolicy = ALLOW_WRITES;
        _enterPhase(Phase.EXTERNALIZING, requiredEntryPolicy);
    }

    function _endExternalizing() internal {
        _exitPhase();
    }

    /*//////////////////////////////////////////////////////////////
                            2. CALLBACKING
    //////////////////////////////////////////////////////////////*/

    function _startExternalizingWithCallback() internal {
        _startExternalizing();
        _startCallbacking();
    }

    function _endExternalizingWithCallback() internal {
        // 1. Exit CALLBACKING
        _exitPhase();
        // 2. Exit EXTERNALIZING
        _exitPhase();
    }

    /*//////////////////////////////////////////////////////////////
                            PRIVATE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _enterPhase(Phase toPhase, uint8 requiredEntryPolicy) private {
        Phase currentPhase = _phase;

        // Check Policy
        uint8 currentPolicy = getPolicy(currentPhase);
        if(currentPolicy & requiredEntryPolicy[i] == 0) {
            revert PolicyGateLocked();
        }

        // Check Transition Matrix 
        bool isAllowed = isTransitionAllowed(currentPhase, toPhase);
        if(!isAllowed) revert TransitionGateLocked();
        
        // State update
        _phase = toPhase;
        _phaseStack.push(toPhase);
        emit PhaseTransition(currentPhase, toPhase);
    }

    function _exitPhase() private {
        Phase currentPhase = _phase;

        // Stack size check: stack should contain at least the current and previous phases for _exitPhase to work. 
        uint256 stackSize = _phaseStack.length;
        if(stackSize < 2) revert StackSizeError();

        // Phase at top of the stack should be the same as global phase:
        Phase fromPhase = _phaseStack[stackSize - 1];
        if(fromPhase != currentPhase) revert StackInconsistencyError();

        // Get previous phase from stack:
        Phase toPhase = _phaseStack[stackSize - 2];

        // Check that transition is allowed in the Transition Matrix: 
        bool isAllowed = isTransitionAllowed(fromPhase, toPhase);
        if(!isAllowed) revert TransitionGateLocked();

        // Pop the current phase and restore the previous phase: 
        _phaseStack.pop();
        _phase = toPhase;
        emit PhaseTransition(fromPhase, toPhase);
    }

    /// @notice Invariant checks that must hold when entering and exiting a phase.
    /// @dev 
    /// PhaseStability: The global phase must be stable when entering a new phase 
    /// StackLength: _phaseStack should only contain one element (the current phase). That shows that we are not in a mid-function operation.
    /// StackState: The stack element should be the same as the global phase.
    function _checkInvariants() private {
        Phase currentPhase = _phase;
        if(!isStable(currentPhase)) revert PhaseStabilityInvariant();
        if(_phaseStack.length != 1) revert StackLengthInvariant();
        if(currentPhase != _phaseStack[0]) revert StackStateInvariant();
    }

    function _startCallbacking() private {
        // Only EXTENRNALIZING can transition to CALLBACKING
        uint8 requiredEntryPolicy = ALLOW_EXTERNAL;
        _enterPhase(Phase.CALLBACKING, requiredEntryPolicy);
    }

    /// @dev Must be overriden in inherited contracts.
    /// Checks if `msg.sender` has the required admin rights to allow entry to a new phase.
    function _checkAdmin() internal view virtual;

    

}
