// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

abstract contract PhaseGuard {

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/
    enum Phase {
        UNINITIALIZED,
        READY,
        MUTATING,
        EXTERNALIZING,
        FINALIZED,
        PAUSED
    }
    
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Phase => Bitmask: Packed flags containing the policy per phase
    /// @dev Bitmask policies default to 0 if uninitialized.
    mapping(Phase => uint8) public _policy; 

    /// @dev Global contract phase
    Phase internal _phase;

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
    event PhaseTransition(Phase from, Phase to);

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/


    // transition matrix: which phase transitions are allowed?
    // transition function, checkmatrix function
    // modifiers: 
    

}
