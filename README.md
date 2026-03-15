
# PhaseGuard

## Abstract

A standard interface for smart contracts that manage their lifecycle through a finite state machine. A conforming contract exposes its current phase, a per-phase access-policy bitmask, and a transition-legality check through three read functions and one event. All guarded entry points share a single 6-phase transition matrix, so lifecycle protection is enforced at the phase level rather than per-function.

## Motivation

Smart contract lifecycle protection is typically assembled from independent mechanisms: reentrancy guards, pause switches, and initialization guards. Each mechanism must be applied correctly to every relevant entry point, and there is no shared model that links them or enforces consistency across the public surface.

That per-function approach keeps producing the same exploit classes: reentrancy (including read-only and cross-function variants), incomplete pause coverage, and uninitialized state exposure. See Security Considerations for a detailed mapping of each class to the phase model.

No existing ERC defines a common interface for contract lifecycle state. Existing patterns address individual concerns, but they expose only isolated, implementation-specific signals. A contract may expose `paused()`, but there is no standard interface that lets an external caller reason uniformly about bootstrap state, in-flight mutation, maintenance mode, terminal finalization, and transition legality across implementations.

A standard interface would let composing contracts check a dependency's lifecycle phase before routing funds or executing a governance action. For instance, a contract could avoid calling a dependency while it is MUTATING, a timelock could verify a target is in READY before executing a queued proposal, and a monitoring system could watch for phase changes across any conforming contract without per-protocol adapters.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### Definitions

- **phase**: a `uint8` value identifying the current lifecycle state of the contract.
- **stable phase**: a phase that MAY persist as the global phase after an external call completes (READY, FINALIZED, PAUSED, MAINTENANCE).
- **unstable phase**: a phase that MUST NOT persist as the global phase after an external call completes (UNINITIALIZED, MUTATING).
- **guarded entry point**: an `external` or `public` function that carries a guard modifier and is therefore subject to phase-level access control.
- **bootstrap**: the one-time transition from UNINITIALIZED to READY that activates the contract.
- **admin**: an address authorized by the implementation to trigger phase transitions between stable phases.

### Interface

A conforming contract MUST implement the following interface:

```solidity
interface IPhaseGuard /* is ERC165 */ {

    event PhaseTransition(uint8 indexed fromPhase, uint8 indexed toPhase);

    function phase() external view returns (uint8);

    function getPolicy(uint8 phase_) external pure returns (uint8);

    function isTransitionAllowed(uint8 from, uint8 to) external pure returns (bool);
}
```

#### Methods

##### `phase`

Returns the current global phase of the contract.

MUST return a valid phase identifier (`0` through `5`).

```yaml
- name: phase
  type: function
  stateMutability: view

  inputs: []
  outputs:
    - name: currentPhase
      type: uint8
```

##### `getPolicy`

Returns the policy bitmask for the given phase.

MUST return a `uint8` with bits 3–7 as `0`.

```yaml
- name: getPolicy
  type: function
  stateMutability: pure

  inputs:
    - name: phase_
      type: uint8
  outputs:
    - name: policy
      type: uint8
```

##### `isTransitionAllowed`

Returns whether a forward transition from `from` to `to` is permitted by the transition matrix.

MUST return `true` if and only if the transition is in the normative matrix.

```yaml
- name: isTransitionAllowed
  type: function
  stateMutability: pure

  inputs:
    - name: from
      type: uint8
    - name: to
      type: uint8
  outputs:
    - name: allowed
      type: bool
```

#### Events

##### `PhaseTransition`

MUST be emitted every time the global phase changes.

```yaml
- name: PhaseTransition
  type: event

  inputs:
    - name: fromPhase
      indexed: true
      type: uint8
    - name: toPhase
      indexed: true
      type: uint8
```

### Interface ID

A conforming contract MUST implement ERC-165 and return `true` for the `IPhaseGuard` interface identifier.

The interface ID is `0x90e42898`, computed as the XOR of:

```
bytes4(keccak256("phase()"))                          = 0xb1c9fe6e
bytes4(keccak256("getPolicy(uint8)"))                 = 0x04f08b55
bytes4(keccak256("isTransitionAllowed(uint8,uint8)")) = 0x25dd5da3
                                                  XOR = 0x90e42898
```

### Phases

Phase identifiers are `uint8` values. A conforming contract MUST use the following six phases:

| ID | Phase          | Type      | Description                                                                              |
|----|----------------|-----------|------------------------------------------------------------------------------------------|
| 0  | UNINITIALIZED  | Unstable  | Not initialized. MUST transition to READY in the same transaction as deployment.         |
| 1  | READY          | Stable    | Normal operating state. User entry, admin entry, and views are all permitted.            |
| 2  | MUTATING       | Unstable  | Temporary execution state. All guarded entry points and guarded views are blocked.       |
| 3  | FINALIZED      | Stable    | Terminal state. No further transitions. Views only.                                      |
| 4  | PAUSED         | Stable    | Emergency stop. User entry is blocked. Admin entry and views remain permitted.           |
| 5  | MAINTENANCE    | Stable    | Admin-only operating window. User entry is blocked. Admin entry and views remain permitted. |

A conforming contract MUST end every external call in a stable phase (READY, FINALIZED, PAUSED, or MAINTENANCE).

MUTATING is entered and exited internally by the guard mechanism. It has no forward transitions in the transition matrix and MUST NOT persist as the global phase after a call completes.

UNINITIALIZED is the default state at deployment. If bootstrap does not complete, all guarded entry MUST remain blocked.

### Transition matrix

`isTransitionAllowed` MUST return values consistent with the following matrix. Conforming implementations MUST NOT alter these values:

| From / To        | UNINITIALIZED | READY | MUTATING | FINALIZED | PAUSED | MAINTENANCE |
|------------------|---------------|-------|----------|-----------|--------|-------------|
| UNINITIALIZED    |      -        |  YES  |   NO     |   NO      |  NO    |     NO      |
| READY            |     NO        |   -   |   YES    |   YES     |  YES   |     YES     |
| MUTATING         |     NO        |  NO   |    -     |   NO      |  NO    |     NO      |
| FINALIZED        |     NO        |  NO   |   NO     |   -       |  NO    |     NO      |
| PAUSED           |     NO        |  YES  |   NO     |   YES     |  -     |     YES     |
| MAINTENANCE      |     NO        |  YES  |   YES    |   NO      |  NO    |      -      |

FINALIZED is a terminal state. Once entered, no transitions are allowed.

PAUSED and MAINTENANCE share the same policy bits but differ in the transition matrix: MAINTENANCE → MUTATING is allowed, PAUSED → MUTATING is not. PAUSED is a stop state; MAINTENANCE is an admin-only operating state.

### Policy bitmask

`getPolicy` returns a `uint8` bitmask. The three low bits are defined:

| Bit | Flag         | Meaning                                                    |
|-----|--------------|------------------------------------------------------------|
|  0  | ALLOW_USER   | Non-admin callers MAY enter guarded state-changing functions |
|  1  | ALLOW_ADMIN  | Admin callers MAY enter guarded state-changing functions     |
|  2  | ALLOW_VIEWS  | Callers MAY enter guarded view functions                     |

Bits 3 through 7 are reserved for future use and MUST be returned as `0` by `getPolicy`.

The normative policy matrix is:

| Bit Flag / Phase | UNINITIALIZED | READY | MUTATING | FINALIZED | PAUSED | MAINTENANCE |
|------------------|---------------|-------|----------|-----------|--------|-------------|
| ALLOW_USER       |      0        |   1   |    0     |     0     |   0    |      0      |
| ALLOW_ADMIN      |      0        |   1   |    0     |     0     |   1    |      1      |
| ALLOW_VIEWS      |      0        |   1   |    0     |     1     |   1    |      1      |

The bitmask format is normative. Conforming implementations MUST return values consistent with the full policy matrix above and MUST NOT alter those values.

The following security-critical consequences are called out explicitly:

- UNINITIALIZED MUST return `0` (all bits off). Guarded entry MUST remain blocked before bootstrap completes.
- MUTATING MUST return `0` (all bits off). This is the lock: no guarded entry or guarded views while the contract is mid-operation.
- PAUSED MUST return ALLOW_USER as `0`. The purpose of PAUSED is to close user entry. Allowing it would contradict the phase's definition.

## Rationale

### Phases

The six phases map directly to the lifecycle states that show up in practice: deploy → operate → pause / maintain → shut down, with a transient lock state for mid-operation exclusion. Fewer phases would collapse distinct operational needs (PAUSED and MAINTENANCE differ in the transition matrix — MAINTENANCE allows MUTATING, PAUSED does not). More phases would push application-specific concerns into the standard. Six is the minimal set that covers the exploit classes listed in Motivation while keeping the transition matrix minimal enough.

### Core invariant

Splitting phases into stable (READY, FINALIZED, PAUSED, MAINTENANCE) and unstable (UNINITIALIZED, MUTATING) makes the invariant easy to state: the contract must be in a stable phase after every external call. MUTATING is the lock: it exists only during execution. UNINITIALIZED exists only before bootstrap completes. Neither should be observable by an external caller between transactions.

### Bitmask

A single `uint8` policy bitmask replaces what would otherwise be three separate view functions (`allowsUser()`, `allowsAdmin()`, `allowsViews()`). One call returns all access flags for a phase. The bitmask is cheaper to store and query, and the five reserved bits leave room for future flags without changing the interface.

## Security Considerations

PhaseGuard addresses the following exploit classes for guarded entry points:

| Exploit class | Mechanism | PhaseGuard effect |
|---|---|---|
| Regular reentrancy | A callback re-enters before state has settled (the DAO hack, 2016). | `MUTATING` blocks guarded state-changing re-entry. |
| Read-only reentrancy | Views expose intermediate state during a callback. Curve and Balancer pool exploits used stale share-price reads mid-operation. | Guarded views revert while `MUTATING` is active. |
| Cross-function reentrancy | A callback enters a different function that sees partially updated state, observed in NFT staking and reward-distribution exploits. | All guarded state-changing entry points are closed during `MUTATING`. |
| Pause bypass | One entry point misses `whenNotPaused`, leaving a live code path during an emergency (Compound Proposal 62). | Phase-level policy closes all guarded user entry in `PAUSED`. |
| Uninitialized state exposure | A contract is externally usable before critical state is set. The Nomad bridge exploit relied on zeroed state that was never initialized. | Guarded entry remains blocked in `UNINITIALIZED`. |

`MAINTENANCE` gives admins an operating window with guarded user entry closed. `FINALIZED` is a terminal, view-only state with no further transitions.

### Coverage boundary

PhaseGuard is a lifecycle and guarded-entry primitive. It does not address oracle correctness, arithmetic bugs, slippage or MEV, access-control design, or arbitrary call / delegatecall vulnerabilities.

The protection applies only to entry points that carry the guard modifiers. Any external or public function that omits the modifier is outside the phase model and will not be blocked by phase transitions.

### Admin trust assumption

Phase transitions between stable phases (READY, PAUSED, MAINTENANCE, FINALIZED) are controlled by admin-gated functions. The security model assumes a trusted or governance-controlled admin. A compromised admin key can move the contract to PAUSED or FINALIZED at will.

Representative examples are documented in [`docs/security-model.md`](docs/security-model.md).

## Backwards Compatibility

This ERC introduces a new interface. There are no backwards compatibility issues with existing standards.

The reference implementation uses ERC-7201 namespaced storage, which avoids slot collisions when composed with other upgradeable contracts or inherited alongside existing storage layouts.

## Reference Implementation

The following is a simplified pseudocode excerpt. The full implementation is in [`src/PhaseGuard.sol`](src/PhaseGuard.sol).

```solidity
// SPDX-License-Identifier: CC0-1.0
// This code snippet is incomplete pseudocode used for example only
// and is not intended to be used in production or guaranteed to be secure.

abstract contract PhaseGuard is IPhaseGuard {

    uint8 internal constant ALLOW_USER  = 1; // bit 0
    uint8 internal constant ALLOW_ADMIN = 2; // bit 1
    uint8 internal constant ALLOW_VIEWS = 4; // bit 2

    function phase() public view returns (uint8) {
        // return current global phase from storage
    }

    function supportsInterface(bytes4 interfaceId) public pure virtual returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == 0x90e42898;
    }

    function isTransitionAllowed(uint8 from, uint8 to) public pure returns (bool) {
        // UNINITIALIZED -> READY
        // READY         -> MUTATING, FINALIZED, PAUSED, MAINTENANCE
        // PAUSED        -> READY, FINALIZED, MAINTENANCE
        // MAINTENANCE   -> READY, MUTATING
        // all others    -> false
    }

    function getPolicy(uint8 phase_) public pure returns (uint8) {
        // UNINITIALIZED -> 0
        // READY         -> ALLOW_USER | ALLOW_ADMIN | ALLOW_VIEWS
        // MUTATING      -> 0
        // FINALIZED     -> ALLOW_VIEWS
        // PAUSED        -> ALLOW_ADMIN | ALLOW_VIEWS
        // MAINTENANCE   -> ALLOW_ADMIN | ALLOW_VIEWS
    }
}
```

An integration example with an ERC-4626 vault is in [`src/extensions/PhaseGuardERC4626.sol`](src/extensions/PhaseGuardERC4626.sol).

## Test Cases

The full test suite is in [`test/unit/PhaseGuard.t.sol`](test/unit/PhaseGuard.t.sol). Key invariants verified:

- `phase()` returns READY after bootstrap; returns MUTATING during a guarded call.
- Every cell in the 6 × 6 transition matrix is tested against `isTransitionAllowed`.
- `getPolicy` returns `0` for UNINITIALIZED and MUTATING; returns ALLOW_USER as `0` for PAUSED.
- `supportsInterface` returns `true` for `0x01ffc9a7` (ERC-165) and `0x90e42898` (IPhaseGuard), `false` for `0xffffffff`.
- Guarded entry points revert when called in a disallowed phase; callbacks cannot re-enter during MUTATING.

The [`test/exploit/`](test/exploit/) directory contains one test per exploit class from Security Considerations. Each test deploys a vulnerable contract without PhaseGuard and a guarded variant, then confirms the exploit succeeds on the former and reverts on the latter.

---

*The following sections are non-normative.*

## How to use

1. Inherit from `PhaseGuard`.
2. Implement `_checkAdmin()` using your chosen access-control system.
3. Call `_phaseGuardInit()` during constructor execution or initialization.
4. Apply `withMutating` to all external/public state-changing entry points.
5. Apply `withView` to all external/public view functions.
6. Use `transitionTo()` to move between stable lifecycle phases.

In practice, all external/public state-changing entry points should use `withMutating`, and all external/public view functions should use `withView`. The default is whole-interface coverage, not function-by-function guesswork.

Because guarded views are blocked during `MUTATING`, contracts may need a split-view pattern: keep the guarded external/public view as the public interface, and move the shared read logic into an internal helper that mutating code can call directly.

Minimal example:

```solidity
contract Example is PhaseGuard {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
        _phaseGuardInit();
    }

    function _checkAdmin() internal view override {
        require(msg.sender == owner, "not admin");
    }

    function deposit() external payable withMutating {
        // state-changing logic
    }

    function totalAssets() external view withView returns (uint256) {
        // read logic
    }
}
```

Full integration guidance is in [`docs/integration.md`](docs/integration.md).

## Additional reading

- [`docs/security-model.md`](docs/security-model.md)
- [`docs/integration.md`](docs/integration.md)

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
