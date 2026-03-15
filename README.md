
# PhaseGuard
*Note: PhaseGuard is still in development and not ready for use*

PhaseGuard is a smart contract lifecycle manager built around a finite state machine. It routes guarded entry points through a shared 6-phase transition matrix with configurable access policies. The goal is to close off common lifecycle failures such as reentrancy, read-only reentrancy, uninitialized state exposure, and incomplete pause coverage, while also giving the contract explicit maintenance and shutdown states.

## Why it exists

Today, lifecycle and safety logic is usually spread across separate modifiers such as `nonReentrant`, `whenNotPaused`, and initializer checks. That works, but it is easy to apply unevenly. `PhaseGuard` pulls those concerns into one lifecycle machine so the public interface follows the same transition rules and the same policy table.

The current implementation is meant for lifecycle-related failures: reentrancy, stale reads during unstable execution, incomplete pause coverage, use before bootstrap finishes, and the lack of explicit maintenance and shutdown states.

## Core model

### Phase Descriptions

| ID | Phase          | Type      | Summary                                                                                  |
|----|----------------|-----------|------------------------------------------------------------------------------------------|
| 0  | Uninitialized  | Unstable  | Not initialized yet: must transition to READY in the same tx as deployment.             |
| 1  | Ready          | Stable    | Normal operating state: user entry, admin entry, and views are all allowed.             |
| 2  | Mutating       | Unstable  | Temporary execution state entered by `withMutating`: guarded state-changing entry points and guarded views are blocked until execution unwinds back to a stable phase. |
| 3  | Finalized      | Stable    | Terminal locked state: no further transitions, views only.                              |
| 4  | Paused         | Stable    | Emergency stop: user entry is blocked while admin can still manage phase transitions.   |
| 5  | Maintenance    | Stable    | Admin-only operating window: user entry stays blocked while admin actions remain available. |

## Phase Transition Matrix

Allowed forward transitions:

| From / To        | UNINITIALIZED | READY | MUTATING | FINALIZED | PAUSED | MAINTENANCE |
|------------------|---------------|-------|----------|-----------|--------|-------------|
| UNINITIALIZED    |      -        |  YES  |   NO     |   NO      |  NO    |     NO      |
| READY            |     NO        |   -   |   YES    |   YES     |  YES   |     YES     |
| MUTATING         |     NO        |  NO   |    -     |   NO      |  NO    |     NO      |
| FINALIZED        |     NO        |  NO   |   NO     |   -       |  NO    |     NO      |
| PAUSED           |     NO        |  YES  |   NO     |   YES     |  -     |     YES     |
| MAINTENANCE      |     NO        |  YES  |   YES    |   NO      |  NO    |      -      |

`MUTATING` has no forward transitions. It is entered by `withMutating` and unwound by popping the phase stack. While the contract is in that phase, other guarded entry points are closed and guarded views are blocked.

**Stable phases:**
- READY, FINALIZED, PAUSED, MAINTENANCE: the contract **must** end every call in one of these phases.

**Unstable phases:**
- UNINITIALIZED: atomic bootstrap state. It **must** transition from UNINITIALIZED to READY in the same transaction as deployment. If that does not happen, the contract becomes **bricked**.
- MUTATING: temporary write state. The contract may pass through it mid-function, but it **must** unwind back to the stable phase captured on entry (for example, READY -> MUTATING -> READY).


## Configuration

### Bit Flags

| Bit Flag    | Direction | Purpose                                                   |
|-------------|-----------|-----------------------------------------------------------|
| ALLOW_USER  | Inbound   | Allow non-admin callers to enter state-changing functions |
| ALLOW_ADMIN | Inbound   | Allow admin callers to enter state-changing functions     |
| ALLOW_VIEWS | Inbound   | Allow access to view functions                            |

- Policies are encoded as a uint8 bitmask. At the moment, only three flags are used: ALLOW_USER, ALLOW_ADMIN, and ALLOW_VIEWS.

## Default Policy Matrix

The values below are the defaults built into `getPolicy()`. They can be overridden per use case.

| Bit Flag / Phase | UNINITIALIZED | READY | MUTATING | FINALIZED | PAUSED | MAINTENANCE |
|------------------|---------------|-------|----------|-----------|--------|-------------|
| ALLOW_USER       |      NO       |  YES  |   NO     |   NO      |  NO    |     NO      |
| ALLOW_ADMIN      |      NO       |  YES  |   NO     |   NO      |  YES   |     YES     |
| ALLOW_VIEWS      |      NO       |  YES  |   NO     |   YES     |  YES   |     YES     |

- `MUTATING` has all bits off. That is the main lock: no guarded user entry, no guarded admin entry, and no guarded views while the contract is mid-operation.
- `MAINTENANCE` keeps `ALLOW_USER` off while leaving `ALLOW_ADMIN` and `ALLOW_VIEWS` on, so operators can work on the contract without reopening user entry points.
- Safe bootstrap is: deploy -> UNINITIALIZED -> `_phaseGuardInit()` -> READY. If that step is missed, guarded entry stays blocked and the contract is effectively bricked.
- `PAUSED` and `MAINTENANCE` share the same policy bits, but they are not the same state. The difference comes from the transition matrix: `MAINTENANCE` -> `MUTATING` is allowed, while `PAUSED` -> `MUTATING` is not. In practice, `PAUSED` is a stop state, while `MAINTENANCE` is an admin-only operating state.

## Security properties

The current implementation covers the following exploit classes for guarded entry points:

| Exploit class | Mechanism | PhaseGuard effect |
|---|---|---|
| Regular reentrancy | callback re-enters before state has settled | `MUTATING` blocks guarded state-changing re-entry |
| Read-only reentrancy | views observe unstable intermediate state | guarded views revert while `MUTATING` is active |
| Cross-function reentrancy | callback enters a different sensitive function | all guarded state-changing entry points are closed during `MUTATING` |
| Pause bypass / incomplete pause coverage | one user entry point misses `whenNotPaused` | phase-level policy closes guarded user entry in `PAUSED` |
| Uninitialized state exposure | contract is used before bootstrap completes | guarded entry remains blocked in `UNINITIALIZED` |

Besides those exploit-oriented properties, `MAINTENANCE` gives you an admin-only operating window: guarded user entry stays closed while guarded admin actions remain available. `FINALIZED` gives you a terminal, view-only state for irreversible shutdown.

Representative examples are documented in [`docs/security-model.md`](docs/security-model.md).

## How to use

1. Inherit from `PhaseGuard`.
2. Implement `_checkAdmin()` using your chosen access-control system.
3. Call `_phaseGuardInit()` during constructor execution or initialization.
4. Apply `withMutating` to all external/public state-changing entry points.
5. Apply `withView` to all external/public view functions.
6. Use `transitionTo()` to move between stable lifecycle phases.

For the model to work properly, the public interface should be guarded by default. In practice, that means all external/public state-changing entry points should use `withMutating`, and all external/public view functions should use `withView`. The default is whole-interface coverage, not function-by-function guesswork.

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

    function mutate() external withMutating {
        // state-changing logic
    }

    function status() external view withView returns (Phase) {
        return phase();
    }
}
```

Full integration guidance is in [`docs/integration.md`](docs/integration.md).

## Scope

`PhaseGuard` is a lifecycle and guarded-entry primitive. It does not solve oracle correctness, arithmetic bugs, slippage or MEV, access-control design, or arbitrary call / delegatecall vulnerabilities on its own.

## Status

The repository currently implements the 6-phase model described above: `UNINITIALIZED`, `READY`, `MUTATING`, `FINALIZED`, `PAUSED`, and `MAINTENANCE`.

## Additional reading

- [`docs/security-model.md`](docs/security-model.md)
- [`docs/integration.md`](docs/integration.md)
