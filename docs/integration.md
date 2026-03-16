# Integration Guide

This guide covers the minimum integration steps for the current `PhaseGuard` implementation.

## 1. Inherit `PhaseGuard`

Your contract should inherit from `PhaseGuard` and provide an implementation of `_checkAdmin()`.

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
}
```

## 2. Bootstrap the lifecycle

Call `_phaseGuardInit()` during constructor execution or inside the contract's initialization flow.

If `_phaseGuardInit()` is never called, the contract remains in `UNINITIALIZED` and guarded entry points stay blocked.

## 3. Guard all external/public state-changing entry points

Apply `withMutating` to all public or external state-changing functions.

```solidity
function deposit(uint256 amount) external withMutating {
    // function body
}
```

During execution of a guarded state-changing function:

- the contract enters `MUTATING`
- guarded user and admin entry points are blocked
- guarded views are blocked
- the phase stack must unwind back to the original stable phase on return

For the lifecycle model to hold, this should be the default across the full public state-changing surface. If one external/public state-changing function is left unguarded, it sits outside the lock and outside phase-level pause semantics.

## 4. Guard all external/public view functions

Apply `withView` to external or public view functions.

```solidity
function pricePerShare() external view withView returns (uint256) {
    return totalAssets * 1e18 / totalSupply;
}
```

The default should be to wrap the full external/public view surface with `withView` and keep the read logic in internal helpers. That avoids exposing unstable state through unguarded public getters.

Because `withView` blocks guarded views during `MUTATING`, state-changing functions should not call those guarded external/public views. Use a split-view pattern instead:

- external/public guarded view: public interface
- internal unguarded helper: shared read logic callable from mutating code

Example:

```solidity
function totalAssets() external view withView returns (uint256) {
    return _totalAssets();
}

function _totalAssets() internal view returns (uint256) {
    return totalAssetsStored;
}

function withdraw(uint256 amount) external withMutating {
    uint256 assetsBefore = _totalAssets();
    // state-changing logic
}
```

## 5. Use lifecycle transitions deliberately

The current stable phases are:

- `READY`
- `PAUSED`
- `MAINTENANCE`
- `FINALIZED`

Use `transitionTo()` to move between them according to the transition matrix.

Typical operational pattern:

- deploy -> `_phaseGuardInit()` -> `READY`
- `READY` -> `PAUSED` during incident response
- `PAUSED` -> `MAINTENANCE` for admin-only actions
- `MAINTENANCE` -> `READY` to resume operation
- `READY` or `PAUSED` -> `FINALIZED` to permanently shut down state-changing access

## 6. Apply ordinary access control separately

`PhaseGuard` does not replace application-level authorization.

Use your existing access-control system for function-level permissions, for example:

- `Ownable`
- `AccessControl`
- governance adapters

`_checkAdmin()` is only the admin hook used by the lifecycle guard.

## 7. Common mistakes

### Leaving a public state-changing function unguarded

If a state-changing entry point is omitted from `withMutating`, it falls outside the shared lock and outside pause semantics.

### Leaving a public view unguarded

If an external/public view is omitted from `withView`, it can still expose state mid-operation and it no longer follows the same lifecycle policy as the rest of the interface.

### Calling guarded public views from mutating code

Because guarded views revert during `MUTATING`, mutating code should call internal read helpers rather than lifecycle-guarded external/public views.

### Treating `PhaseGuard` as CEI enforcement

`PhaseGuard` blocks guarded re-entry. It does not automatically enforce checks-effects-interactions ordering or detect arbitrary external calls.

### Treating bootstrap as automatic

`_phaseGuardInit()` must still be called by the integrating contract.

## 8. Minimal reference pattern

```solidity
contract Vault is PhaseGuard {
    address public owner;
    mapping(address => uint256) public balance;
    uint256 public totalAssets;

    constructor(address _owner) {
        owner = _owner;
        _phaseGuardInit();
    }

    function _checkAdmin() internal view override {
        require(msg.sender == owner, "not admin");
    }

    function deposit() external payable withMutating {
        balance[msg.sender] += msg.value;
        totalAssets += msg.value;
    }

    function withdraw(uint256 amount) external withMutating {
        require(balance[msg.sender] >= amount, "insufficient");
        balance[msg.sender] -= amount;
        totalAssets -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function assets() external view withView returns (uint256) {
        return totalAssets;
    }
}
```

This does not make the vault correct by itself. It places the public interface behind the shared lifecycle machine.