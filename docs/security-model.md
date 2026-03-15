# Security Model

This document describes the exploit classes addressed by the current `PhaseGuard` implementation and how the mechanism works.

## Threat Model

`PhaseGuard` is a lifecycle guard for contracts that place their public entry points behind a shared phase machine. Its current guarantees are limited to:

- gated entry into guarded state-changing functions
- gated entry into guarded view functions
- lifecycle transitions between stable phases
- fail-closed behavior before bootstrap completes

It does not inspect arbitrary writes, arbitrary external calls, arithmetic correctness, pricing logic, or access-control policy beyond the `_checkAdmin()` hook provided by the integrating contract.

## Covered Exploit Classes

### 1. Regular Reentrancy

Classic reentrancy occurs when a contract makes an external call before its accounting has settled, and the callee re-enters the same function to observe or exploit an inconsistent intermediate state.

This is the class of failure associated with the DAO hack and many later callback-driven fund extraction exploits.

In `PhaseGuard`, a guarded state-changing entry point enters `MUTATING` before user code runs. During `MUTATING`, both `ALLOW_USER` and `ALLOW_ADMIN` are disabled. A callback that tries to enter another guarded state-changing entry point reverts.

This protection applies only to guarded entry points. Unguarded code remains outside the model.

**Representative example**

```solidity
function withdraw(uint256 amount) external {
	require(bal[msg.sender] >= amount, "insufficient");
	(bool ok, ) = msg.sender.call{value: amount}("");
	require(ok, "send failed");
	bal[msg.sender] -= amount;
}
```

Here the external call occurs before accounting settles. With `PhaseGuard`, a guarded callback that tries to re-enter another guarded state-changing entry point during `MUTATING` reverts.

### 2. Read-Only Reentrancy

Read-only reentrancy occurs when a protocol exposes a view during an unstable intermediate state and an external integrator relies on that stale value.

This showed up in later DeFi incidents such as Balancer- and Curve-style stale-view or distorted-valuation patterns, where oracle-like views exposed inconsistent state during deposits, withdrawals, or rebalancing.

In `PhaseGuard`, `ALLOW_VIEWS` is disabled during `MUTATING`. A guarded view therefore reverts instead of exposing mid-operation state.

This only applies to views wrapped with `withView`.

**Representative example**

```solidity
function deposit(uint256 assets) external {
	_mint(msg.sender, assets);
	asset.transferFrom(msg.sender, address(this), assets);
	totalAssets += assets;
}

function pricePerShare() external view returns (uint256) {
	return totalAssets * 1e18 / totalSupply;
}
```

If `pricePerShare()` is callable mid-operation, an integrator can observe distorted state. With `PhaseGuard`, a guarded public view reverts during `MUTATING`.

### 3. Cross-Function Reentrancy

Cross-function reentrancy happens when a callback does not re-enter the same function, but instead enters a different sensitive function that sees partially updated state.

This pattern has repeatedly appeared in systems where one callback-enabled exit path leaves stale state visible to a second public function, including NFT staking and position-management reward exploits.

This is covered for the same reason as regular reentrancy: during `MUTATING`, all guarded state-changing entry points are closed, not just the originating function.

**Representative example**

```solidity
function unstake(uint256 tokenId) external {
	nft.safeTransferFrom(address(this), msg.sender, tokenId);
	delete stakes[tokenId];
}

function harvest(uint256 tokenId) external {
	Stake memory s = stakes[tokenId];
	require(s.owner == msg.sender, "not owner");
	rewardToken.transfer(s.owner, rewards(tokenId));
}
```

If `unstake()` triggers a callback before cleanup runs, `harvest()` can observe stale state. A guarded callback into another guarded state-changing entry point reverts during `MUTATING`.

### 4. Pause Bypass / Incomplete Pause Coverage

Modifier-based pause systems fail when one sensitive user entry point is left unguarded.

This is the same operational failure mode seen in incidents such as Compound Proposal 62, where an emergency pause mechanism existed but one live code path remained callable.

In `PhaseGuard`, pause behavior lives at the phase level rather than on individual functions. When the contract is in `PAUSED`, `ALLOW_USER` is disabled globally for guarded state-changing entry points.

That reduces the risk of incomplete pause coverage across guarded functions.

**Representative example**

```solidity
modifier whenNotPaused() {
	require(!paused, "paused");
	_;
}

function mint() external whenNotPaused {
	// ...
}

function claim() external {
	// pause modifier missing
}
```

With ordinary modifier-based pause systems, one missed entry point can remain live. In `PhaseGuard`, `PAUSED` closes guarded user state-changing entry at the phase level.

### 5. Uninitialized State Exposure

Upgradeable or initializable systems can be deployed in a usable but uninitialized state, exposing zeroed or attacker-controlled critical variables.

This class includes high-impact initialization failures such as the Nomad bridge incident, where zeroed critical state remained externally usable.

In `PhaseGuard`, public operation remains blocked while the contract is in `UNINITIALIZED`. Bootstrap requires `_phaseGuardInit()` to move the contract to `READY`. If that step is omitted, guarded entry stays blocked and the contract is effectively bricked.

This is fail-closed initialization, not automatic deployment-time initialization.

**Representative example**

```solidity
contract Replica {
	bytes32 public committedRoot;

	function initialize(bytes32 _root) external {
		committedRoot = _root;
	}

	function process(bytes calldata message, bytes32 root) external {
		require(root == committedRoot, "invalid root");
		_execute(message);
	}
}
```

If bootstrap never completes, zeroed critical state can remain exposed. In `PhaseGuard`, guarded public operation remains blocked while the contract stays in `UNINITIALIZED`.

## Why the Model Helps

The current design targets a set of failures that still shows up regularly in production systems:

- fragmented modifier application
- state exposure during callbacks
- lifecycle drift between bootstrap, normal operation, pause, maintenance, and shutdown

The main advantage is centralization. Instead of relying on each function to carry its own local safety modifiers, guarded entry points share the same lifecycle and the same policy matrix.

The same mechanism also provides two operational properties that are not themselves exploit classes:

- `MAINTENANCE` keeps guarded user entry closed while leaving guarded admin entry available. That allows admin-only maintenance without reopening the full public surface.
- `FINALIZED` provides a terminal, view-only resting state. Once reached, the transition matrix does not allow reopening operational phases. That is stronger than an ordinary pause system, which is usually meant for temporary suspension rather than irreversible shutdown.