
## PhaseGuard

PhaseGuard is a lifecycle layer that routes every call through a shared phase machine, so initialization, mutation, externalization, and finalization follow one enforced order. Policies on each phase encode today’s best practices (init process, CEI, pause/upgrade invariants, and other phase-specific policies) in one guard, replacing scattered modifiers and making lifecycle mistakes structurally impossible.

## Phase Descriptions

| Phase          | Summary                                                                                  |
|----------------|------------------------------------------------------------------------------------------|
| Uninitialized  | Deployed but not initialized (initializer/init step pending).                            |
| Ready          | Initialized, stable: user/admin entrypoints and reads allowed.                           |
| Mutating       | Write phase: storage updates allowed, outbound calls/value blocked.                      |
| Externalizing  | Outbound-call phase: external calls/value allowed per policy, storage writes blocked.    |
| Finalized      | Terminal locked state: no transitions, writes, or calls.                                 |
| Paused         | Temporary locked state: normal entrypoints blocked until admin moves to Ready/Finalized; reads per policy. |

## Phase Transition Matrix

Allowed transitions:

| From / To        | UNINITIALIZED | READY | MUTATING | EXTERNALIZING | FINALIZED | PAUSED |
|------------------|---------------|-------|----------|---------------|-----------|--------|
| UNINITIALIZED    |      -        |  YES  |   NO     |     NO        |   NO      |  NO    |
| READY            |     NO        |   -   |   YES    |     YES       |   YES     |  YES   |
| MUTATING         |     NO        |  YES  |    -     |     NO        |   NO      |  NO    |
| EXTERNALIZING    |     NO        |  YES  |   NO     |     -         |   NO      |  NO    |
| FINALIZED        |     NO        |  NO   |   NO     |     NO        |   -       |  NO    |
| PAUSED           |     NO        |  YES  |   NO     |     NO        |   YES     |  -     |


## Bit Flag descriptions

| Bit Flag           | Direction | Purpose                                                     |
|--------------------|-----------|-------------------------------------------------------------|
| ALLOW_USER         | Inbound   | Allow non-admin callers to enter state-changing functions   |
| ALLOW_ADMIN        | Inbound   | Allow admin (owner/role) to enter protected functions       |
| ALLOW_EXTERNAL     | Outbound  | Allow contract to make calls to other contracts             |
| ALLOW_VALUE        | Outbound  | Allow contract to send ETH/Value                            |
| ALLOW_WRITES       | Internal  | Allow modification of state (SSTORE)                        |
| ALLOW_VIEWS        | Inbound   | Allow reading of state (View/Pure functions)                |
| ALLOW_CALLBACKS    | Inbound   | Allow re-entry during an active external call               |
| ALLOW_DELEGATECALL | Internal  | Allow delegatecall operations                               |


## Bit Flag To Phase Matrix 

The values below are just defaults - they can be adjusted on a usecase basis.

| Bit Flag / Phase | UNINITIALIZED | READY | MUTATING | EXTERNALIZING | FINALIZED | PAUSED |
|------------------|---------------|-------|----------|---------------|-----------|--------|
| ALLOW_USER       |               |       |          |               |           |        |
| ALLOW_ADMIN      |               |       |          |               |           |        |
| ALLOW_EXTERNAL   |               |       |          |               |           |        |
| ALLOW_VALUE      |               |       |          |               |           |        |
| ALLOW_WRITES     |               |       |          |               |           |        |
| ALLOW_VIEWS      |               |       |          |               |           |        |
| ALLOW_CALLBACKS  |               |       |          |               |           |        |
| ALLOW_DELEGATECALL|              |       |          |               |           |        |

## Exploits

Below is a list of common exploits PhaseGuard aims to tackle.

### 1. Regular Reentrancy (Fund Draining)

Classic "DAO hack" style reentrancy where an attacker re-enters a function to drain funds before the balance is updated.

|  | Description |
|-----------|-------------|
| **Victim** | The Contract itself (accounting mismatch) |
| **Trigger** | Callback on value transfer (`msg.sender.call`) |
| **Result** | Inconsistent contract accounting (double spend) |
| **Attack** | Loop withdrawal to drain funds |

**Example:**
```solidity
// Vulnerable pattern: updates state AFTER external call (violates CEI)
function withdraw(uint256 amount) external {
    require(bal[msg.sender] >= amount, "insufficient");
    // Interaction: External call to user 
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "send failed");
    // Effect: Attacker reenters here before balance is reduced
    bal[msg.sender] -= amount;
}
```

---

### 2. Read-Only Reentrancy (Oracle Manipulation)

The contract is not drained directly, but its view functions report incorrect data during a state update, causing loss in third-party systems.

|  | Description |
|-----------|-------------|
| **Victim** | Integrators (Lending Markets relying on this pool as an Oracle) |
| **Trigger** | Callback on share token (Deposit) OR asset token (Withdraw) |
| **Result** | Temporary price devaluation (Oracle manipulation) |
| **Attack** | Wrongful liquidation of healthy positions |

**Example A: Deflated price during Deposit**

*Mechanism: Supply increases before Assets are received.*

```solidity
function deposit(uint256 assets) external {
    // 1) Mint shares (Supply increases immediately)
    // Vulnerability: _mint triggers callback if ERC777/ERC1155, or _safeMint/ERC721 (onERC721Received)
    _mint(msg.sender, assets); 

    // <--- Attacker reenters here. 
    // Supply is High, Assets are Low -> PricePerShare is artificially low.

    // 2) Then pull assets (Assets increase later)
    asset.transferFrom(msg.sender, address(this), assets); 
    totalAssets += assets; 
}

function pricePerShare() external view returns (uint256) {
    return totalAssets * 1e18 / totalSupply; 
}
```

**Example B: Deflated price during Removal (Curve/Balancer type hack)**

*Mechanism: Assets decrease before Supply is burned.*

```solidity
function removeLiquidity(uint256 lpAmount) external {
    uint256 ethAmount = calculateWithdrawal(lpAmount);
    
    // 1. Update internal balance (Assets decrease immediately)
    balances[ETH] -= ethAmount;
    
    // 2. Send ETH (Triggers fallback/attacker logic)
    (bool success, ) = msg.sender.call{value: ethAmount}("");
    require(success);
    
    // <--- Attacker reenters here via fallback.
    // Assets are Low, Supply is High (not burned yet) -> VirtualPrice is artificially low.

    // 3. Burn LP tokens (Supply decreases later)
    _burn(msg.sender, lpAmount);
}
```

**Attack Path (Price Devaluation)**

1. Victim has a healthy loan on a Lending Market, using Pool LP tokens as collateral.
2. Attacker calls `deposit` or `removeLiquidity`.
3. During the callback, the Pool's `pricePerShare` reports a value lower than reality.
4. Attacker calls `liquidate(victim)` on the Lending Market.
5. Lending Market reads the low price, marks Victim as insolvent.
6. Attacker liquidates collateral at a discount.
7. Function completes, price returns to normal.

---

### Comparison of Solutions

| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Regular Reentrancy** <br> *(Fund Draining)* | **CEI Pattern** + `nonReentrant` modifier (Storage/Transient Storage). | **Automatic (MUTATING Phase)** <br> Blocks `ALLOW_USER` (state-changing entry). |
| **Read-Only Reentrancy** <br> *(Oracle Manipulation)* | **Manual Checks**: <br>1. Opt-in `check_reentrancy()` (relies on integrators). <br>2. Internal check in every view (Maintenance burden). | **Automatic (MUTATING Phase)** <br> Blocks `ALLOW_VIEWS` (read-only entry). <br> *Views revert automatically during exploits.* |


## 3. Re-initialization via storage collision (proxy-based)

Admin upgrades a UUPS manually but the new implementation has added a state variable before the already existing variables. As a result, the _initialized flag within the proxy's storage is set to zero. 

|  | Description |
|-----------|-------------|
| **Victim** | Contract |
| **Trigger** | Storage colission |
| **Result** | `_initialized` reset to 0 |
| **Attack** | attacker becomes admin after re-initializing |

**Example**
```solidity
// V1 implementation
contract VaultV1 is Initializable, UUPSUpgradeable {
    // OZ _initialized, _initializing in slot 0 
    address public admin;    // slot 1
    uint256 public feeBps;   // slot 2

    function initialize(address _admin, uint256 _fee) public initializer {
        admin = _admin;
        feeBps = _fee;
    }
}

// V2 implementation (bug: inserts var before inherited storage)
contract VaultV2 is Initializable, UUPSUpgradeable {
    uint256 public newConfig;  // slot 0 (collides with initializer state)
    address public admin;      // slot 1
    uint256 public feeBps;     // slot 2

    function initializeV2(uint256 cfg) public reinitializer(2) {
        newConfig = cfg;
    }
}
```

Attack Path: 
1. Admin upgrades proxy from V1 to V2 manually (no OZ plugin check).
2. newConfig is stored at slot 0, overwriting Initializable’s `_initialized` bit.
3. `_initialized` reverts to 0. Proxy now thinks it was never initialized.
4. Attacker calls initialize(attacker, …) on the proxy.
5. Attacker becomes admin, can drain or upgrade again.

| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Re-initialization via storage colission** | manual OZ upgrade plugin check | **Automatic (READY Phase)** <br> Blocks transition from READY to UNINITIALIZED even after a storage collision|

## 4. Non-proxy re-initialization 

Even contracts deployed without proxies can be exploited when their initializer functions remain callable or state variables have not been set.

|  | Description |
|-----------|-------------|
| **Victim** | Contract |
| **Trigger** | Public initializer callable / Uninitialized state variables |
| **Result** | Attacker becomes owner / State variables default to 0 |
| **Attack** | Attcker takes ownership / Funds stolen using unset state variables |

**Example A: Parity Wallet Library (2017) type hack**

*Mechanism: shared library redeployed after a fix, but nobody re-initialized it*

```solidity
contract WalletLibrary {
    address public owner;
    bool public initialized;

    function initWallet(address _owner) public {
        require(!initialized, "already initialized");
        owner = _owner;
        initialized = true;
    }

    function kill(address payable recipient) external {
        require(msg.sender == owner, "not owner");
        selfdestruct(recipient);
    }
}
```

Attack Path: 
1. Library / contract is re-deployed after a fix but admins forget to initialize it (`initWallet`).
2. Attacker calls `initWallet` and becomes owner.
3. Attacker then calls `kill()` triggering a selfdestruct and removing the code for every wallet pointing to the library. 
4. Funds are frozen forever. 

**Example B: Nomad Bridge (2022) type hack**

*Mechanism: contract redeployed, state variables left uninitialized*
```solidity
contract Replica {
    bytes32 public committedRoot;
    bool public initialized;

    function initialize(bytes32 _root) external {
        require(!initialized, "already initialized");
        committedRoot = _root;
        initialized = true;
    }

    function process(bytes calldata message, bytes32 root) external {
        // expects root to match the proven tree root
        require(root == committedRoot, "invalid root");
        _execute(message); // releases bridged funds
    }
}
```
Attack Path: 
1. Protocol deploys new contract but never calls `initialize()`.
2. `committedRoot` defaults to 0x0.
3. Attacker calls `process` with a 0x0 root and steals funds. 


| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Parity-style: Public initializer callable after redeploy** | Manual runbooks that remind operators to call `init` after deployment; relies entirely on humans | PhaseGuard keeps the contract in `UNINITIALIZED` until the privileged bootstrap script runs the initializer in the same transaction (or authorized sequence): every other entrypoint—including `init` reverts |
| **Nomad-style: Critical state defaults because initializer never runs** | Audits and post-deploy checklists to set state (e.g., Merkle roots) | PhaseGuard blocks every public function while in `UNINITIALIZED`, so operational calls like `process()` cannot execute until the initializer commits non-zero state. If the bootstrap deadline is missed, deployment reverts |

## 5. Pause bypass / incomplete pause coverage

Sensitive functions missing `whenNotPaused` can lead to attackers bypassing the pause mechanism and drain funds. 

|  | Description |
|-----------|-------------|
| **Victim** | Contract |
| **Trigger** | missing `whenNotPaused` modifier |
| **Result** | unguarded function |
| **Attack** | Attacker drains funds through permitted entrypoint |

**Example: Compound Proposal 62 incident (2021)**

*Mechanism: Governance executed Proposal 62 but accidentally wrote huge positive `accruedComp` balances to many users. The pause guardian halted `mint`/`borrow`, yet `claimComp()` lacked the pause modifier, so anyone with a bloated balance could keep calling it to withdraw inflated COMP rewards until Proposal 63 (emergency fix) could pass its timelock.* 

```solidity
contract ComptrollerLike {
    address public pauseGuardian;
    bool public transfersPaused;
    mapping(address => uint256) public accruedComp;

    modifier whenNotPaused() {
        require(!transfersPaused || msg.sender == pauseGuardian, "paused");
        _;
    }

    function setPauseGuardian(address guardian) external {
        // governance only, omitted for brevity
        pauseGuardian = guardian;
    }

    function sweepPause(bool pause) external {
        require(msg.sender == pauseGuardian, "not guardian");
        transfersPaused = pause;
    }

    // Core actions respect the pause flag
    function mint(address market, uint256 amount) external whenNotPaused {
        // ... mint logic ...
    }

    function borrow(address market, uint256 amount) external whenNotPaused {
        // ... borrow logic ...
    }

    // Vulnerable: Proposal 62 accidentally boosted accruedComp,
    // but claimComp() never checked pause state.
    function claimComp(address user) external { // whenNotPaused missing
        uint256 claimable = accruedComp[user];
        require(claimable > 0, "nothing to claim");

        accruedComp[user] = 0;
        _transferComp(user, claimable); // inflated rewards paid out even while paused
    }

    function _transferComp(address to, uint256 amount) internal {
        // send COMP
    }
}
```

Attack path: 
1. Protocol forgets to add `whenNotPaused` to a critical function (`claimComp`).
2. Upgrade bloats state variable `accruedComp`. 
3. Pause Guardian calls `sweepPause` to block user-entry points, but `claimComp` is unguarded.
4. Governance timelock prevents an immediate fix and as a result attackers repeatedly call `claimComp` to drain funds.


| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Proposal 62-style: Pause guardian misses a code path** | Rely on developers to remember every function that needs `whenNotPaused`| PhaseGuard puts the entire contract into `PAUSED` phase with a single state transition: policy bits can be tuned to auto-disable `ALLOW_USER`, `ALLOW_EXTERNAL`, and `ALLOW_VALUE` while enabling `ALLOW_ADMIN` enabled if needed. No per-function modifiers |






