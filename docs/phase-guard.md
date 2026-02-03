
# PhaseGuard

PhaseGuard is a lifecycle layer that routes every call through a shared phase machine, so initialization, mutation, externalization, and finalization follow one enforced order. Policies on each phase encode today’s best practices (init process, CEI, pause/upgrade invariants, and other phase-specific policies) in one guard, replacing scattered modifiers and making lifecycle mistakes structurally impossible.

## Architecture

### Phase Descriptions

| ID | Phase          | Type      | Summary                                                                                  |
|----|----------------|-----------|------------------------------------------------------------------------------------------|
| 0  | Uninitialized  | Unstable  | Not initialized (initializer/init step pending): must be initialized in the same tx as deployment. |
| 1  | Ready          | Stable    | Initialized, stable: user/admin entrypoints and reads allowed.                           |
| 2  | Mutating       | Unstable  | Write phase: storage updates allowed, outbound calls/value blocked.                      |
| 3  | Callbacking    | Unstable  | Transient hook window: inbound callbacks allowed, writes/external calls disabled.        |
| 4  | Externalizing  | Unstable  | Outbound-call phase: external calls/value allowed per policy, storage writes blocked.    |
| 5  | Finalized      | Stable    | Terminal locked state: no transitions, writes, or calls.                                 |
| 6  | Paused         | Stable    | Temporary locked state: normal entrypoints blocked until admin moves to Ready/Finalized; reads per policy. |
| 7  | Maintenance    | Stable    | Admin-only maintenance/upgrade window: user entrypoints stay blocked while delegatecall/external automation runs under stricter policy bits. |

## Phase Transition Matrix

Allowed transitions:

| From / To        | UNINITIALIZED | READY | MUTATING | CALLBACKING | EXTERNALIZING | FINALIZED | PAUSED | MAINTENANCE |
|------------------|---------------|-------|----------|-------------|---------------|-----------|--------|-------------|
| UNINITIALIZED    |      -        |  YES  |   NO     |     NO      |     NO        |   NO      |  NO    |     NO      |
| READY            |     NO        |   -   |   YES    |     NO      |     NO        |   YES     |  YES   |     YES     |
| MUTATING         |     NO        |  YES⌃ |    -     |     NO      |     YES       |   NO      |  NO    |     YES⌃    |
| CALLBACKING      |     NO        |  NO   |   NO     |      -      |     YES⌃      |   NO      |  NO    |     NO      |
| EXTERNALIZING    |     NO        |  NO   |   YES⌃   |     YES     |      -        |   NO      |  NO    |     NO      |
| FINALIZED        |     NO        |  NO   |   NO     |     NO      |     NO        |   -       |  NO    |     NO      |
| PAUSED           |     NO        |  YES  |   NO     |     NO      |     NO        |   YES     |  -     |     YES     |
| MAINTENANCE      |     NO        |  YES  |   YES    |     NO      |     NO        |   NO      |  NO    |      -      |

⌃Allowed only during unwinding back to the stable phase

**Stable phases:**
- READY, FINALIZED, PAUSED, MAINTENANCE: contract **must** return to either of those after functions finish executing.

**Unstable phases:**
- UNINITIALIZED: contract is not allowed to remain uninitialized (atomic initialization). It **must** transition from UNINITIALIZED -> READY in the same tx originating from the deployer. If the transition to READY is not complete, the proxy becomes **bricked** as noone else is allowed to initialiaze it afterwards.
- MUTATING, CALLBACKING, EXTERNALIZING: contract is allowed to be in unstable phases mid-function but **must** return to a stable phase when the call ends.
- contract **must** return to the most recent stable phase captured on entry (eg., READY -> MUTATING -> CALLBACKING -> MUTATING -> READY).

**Note on `READY` -> `EXTERNALIZING`** 
- This transition is strictly forbidden to enforce safety. All functions performing external calls must first enter `MUTATING` to lock user entry (`ALLOW_USER = 0`), creating a mandatory mutex before any interaction occurs.

**Note on `CALLBACKING`** 
- This phase is only accessible from `EXTERNALIZING`. You cannot enter `CALLBACKING` directly from `MUTATING` because a callback implies a preceding external call.


## Configuration 

### Bit Flags

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


## Default Policy Matrix 

The values below are just defaults - they can be adjusted on a usecase basis.

| Bit Flag / Phase | UNINITIALIZED | READY | MUTATING | CALLBACKING | EXTERNALIZING | FINALIZED | PAUSED | MAINTENANCE |
|------------------|---------------|-------|----------|-------------|---------------|-----------|--------|-------------|
| ALLOW_USER       |      NO       |  YES  |   NO     |    NO       |    NO         |   NO      |  NO    |     NO      |
| ALLOW_ADMIN      |      NO       |  YES  |   NO     |    NO       |    NO         |   NO      |  YES   |     YES     |
| ALLOW_EXTERNAL   |      NO       |  NO   |   NO     |    NO       |    YES        |   NO      |  NO    |     YES     |
| ALLOW_VALUE      |      NO       |  NO   |   NO     |    NO       |    YES        |   NO      |  NO    |     YES     |
| ALLOW_WRITES     |      NO       |  NO   |   YES    |    NO       |    NO         |   NO      |  NO    |     YES     |
| ALLOW_VIEWS      |      NO       |  YES  |   NO     |    NO       |    NO         |   YES     |  YES   |     YES     |
| ALLOW_CALLBACKS  |      NO       |       |   NO     |    YES      |    NO         |   NO      |  NO    |     YES     |
| ALLOW_DELEGATECALL|    NO        |  NO   |   NO     |    NO       |    NO         |   NO      |  NO    |     YES     |

> Maintenance is the only phase that simultaneously enables `ALLOW_WRITES`, `ALLOW_EXTERNAL`, and `ALLOW_DELEGATECALL` while keeping `ALLOW_USER` off. Transitions are limited to operator-controlled states (READY, PAUSED, or MUTATING) so a runbook can finish a write cycle, hop into Maintenance, run privileged automation, then return to READY or drop into EXTERNALIZING for outbound calls without exposing that power to end users.

> The initializer runs with an authorized bootstrap call : deploy -> UNINITIALIZED (all bits off) -> init via bootstrap -> tranistions contract into READY.

## Solved Vulnerabilities (Exploits)

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
| **Nomad-style: Critical state defaults because initializer never runs** | Audits and post-deploy checklists to set state (e.g., Merkle roots) | PhaseGuard blocks every public function while in `UNINITIALIZED`. If the atomic bootstrap sequence is not completed in the deployment transaction, the contract becomes **bricked** (permanently locked in `UNINITIALIZED` with no valid entrypoints), preventing the usage of a contract with zeroed state. |

## 5. Pause bypass / incomplete pause coverage

Sensitive functions missing `whenNotPaused` can lead to attackers bypassing the pause mechanism and drain funds. 

|  | Description |
|-----------|-------------|
| **Victim** | The contract itself |
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
| **Pause guardian misses a code path** | Rely on developers to remember every function that needs `whenNotPaused`| PhaseGuard puts the entire contract into `PAUSED` phase with a single state transition: policy bits can be tuned to auto-disable `ALLOW_USER`, `ALLOW_EXTERNAL`, and `ALLOW_VALUE` while enabling `ALLOW_ADMIN` if needed. No per-function modifiers |

## 6 Delegatecall injection paths

Using delegatecall can lead to bad actors injecting malicious calldata to drain funds.

|  | Description |
|-----------|-------------|
| **Victim** | The contract itself |
| **Trigger** | `delegatecall` |
| **Result** | malicious calldata injection |
| **Attack** | Attacker runs malicious code on contract's context |

**Example A: SushiSwap Dutch Auction (2021) type hack**

*Mechanism: delegatecall overrides storage in the contract's context*
```solidity
// Simplified MISO-style launcher
contract AuctionLauncher {
    address public treasury;
    mapping(bytes32 => bool) public templates; // supposed to whitelist auction logic

    function registerTemplate(bytes32 templateId, address impl) external /* governance */ {
        templates[templateId] = true;
        templateImpl[templateId] = impl;
    }

    function launch(bytes32 templateId, bytes calldata initData) external payable {
        require(templates[templateId], "template not approved");
        treasury = msg.sender; // project expects its own wallet set here

        // Vulnerability: user controls initData and can point templateId to a malicious impl
        // The delegatecall executes inside AuctionLauncher’s storage context.
        (bool ok, ) = templateImpl[templateId].delegatecall(
            abi.encodeWithSignature("initAuction(bytes)", initData)
        );
        require(ok, "init failed");
    }

    function withdrawProceeds() external {
        require(msg.sender == treasury, "not treasury");
        (bool ok, ) = treasury.call{value: address(this).balance}("");
        require(ok, "send failed");
    }
}

// Attacker-supplied "template" that overwrites treasury.
contract EvilTemplate {
    address public treasury; // storage slot aligns with AuctionLauncher.treasury

    function initAuction(bytes calldata) external {
        treasury = msg.sender; // when delegatecalled, overwrites launcher.treasury
    }
}
```
Attack path: 
1. Attacker socially engineered the MISO team to register their “whitelisted” template address.
2. During launch(), the factory executed delegatecall into the template’s initAuction.
3. The malicious template rewrote treasury to the attacker’s address inside the factory contract.
4. After the auction raised funds, the attacker called withdrawProceeds() and drained the entire sale (approx $3M USDC/ETH).

**Example B: Furucombo cached handler (2021) type hack**

*Mechanism: cached malicious handler hijacks user approvals to siphon funds*
```solidity
contract ComboProxy {
    struct Cube { address handler; bytes data; }

    mapping(bytes32 => Cube[]) public cachedCombos;

    function cacheCombo(bytes32 id, Cube[] calldata cubes) external /* admin */ {
        cachedCombos[id] = cubes; // stored recipe executes later
    }

    function executeCached(bytes32 id) external payable {
        Cube[] storage cubes = cachedCombos[id];
        for (uint256 i; i < cubes.length; i++) {
            // Vulnerability: handler target can be swapped to attacker-controlled logic.
            (bool ok, ) = cubes[i].handler.delegatecall(cubes[i].data);
            require(ok, "cube failed");
        }
    }
}

// Attacker registers a handler that reuses user approvals inside the proxy’s storage.
contract EvilHandler {
    IERC20 public token;

    function init(address _token) external {
        token = IERC20(_token);
    }

    function rug(address victim) external {
        // executes as ComboProxy (which already has victim approvals)
        token.transferFrom(victim, msg.sender, token.balanceOf(victim));
    }
}
```

Attack path:
1. Attacker deploys `EvilHandler` disguised as a legitimate protocol adapter. The malicious code is hidden within a helper import.
2. Victims previously granted ComboProxy unlimited ERC20 approvals for legitimate strategies.
3. When any victim executes the cached combo, the proxy delegatecalls `EvilHandler.rug`, which runs in the proxy’s context and uses the stored approvals/state.
4. `transferFrom` pulls the victim’s entire balance to the attacker before the combo reverts or completes.
5. Because the malicious handler stayed cached, every subsequent user who clicked “execute cached combo” was drained without additional interaction.

| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Delegatecall injection path** | Manual governance allow-lists, handler reviews, and emergency kill switches | user-facing phases (READY, EXTERNALIZING) never permit delegatecall: any attempt from a public entrypoint reverts because `ALLOW_DELEGATECALL` stays at 0. Teams need to enter `MAINTENANCE` (where `ALLOW_DELEGATECALL` is enabled while `ALLOW_USER` is disabled) execute a maintenance script or migration, then transition back to READY. |


## 7 Callback exploit within a delegatecalled proxy context 

Hook reentrancy that directly mutates vault balances as implementation runs in the proxy’s storage context.

|  | Description |
|-----------|-------------|
| **Victim** | The contract itself |
| **Trigger** | `delegatecall` & ERC777 token callback |
| **Result** |  hook code runs in the contract's context|
| **Attack** | Attacker can directly manipulate state |

**Example A: Lendf.Me imBTC (2020) type hack**

```solidity
contract LendfMeiBTC is IERC777Recipient {
    IERC777 public immutable imBTC;
    address public immutable underlying;
    mapping(address => uint256) public accountTokens;
    uint256 public totalSupply;

    function mint(uint256 mintAmount) external returns (uint256) {
        (uint256 err, ) = mintInternal(msg.sender, mintAmount);
        require(err == 0, "mint failed");
        return err;
    }

    function mintInternal(address minter, uint256 mintAmount) internal returns (uint256, uint256) {
        accrueInterest();

        uint256 exchangeRate = exchangeRateStoredInternal();
        uint256 actualMintAmount = doTransferIn(minter, mintAmount);
        // ^ imBTC.transferFrom() triggers tokensReceived before balances are updated

        uint256 mintTokens = (actualMintAmount * 1e18) / exchangeRate;
        totalSupply += mintTokens;
        accountTokens[minter] += mintTokens;
        return (0, mintTokens);
    }

    function doTransferIn(address from, uint256 amount) internal returns (uint256) {
        IERC20 token = IERC20(underlying);
        uint256 balanceBefore = token.balanceOf(address(this));
        require(token.transferFrom(from, address(this), amount), "transfer failed");
        uint256 balanceAfter = token.balanceOf(address(this));
        return balanceAfter - balanceBefore;
    }

    // Lendf.Me registered itself in ERC1820, so imBTC invokes this hook mid-mint.
    function tokensReceived(
        address /*operator*/,
        address from,
        address /*to*/,
        uint256 /*amount*/,
        bytes calldata,
        bytes calldata
    ) external override {
        // ERC777 calls this hook after tokens move but before mintInternal updates supply.
        // Whatever share balance `from` had BEFORE this deposit is redeemed at the temporarily inflated price.
        redeemFresh(from, accountTokens[from], 0);
    }

    function redeemFresh(address redeemer, uint256 redeemTokens, uint256 redeemAmountIn) internal {
        uint256 exchangeRate = exchangeRateStoredInternal();
        uint256 redeemAmount = redeemAmountIn == 0
            ? (redeemTokens * exchangeRate) / 1e18
            : redeemAmountIn;

        totalSupply -= redeemTokens;
        accountTokens[redeemer] -= redeemTokens;
        doTransferOut(redeemer, redeemAmount);
    }
}
```

Attack path:
1. The attacker preloads a large amount of iBTC shares (borrowed elsewhere) and keeps them in the proxy, which assumes depositors arrive with zero balance.
2. They submit a tiny new deposit; `imBTC.transferFrom` transfers assets before `totalSupply` moves, so the exchange rate temporarily inflates by `deltaAssets / oldSupply`.
3. The ERC777 `tokensReceived` hook reenters `redeemFresh` and cashes out the *entire* preloaded share balance at that inflated price, returning far more imBTC than the attacker just supplied.
4. Once the hook exits, `mintInternal` finishes, re-crediting fresh shares at the old rate. The attacker reloads the stash and repeats, draining almost the whole ~$25M pool and making a profit. 

| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Callback exploit in delegatecalled proxy** | Ban ERC777-style tokens, add `nonReentrant` modifiers, or use custom lock flags inside each hook | The guard blocks writes while externalizing, only enables callbacks inside a Callbacking phase with ALLOW_WRITES and ALLOW_EXTERNAL disabled, and forces execution to return back to the stable phase recorded on entry, so hooks can’t mutate stale state or loop outbound calls|

## 8. Cross-Function State Bleeding (Per-ID)

A logic inconsistency between two different functions that operate on the same ID. While technically a reentrancy bug, it is distinct because it exploits the gap between two *different* entrypoints rather than re-entering the caller.

|  | Description |
|-----------|-------------|
| **Victim** | NFT Staking / Position Managers |
| **Trigger** | `safeTransfer` callback during exit |
| **Result** | Rewards claimed on already-withdrawn assets |
| **Attack** | `unstake(id)` triggers hook -> `harvest(id)` reads stale state |

**Example: NFT Staking "Cleanup" vulnerability**

*Mechanism: The protocol follows a "Check -> Interact -> Cleanup" flow. The cleanup (deletion of stake data) happens last, allowing a cross-function re-entry.*

```solidity
contract NftStaker {
    struct Stake { 
        uint256 timestamp; 
        address owner; 
    }
    mapping(uint256 => Stake) public stakes;
    IERC721 public nft;
    IERC20 public rewardToken;

    // Function A: Exit the system
    function unstake(uint256 tokenId) external {
        require(stakes[tokenId].owner == msg.sender, "not owner");

        // 1. Interaction: Return the NFT
        // Vulnerability: safeTransferFrom triggers onERC721Received on recipient
        nft.safeTransferFrom(address(this), msg.sender, tokenId);

        // 2. Effect: Cleanup storage
        // Developer places this last to zero out the struct (gas refund pattern)
        delete stakes[tokenId];
    }

    // Function B: Claim rewards (Publicly callable)
    function harvest(uint256 tokenId) external {
        Stake memory s = stakes[tokenId];
        
        // Vulnerability logic:
        // If called mid-unstake, 's.owner' is still set because 'delete' hasn't run.
        require(s.owner == msg.sender, "not owner");
        
        uint256 rewards = (block.timestamp - s.timestamp) * 1e18; 
        
        // Updates timestamp to now (benign, since struct is about to be deleted)
        stakes[tokenId].timestamp = block.timestamp; 
        
        // Transfers rewards for an NFT the user effectively just withdrew
        rewardToken.transfer(s.owner, rewards);
    }
}

// Attacker Contract
contract CrossFunctionExploiter is IERC721Receiver {
    NftStaker public staker;
    uint256 public activeId;

    function attack(uint256 tokenId) external {
        activeId = tokenId;
        // Start the exit process
        staker.unstake(tokenId);
    }

    function onERC721Received(address, address, uint256, bytes calldata) external override returns (bytes4) {
        // Callback fires mid-unstake.
        // The NFT is already in our wallet (step 1 complete).
        // But 'stakes[tokenId]' hasn't been deleted yet (step 2 pending).
        
        // We call harvest() to claim rewards on the NFT we just withdrew.
        staker.harvest(activeId);
        
        return this.onERC721Received.selector;
    }
}
```

**Attack Path:**
1. Attacker calls `unstake(ID)`.
2. Contract sends NFT to Attacker (`safeTransferFrom`).
3. Attacker's receiver hook fires and calls `harvest(ID)`.
4. `harvest` checks storage: `stakes[ID]` still exists because `unstake` hasn't reached the `delete` line yet.
5. `harvest` pays out rewards.
6. `harvest` finishes.
7. `unstake` resumes and finally executes `delete stakes[ID]`.
8. **Result:** Attacker leaves with both the NFT and the rewards, exploiting the stale state window.

| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Cross-Function Interaction** | `nonReentrant` modifiers on ALL public functions interacting with state (easy to miss helper functions) or strict adherence to CEI (Move `delete` before `transfer`). | **Automatic Lifecycle Stack** <br> The logic inside PhaseGuard treats the contract lifecycle as a stack. <br> **Flow:** `READY` → `MUTATING` (Lock) → `EXTERNALIZING` (Transfer) → `MUTATING` (Cleanup) → `READY`. <br> Even though the transfer happens before the deletion, the contract returns is in `EXTERNALIZING` during the external call: `ALLOW_USER` remains disabled protecting the specific state gap. |
