
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

| Attribute | Description |
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

| Attribute | Description |
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

**Example B: Deflated price during Removal (Curve/Balancer style)**

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

**Unified Attack Path (Price Devaluation)**

1.  **Setup**: Victim has a healthy loan on a Lending Market, using Pool LP tokens as collateral.
2.  **Trigger**: Attacker calls `deposit` or `removeLiquidity`.
3.  **State Mismatch**: During the callback, the Pool's `pricePerShare` reports a value lower than reality.
4.  **Exploit**: Attacker calls `liquidate(victim)` on the Lending Market.
5.  **Validation**: Lending Market reads the low price, marks Victim as insolvent.
6.  **Profit**: Attacker liquidates collateral at a discount.
7.  **Settlement**: Function completes, price returns to normal.

---

### Comparison of Solutions

| Security Challenge | Current Standard Solutions | PhaseGuard Solution |
| :--- | :--- | :--- |
| **Regular Reentrancy** <br> *(Fund Draining)* | **CEI Pattern** + `nonReentrant` modifier (Storage/Transient Storage). | **Automatic (MUTATING Phase)** <br> Blocks `ALLOW_USER` (state-changing entry). |
| **Read-Only Reentrancy** <br> *(Oracle Manipulation)* | **Manual Checks**: <br>1. Opt-in `check_reentrancy()` (relies on integrators). <br>2. Internal check in every view (Maintenance burden). | **Automatic (MUTATING Phase)** <br> Blocks `ALLOW_VIEWS` (read-only entry). <br> *Views revert automatically during exploits.* |


## 3. Re-initialization

| Attribute | Description |
|-----------|-------------|
| **Victim** |  |
| **Trigger** |  |
| **Result** |  |
| **Attack** |  |



## 4. Double-finalization




## Guard To Exploit Matrix

| Exploit Type | Root Cause | Victim | PhaseGuard Defense |
|--------------|------------|--------|-------------------|
| **State-Modifying Reentrancy** | CEI Violation (Writes after Call) | The Contract Itself | **Phase.Mutating**: Implementation enters `MUTATING` phase which disables `ALLOW_USER` / `ALLOW_EXTERNAL`. Re-entering `withdraw()` fails because the contract is not in `READY` phase. |
| **Read-Only Reentrancy** | CEI Violation (Writes after Call) | Third-party Integrators (Lending Markets) | **View Locks**: During `MUTATING` phase, `ALLOW_VIEWS` is disabled. Any call to `pricePerShare()` or `getVirtualPrice()` reverts, preventing the third party from reading stale data. |
| **Cross-Function Reentrancy** | Shared State inconsistencies | The Contract Itself | **Phase.Mutating**: Global lock prevents entering *any* public function that modifies state. |
| **Delegatecall Injection** | Unsafe delegatecall | The Contract Itself | **Bit Flags**: `ALLOW_DELEGATECALL` is explicit. Default policy is `0` (Disabled). |

