# Gas Benchmarks

Gas measurements for the reference implementation, compared against OpenZeppelin `ReentrancyGuard` and an unguarded baseline.

All numbers from `forge test --mc GasBenchmark` with Solidity 0.8.30, default optimizer settings.

## Methodology

Three vault contracts with identical logic (deposit, withdraw, view) are tested:

- **Bare**: no guard at all
- **OZ**: OpenZeppelin `ReentrancyGuard` (`nonReentrant`)
- **PhaseGuard**: full lifecycle guard (`withMutating`, `withView`)

Each test function measures the full transaction gas. The guard overhead is the difference from the bare baseline.

## Results

### State-changing operations

| Operation      | Bare   | OZ `nonReentrant` | PhaseGuard `withMutating` |
|----------------|--------|---------------------|----------------------------|
| deposit (cold) | 39,615 | 42,289              | 56,106                     |
| deposit (warm) | 47,776 | 51,144              | 74,849                     |
| withdraw       | 34,871 | 42,117              | 69,969                     |

### Guard overhead (gas above bare baseline)

| Operation      | OZ overhead | PhaseGuard overhead | Δ (PG − OZ)  |
|----------------|-------------|---------------------|---------------|
| deposit (cold) | +2,674      | +16,491             | +13,817       |
| deposit (warm) | +3,368      | +27,073             | +23,705       |
| withdraw       | +7,246      | +35,098             | +27,852       |

### View operations

| Operation      | Bare   | OZ (unguarded) | PhaseGuard `withView` |
|----------------|--------|----------------|-----------------------|
| view           | 41,466 | 44,185         | 58,703                |

OZ `ReentrancyGuard` does not include view protection — it is designed to guard state-changing functions. The OZ column here reflects only the baseline contract-size difference; no guard logic runs on the view call.

### Pure introspection

| Function               | Gas   |
|------------------------|-------|
| `phase()`              | 8,022 |
| `getPolicy(uint8)`     | 6,592 |
| `isTransitionAllowed()` | 7,276 |
| `isStable(uint8)`      | 6,552 |
| `supportsInterface()`  | 6,404 |

### Admin transitions

| Transition         | Gas    |
|--------------------|--------|
| READY → PAUSED     | 26,714 |
| READY → MAINTENANCE | 26,879 |
| READY → FINALIZED  | 26,522 |

## Why the overhead exists

`ReentrancyGuard` is a single-purpose lock: it flips one storage slot per call and checks it on entry. PhaseGuard does more work because it covers more. On every guarded state-changing call:

1. **Pre-invariant check**: 3 storage reads, 3 comparisons (`_phase` stability, stack length, stack consistency)
2. **Policy evaluation**: `getPolicy()` branch + `ALLOW_USER` / `ALLOW_ADMIN` check
3. **Phase entry**: `isTransitionAllowed()` + `SSTORE` to `_phase` + `_phaseStack.push()` + `emit PhaseTransition`
4. **Phase exit**: stack read + `pop()` + `SSTORE` to `_phase` + `emit PhaseTransition`
5. **Post-invariant check**: same 3 reads + 3 comparisons as step 1

The two `PhaseTransition` events alone account for ~3,000 gas (two `LOG3` operations). The dynamic array push/pop and double invariant check account for most of the rest.

## Scope comparison

`ReentrancyGuard` and PhaseGuard solve different problems at different scope levels. A direct gas comparison is not apples-to-apples.

`ReentrancyGuard` prevents mutating re-entry, efficiently and with minimal overhead. PhaseGuard covers a broader set of concerns — pause semantics, view protection, and phase-level introspection — none of which `ReentrancyGuard` addresses.

The closest per-function equivalent would be stacking `nonReentrant` and `whenNotPaused` on every entry point:

| Mechanism             | Approx. gas | Coverage                                  |
|-----------------------|-------------|-------------------------------------------|
| `nonReentrant`        | ~2,700      | Mutating re-entry only                    |
| `whenNotPaused`       | ~2,100      | Pause check (per-function opt-in)         |
| View protection        | —           | Not available as a standalone modifier    |
| **Combined**          | **~4,800**  | Per-function, no view coverage            |

PhaseGuard at ~16–35k overhead covers the full lifecycle including views, applied uniformly through a single mechanism. The extra cost comes from invariant checks, event emissions, and stack management.

## Reproducing

```bash
forge test --mc GasBenchmark -v
forge snapshot --mc GasBenchmark --snap .gas-benchmark
```
