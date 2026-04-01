# Security Issues Report

Date: 2026-04-02
Branch: constant-time
Base commit: 0735081

---

## Overview

| # | ID | Issue | Status | Rating | Fix? | Rationale |
|---|-----|-------|--------|--------|------|-----------|
| 1 | SRC-2026-573 | secp256k1 IsOnCurve missing coordinate range check | **Fixed** `685c2af` | P2-P3 | - | Fixed. Non-canonical coordinates bypass curve check, affects ECIES and point validation |
| 2 | SRC-2026-574 | Incomplete GG20 Session Binding (ssidNonce=0 + ProveRangeAlice sessionless) | **Fixed** `fc38979` | P2-P3 | - | Fixed. Breaks session isolation, allows cross-session ZK proof replay, but no key leakage |
| 3 | SRC-2026-630 | MtA Alice Range Proof missing Session binding | **Fixed** `b59ed36` + `fc38979` | Duplicate of 574 | - | Sub-issue of 574 F-2, same fix covers both |
| 4 | SRC-2026-640 | VSS ReConstruct threshold off-by-one | **Not fixed** (duplicate of PR #324) | No Impact | **No** | `ReConstruct` never called in protocol code, only tests; duplicate of existing PR #324 |
| 5 | SRC-2026-641 | ECPoint.ScalarMult panic on identity point | **Not fixed** | No Impact | **No** | Identity point unreachable on prime-order curves; signature change requires updating 20+ callers, high churn low benefit |
| 6 | SRC-2026-644 | EdDSA Signing Round 3 nil pointer crash | **Fixed** (pending commit) | P3 | **Yes** | Trivial DoS, any malicious EdDSA signer crashes all honest parties; fix is 2-line swap, zero risk |
| 7 | SRC-2026-674 | betaPrm mod q unconstrained in MtA range proof | **No fix needed** | No Impact | **No** | PoC requires Alice's Paillier private key; protocol-level equation system underdetermined, freedom degree remains 1 across sessions |

---

## 1. [SRC-2026-640] VSS ReConstruct Threshold Off-By-One

**Report time:** 2026-03-21
**Reporter claimed severity:** P2
**Assessed severity: No Impact**
**File:** `crypto/vss/feldman_vss.go`, line 117, function `ReConstruct()`

### Description

`ReConstruct` function has an off-by-one error in the threshold check. In a (t, n) Shamir secret sharing scheme, `Threshold` stores `t` (the polynomial degree), and `t+1` shares are needed for reconstruction. The current check `Threshold > len(shares)` allows reconstruction when `len(shares) == Threshold` (i.e., `t` shares), which is one fewer than the required `t+1`.

### Current Code (Buggy)

```go
// crypto/vss/feldman_vss.go, line 117
if shares != nil && shares[0].Threshold > len(shares) {
    return nil, ErrNumSharesBelowThreshold
}
```

### Suggested Fix

```go
if shares != nil && shares[0].Threshold + 1 > len(shares) {
    return nil, ErrNumSharesBelowThreshold
}
```

### Assessment: No Protocol Impact

**`ReConstruct` is never called in any protocol code path.** All callers are test files only:

| Caller | File |
|--------|------|
| Unit test | `crypto/vss/feldman_vss_test.go:106,110,114` |
| Keygen test | `ecdsa/keygen/local_party_test.go:266,284` |
| Keygen test | `eddsa/keygen/local_party_test.go:134,152` |

The actual Lagrange interpolation used in signing is implemented inline in `PrepareForSigning()` (`ecdsa/signing/prepare.go`), which computes Lagrange coefficients directly from party indices — it does not call `ReConstruct`.

The off-by-one is a real correctness bug in the `ReConstruct` utility function, but it does not affect the TSS protocol's key generation, signing, or resharing flows. External users who call `ReConstruct` directly with exactly `t` shares would get an incorrect result silently, but this is a misuse of the API (correct usage requires `t+1` shares).

This is analogous to SRC-2026-674: the underlying observation is correct, but no protocol-level impact exists.

---

## 2. [SRC-2026-641] ECPoint.ScalarMult Unrecoverable Panic on Identity Point Result

**Report time:** 2026-03-21
**Reporter claimed severity:** P2-P3
**Assessed severity: No Impact**
**File:** `crypto/ecpoint.go`, lines 62-69 (`ScalarMult`) and lines 107-114 (`ScalarBaseMult`)

### Description

`ScalarMult` panics (unrecoverable crash) when the scalar multiplication result is the point at infinity (0, 0). The report claims a malicious coalition can craft contributions that cause an honest party's intermediate `ScalarMult` computation to yield the identity point.

### Current Code

```go
// crypto/ecpoint.go, lines 62-69
func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
    x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
    newP, err := NewECPoint(p.curve, x, y)
    if err != nil {
        panic(fmt.Errorf("scalar mult to an ecpoint %s", err.Error()))
    }
    return newP
}
```

### Assessment: Identity Point Unreachable on Prime-Order Curves

On secp256k1 (prime-order curve, used in ECDSA), `k * P = O` (identity) **if and only if** `k ≡ 0 mod N`. All protocol scalars passed to `ScalarMult` are provably non-zero:

| Scalar source | Why non-zero |
|---------------|-------------|
| Random nonces (`k`, `gamma`, `ri`) | `GetRandomPositiveInt` returns [1, N-1] |
| Lagrange coefficients (`iota`) | Non-zero with distinct party indices (`CheckIndexes` rejects duplicates and 0) |
| `thetaInverse` (round 5) | If delta = 0, `ModInverse(0)` returns **nil** (not 0) — crash is nil pointer on `nil.Bytes()`, a different bug class |
| `si = m*k + r*sigma` | Probability of being exactly 0 mod N is 2^{-256}, negligible |
| Constant scalars (`eight`, `eightInv`) | 8 and 8^{-1} mod N are non-zero |
| VSS verify exponents (`t = share.ID^j`) | `share.ID ≠ 0` enforced by `CheckIndexes` |

The `delta = 0` scenario (malicious party sending crafted delta_j to cancel the sum) causes `ModInverse` to return nil, leading to a nil pointer dereference on `nil.Bytes()` **before** `ScalarMult` even executes. This is a nil-argument crash, not the identity-point crash described in SRC-2026-641.

On Edwards curves (EdDSA), `ScalarMult` is called with constant scalars (`eight`, `eightInv`) in `EightInvEight()`, which cannot produce identity for valid curve points.

**Conclusion:** The panic is a code quality issue (libraries should return errors, not panic), but the specific attack scenario described — a malicious party forcing the identity point result — is not achievable in the TSS protocol on prime-order curves. The bug has no practical security impact.

---

## 3. [SRC-2026-644] EdDSA Signing Round 3 Nil Pointer Crash

**Report time:** 2026-03-21
**Reporter claimed severity:** P3
**Assessed severity: P3 (Low Risk)**
**Status: Fixed** (pending commit)
**File:** `eddsa/signing/round_3.go`, lines 55-58

### Description

`EightInvEight()` is called on the result of `NewECPoint()` BEFORE the error check. When coordinates are not on the curve, `NewECPoint` returns `(nil, error)`. The immediate `nil.EightInvEight()` dereferences nil, causing an unrecoverable panic. The tss-lib codebase has zero `defer recover()` calls — panics terminate the process.

### Current Code (Buggy)

```go
// eddsa/signing/round_3.go, lines 55-58
Rj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
Rj = Rj.EightInvEight()  // Rj is nil when NewECPoint fails — PANIC
if err != nil {
    return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
}
```

### Fix

Move the error check before calling `EightInvEight()`:

```go
Rj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
if err != nil {
    return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
}
Rj = Rj.EightInvEight()
```

### Assessment: Real Bug — Trivial DoS

This is a genuine, trivially exploitable vulnerability:

1. **Malicious party** commits to arbitrary off-curve coordinates `(x, y)` in round 1
2. **Round 2**: reveals decommitment — hash matches (malicious party committed to these exact values)
3. **Round 3 line 55**: `NewECPoint` returns `(nil, error)` for off-curve coordinates
4. **Round 3 line 56**: `nil.EightInvEight()` → nil pointer dereference → **unrecoverable process crash**
5. The error check at line 57 never executes — the crash happens first

**Contrast with ECDSA:** In `ecdsa/signing/round_5.go:43-46`, `NewECPoint` error is checked **immediately** before any method call on the point. ECDSA does not have this bug.

**Impact:**
- Any single malicious EdDSA signing participant can crash all honest parties
- No special computation required — just send any coordinates where `y² ≠ x³ + ax + b`
- The crash is unrecoverable (`panic` with no `defer recover()`)
- The crash occurs before fault attribution — the malicious party cannot be identified
- Repeated exploitation permanently prevents EdDSA signing from completing

**Severity rationale (P3):** This is a DoS-only vulnerability — it cannot leak secrets or forge signatures. The attacker must be an authorized signer (inside the TSS committee). However, it is trivially exploitable with zero computational cost and completely blocks the protocol.
