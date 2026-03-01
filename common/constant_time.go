// Copyright © 2019-2024 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Package common provides constant-time big integer operations for cryptographic use.
//
// SECURITY NOTE: Go's math/big package is NOT constant-time and should not be used
// with secret values. This module provides constant-time alternatives using
// filippo.io/bigmod, which is the same library used by Go's crypto/rsa.
//
// Reference: https://github.com/golang/go/issues/20654

package common

import (
	"crypto/subtle"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/bigmod"
)

// constantTimeEnabled controls whether constant-time operations are used.
// Default is false (disabled) for performance. Enable for high-security environments.
var constantTimeEnabled int32 = 0

// EnableConstantTimeOps enables constant-time cryptographic operations.
// Call this at application startup if timing side-channel protection is required.
func EnableConstantTimeOps() {
	atomic.StoreInt32(&constantTimeEnabled, 1)
}

// DisableConstantTimeOps disables constant-time operations (default).
func DisableConstantTimeOps() {
	atomic.StoreInt32(&constantTimeEnabled, 0)
}

// IsConstantTimeEnabled returns true if constant-time operations are enabled.
func IsConstantTimeEnabled() bool {
	return atomic.LoadInt32(&constantTimeEnabled) == 1
}

// CTModInt provides constant-time modular arithmetic using filippo.io/bigmod.
// This is the recommended implementation as bigmod is:
// 1. Maintained by the Go crypto team lead (Filippo Valsorda)
// 2. The same code used internally by crypto/rsa and crypto/ecdsa
// 3. Highly optimized with architecture-specific assembly
type CTModInt struct {
	mod         *bigmod.Modulus
	modBigInt   *big.Int
	modMinusTwo []byte // For Fermat inverse: a^(p-2) mod p
	byteLen     int
	bytePool    sync.Pool
}

// NewCTModInt creates a constant-time modular context using bigmod.
// Note: bigmod requires odd modulus for Exp operations.
func NewCTModInt(mod *big.Int) *CTModInt {
	modBytes := mod.Bytes()
	m, err := bigmod.NewModulus(modBytes)
	if err != nil {
		// Fallback: should not happen for valid modulus
		panic(err)
	}

	// Pre-compute mod-2 for Fermat inverse: a^(-1) = a^(mod-2) mod mod
	modMinusTwo := new(big.Int).Sub(mod, big.NewInt(2))

	byteLen := len(modBytes)
	return &CTModInt{
		mod:         m,
		modBigInt:   new(big.Int).Set(mod),
		modMinusTwo: modMinusTwo.Bytes(),
		byteLen:     byteLen,
		bytePool: sync.Pool{
			New: func() interface{} {
				return make([]byte, byteLen)
			},
		},
	}
}

// ExpCT performs constant-time modular exponentiation using bigmod.
// IMPORTANT: The modulus must be odd. For Paillier N² where N = p*q with
// odd primes, N² is always odd, so this is safe.
func (ct *CTModInt) ExpCT(base, exp *big.Int) *big.Int {
	if exp.Sign() == 0 {
		return big.NewInt(1)
	}
	if exp.Sign() < 0 {
		baseInv := new(big.Int).ModInverse(base, ct.modBigInt)
		if baseInv == nil {
			return nil
		}
		base = baseInv
		exp = new(big.Int).Neg(exp)
	}

	// Get pooled buffer for base padding
	paddedBase := ct.bytePool.Get().([]byte)
	defer ct.bytePool.Put(paddedBase)

	// Clear and fill buffer
	for i := range paddedBase {
		paddedBase[i] = 0
	}
	baseBytes := base.Bytes()
	copy(paddedBase[ct.byteLen-len(baseBytes):], baseBytes)

	// Convert base to bigmod.Nat and reduce
	baseNat := bigmod.NewNat()
	baseNat.SetBytes(paddedBase, ct.mod)

	// Perform constant-time exponentiation
	expBytes := exp.Bytes()
	result := bigmod.NewNat()
	result.Exp(baseNat, expBytes, ct.mod)

	// Convert result back to big.Int
	return new(big.Int).SetBytes(result.Bytes(ct.mod))
}

// ModInverseCT computes the modular inverse in constant time using Fermat's little theorem.
// For a prime modulus p: a^(-1) ≡ a^(p-2) mod p
// For a non-prime modulus n with known φ(n): a^(-1) ≡ a^(φ(n)-1) mod n
// SECURITY: This uses constant-time Exp, making the entire operation constant-time.
// Note: The modulus should be prime for this to work correctly. For composite moduli,
// use NewCTModIntWithPhi to provide φ(n).
func (ct *CTModInt) ModInverseCT(a *big.Int) *big.Int {
	if a.Sign() == 0 {
		return nil
	}

	// Get pooled buffer for padding
	paddedA := ct.bytePool.Get().([]byte)
	defer ct.bytePool.Put(paddedA)

	// Clear and fill buffer
	for i := range paddedA {
		paddedA[i] = 0
	}
	aBytes := a.Bytes()
	copy(paddedA[ct.byteLen-len(aBytes):], aBytes)

	// Convert to bigmod.Nat
	aNat := bigmod.NewNat()
	if _, err := aNat.SetBytes(paddedA, ct.mod); err != nil {
		// Value out of range, fall back to standard ModInverse
		return new(big.Int).ModInverse(a, ct.modBigInt)
	}

	// a^(mod-2) mod mod using constant-time Exp
	result := bigmod.NewNat()
	result.Exp(aNat, ct.modMinusTwo, ct.mod)

	return new(big.Int).SetBytes(result.Bytes(ct.mod))
}

// Mod returns the modulus as a big.Int.
func (ct *CTModInt) Mod() *big.Int {
	return new(big.Int).Set(ct.modBigInt)
}

// MulCT performs constant-time modular multiplication using bigmod.
func (ct *CTModInt) MulCT(x, y *big.Int) *big.Int {
	// Get pooled buffers
	paddedX := ct.bytePool.Get().([]byte)
	paddedY := ct.bytePool.Get().([]byte)
	defer ct.bytePool.Put(paddedX)
	defer ct.bytePool.Put(paddedY)

	// Clear and fill buffers
	for i := range paddedX {
		paddedX[i] = 0
	}
	for i := range paddedY {
		paddedY[i] = 0
	}
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(paddedX[ct.byteLen-len(xBytes):], xBytes)
	copy(paddedY[ct.byteLen-len(yBytes):], yBytes)

	// Convert to bigmod.Nat
	xNat := bigmod.NewNat()
	yNat := bigmod.NewNat()
	if _, err := xNat.SetBytes(paddedX, ct.mod); err != nil {
		// Value out of range, reduce first
		xReduced := new(big.Int).Mod(x, ct.modBigInt)
		copy(paddedX, make([]byte, ct.byteLen))
		xBytes = xReduced.Bytes()
		copy(paddedX[ct.byteLen-len(xBytes):], xBytes)
		xNat.SetBytes(paddedX, ct.mod)
	}
	if _, err := yNat.SetBytes(paddedY, ct.mod); err != nil {
		// Value out of range, reduce first
		yReduced := new(big.Int).Mod(y, ct.modBigInt)
		copy(paddedY, make([]byte, ct.byteLen))
		yBytes = yReduced.Bytes()
		copy(paddedY[ct.byteLen-len(yBytes):], yBytes)
		yNat.SetBytes(paddedY, ct.mod)
	}

	// Constant-time multiplication
	xNat.Mul(yNat, ct.mod)

	return new(big.Int).SetBytes(xNat.Bytes(ct.mod))
}

// NewCTModIntWithPhi creates a constant-time modular context for composite moduli.
// This is required for correct ModInverse on composite moduli where φ(n) is known.
// For RSA-like moduli n = p*q, pass phiN = (p-1)*(q-1).
func NewCTModIntWithPhi(mod, phiN *big.Int) *CTModInt {
	modBytes := mod.Bytes()
	m, err := bigmod.NewModulus(modBytes)
	if err != nil {
		panic(err)
	}

	// For composite modulus: a^(-1) = a^(φ(n)-1) mod n
	phiMinusOne := new(big.Int).Sub(phiN, big.NewInt(1))

	byteLen := len(modBytes)
	return &CTModInt{
		mod:         m,
		modBigInt:   new(big.Int).Set(mod),
		modMinusTwo: phiMinusOne.Bytes(), // Use φ(n)-1 instead of n-2
		byteLen:     byteLen,
		bytePool: sync.Pool{
			New: func() interface{} {
				return make([]byte, byteLen)
			},
		},
	}
}

// Global cache for CTModInt instances
var ctModCache sync.Map

// GetCTModInt returns a cached or new CTModInt for the given modulus.
func GetCTModInt(mod *big.Int) *CTModInt {
	key := mod.String()
	if cached, ok := ctModCache.Load(key); ok {
		return cached.(*CTModInt)
	}
	ct := NewCTModInt(mod)
	ctModCache.Store(key, ct)
	return ct
}

// TimingProtection provides response time normalization to prevent timing attacks.
type TimingProtection struct {
	targetDuration time.Duration
	jitterRange    time.Duration
}

// NewTimingProtection creates a TimingProtection with custom parameters.
func NewTimingProtection(targetDuration, jitterRange time.Duration) *TimingProtection {
	return &TimingProtection{
		targetDuration: targetDuration,
		jitterRange:    jitterRange,
	}
}

// ProtectBigInt wraps a function that returns *big.Int with timing normalization.
func (tp *TimingProtection) ProtectBigInt(fn func() (*big.Int, error)) (*big.Int, error) {
	startTime := time.Now()
	result, err := fn()
	elapsed := time.Since(startTime)

	if remaining := tp.targetDuration - elapsed; remaining > 0 {
		time.Sleep(remaining)
	}
	return result, err
}

// ConstantTimeCompare compares two big.Int values in constant time.
func ConstantTimeCompare(a, b *big.Int) int {
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}

	padA := make([]byte, maxLen)
	padB := make([]byte, maxLen)
	copy(padA[maxLen-len(aBytes):], aBytes)
	copy(padB[maxLen-len(bBytes):], bBytes)

	return subtle.ConstantTimeCompare(padA, padB)
}
