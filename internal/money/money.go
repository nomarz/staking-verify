// Package money is vendored verbatim from the platform's own shared decimal-amount
// type so this module needs no access to a private Go module to build. Keep it in
// sync by hand if the upstream type's public surface changes.
//
// Package money is the platform-wide canonical decimal-amount type and helper
// set. Every wallet-facing amount, balance, payout, bet, rake, stack, blind,
// fee, and any rate/factor that multiplies money must be money.Amount. float64
// is reserved for non-money values (RNG outputs, probabilities, time, geometry)
// and for the explicit, auditable FromFloat/ToFloat bridge points during the
// migration off the legacy float64 wire.
//
// Wire format is EXACT decimal-as-string (see String) — no forced scale — so no
// precision is lost for 18-decimal crypto stored in numeric(36,18) columns.
// Amount deliberately has NO custom MarshalJSON: it is an alias of
// decimal.Decimal, whose marshaller already emits a string and whose
// unmarshaller accepts BOTH JSON numbers and JSON strings. That dual-read is
// what lets a consumer adopt this type before a producer switches to emitting
// strings, which is the safety lever for a staged/lockstep cutover.
package money

import (
	"errors"
	"fmt"

	"github.com/shopspring/decimal"
)

// Amount is the canonical type for all money-typed values. Aliased rather than
// wrapped so decimal.Decimal's methods (Add, Sub, Mul, Div, Cmp, …) are usable
// directly and so its number-or-string JSON unmarshaller is inherited.
type Amount = decimal.Decimal

// Zero is the additive identity. Use instead of an Amount{} literal so call
// sites stay self-documenting (a zero-value Decimal is also valid, but the name
// makes intent explicit).
var Zero = decimal.Zero

// ScaleDB is the scale (decimal places) of the on-disk numeric(36,18) money
// columns. Exported so audit/migration tooling can assert column-type
// consistency; it does not truncate values (the wire format is exact).
const ScaleDB = 18

// Parse converts a wire-format decimal string to Amount. Empty string is
// treated as Zero so older audit rows predating a field can be replayed; any
// actively malformed input (letters, spaces) errors so a typo never silently
// becomes 0.
func Parse(s string) (Amount, error) {
	if s == "" {
		return Zero, nil
	}
	a, err := decimal.NewFromString(s)
	if err != nil {
		return Zero, fmt.Errorf("money.Parse %q: %w", s, err)
	}
	return a, nil
}

// MustParse is the test/config-time sibling of Parse; it panics on malformed
// input. Never use in request-handling code — a bad operator payload must not
// crash the process; use Parse there and handle the error.
func MustParse(s string) Amount {
	a, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return a
}

// FromFloat is the explicit float64 → Amount bridge. Every call site is a
// precision-loss point; grep `money.FromFloat` to audit surviving floats.
func FromFloat(f float64) Amount {
	return decimal.NewFromFloat(f)
}

// ToFloat is the reverse bridge, used by legacy float64 wire adapters during the
// migration. Same audit semantics as FromFloat.
func ToFloat(a Amount) float64 {
	f, _ := a.Float64()
	return f
}

// FromInt is the integer-source constructor (chips, fixed amounts, tests).
func FromInt(n int64) Amount {
	return decimal.NewFromInt(n)
}

// MulFloatMultiplier is the RNG → money pivot: it multiplies a money Amount by a
// float64 multiplier that came from an RNG/probability source. This is the ONLY
// place a money-source decimal should meet an RNG-source float; any other shape
// means a bet was still float64 by the time it reached the multiplication.
func MulFloatMultiplier(bet Amount, multiplier float64) Amount {
	return bet.Mul(decimal.NewFromFloat(multiplier))
}

// Cap returns min(a, max) — the pot rake-cap pattern, kept here so call sites
// don't hand-roll an easy-to-flip `if a.Cmp(max) > 0`.
func Cap(a, max Amount) Amount {
	if a.Cmp(max) > 0 {
		return max
	}
	return a
}

// PercentOf returns a * rate where rate is itself decimal (a rake/fee stored as
// e.g. "0.05"). For float-source rates use MulFloatMultiplier or convert first.
func PercentOf(a, rate Amount) Amount {
	return a.Mul(rate)
}

// Sum reduces a slice of amounts; empty returns Zero. Pot/multi-bet aggregation.
func Sum(amounts ...Amount) Amount {
	total := Zero
	for _, a := range amounts {
		total = total.Add(a)
	}
	return total
}

// Eq is a name-aliased Cmp == 0 (decimal equality is by value, not ==).
func Eq(a, b Amount) bool {
	return a.Cmp(b) == 0
}

// String renders Amount in the canonical on-the-wire format: the EXACT decimal
// value with no forced scale or padding (decimal.Decimal.String). This is the
// platform decimal-string wire format for numeric(36,18) columns; parse it back
// with Parse. Callers that need a fixed number of places (e.g. a display value)
// should use the Amount's StringFixed method directly.
func String(a Amount) string {
	return a.String()
}

// IsPositive reports a > 0 (false for both zero and negative).
func IsPositive(a Amount) bool {
	return a.Sign() > 0
}

// ErrNegativeAmount is returned by ValidateBetAmount for a zero/negative input;
// exported so handlers branch on it rather than string-matching.
var ErrNegativeAmount = errors.New("amount must be positive")

// ValidateBetAmount is the standard precondition for any bet/credit path:
// amount > 0. Currency-specific min/max is operator-config concern, not here.
func ValidateBetAmount(a Amount) error {
	if !IsPositive(a) {
		return ErrNegativeAmount
	}
	return nil
}
