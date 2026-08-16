# Baseline policy-gate abstraction for the comparative evaluation.
#
# This is the SAME schema-gate semantics the evaluation always modeled for
# "OPA/Kyverno-style admission check" — but executed by the real OPA engine
# (opa eval) instead of a Python re-implementation. It validates unsigned
# evidence JSON: pass-rate and drift schema fields, nothing cryptographic.
# An unsigned validator cannot see signature, Merkle, nonce, or key-trust
# problems — which is exactly the point the comparison makes.
package eviassure.baseline

allow if {
    input.test_pass_pct >= 100.0
    input.unresolved_drift == 0
}
