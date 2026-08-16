# Polymorphic Spectrum Solver

> Experimental/future architecture. This document describes a research direction; it is not a claim that quantum-resistant forensic indistinguishability or general symbolic solvability has been established.

## Objective

Given a canonical V0ID machine `T`, construct an explicit family of alternative machine representations that remain semantically equivalent under a declared interface while differing in representation, layout, and polymorphic structure.

The central object is an equivalence family:

```text
P(T) = { T' | T' satisfies the declared equivalence constraints for T }
```

The solver should be able to request either:

- one valid representative;
- `n` distinct representatives;
- an estimate/bounded count of representatives;
- representatives satisfying additional layout/input/output constraints.

## Constraint model

The first implementation should use bounded, explicit constraints rather than attempting an unrestricted symbolic solution to arbitrary Turing machines.

Possible constraints:

```text
same semantic function
same declared input width
same declared output width
same canonical integrity statement
input position = i
output position = j
selected input positions masked/abstracted
selected output positions masked/abstracted
maximum state count
maximum tape cells
maximum execution rounds
allowed transition templates
```

The solver should distinguish:

```text
SAT         a valid representative was found
UNSAT       no representative exists in the declared bounded model
UNKNOWN     timeout/resource bound/unsupported symbolic feature
```

`UNKNOWN` must never be interpreted as proof that the spectrum is empty.

## Symbolic Turing-machine representation

Represent a bounded machine symbolically as a finite set of variables:

```text
state transition variables
write-symbol variables
head-movement variables
input/output cell selectors
state-layout/permutation variables
optional neutral/camouflage gadget variables
```

A candidate representation is accepted only when the constraint solver proves the required semantics for the declared bounded domain.

The future solver may use:

```text
BooleanIR
SAT/SMT
bounded bit-vector reasoning
symbolic transition systems
bounded model checking
```

The existing `BooleanIR` and Boolean-program lowering should remain the concrete
replay/reference layer. Solver-generated candidates must always be replayable by
an ordinary reference interpreter.

## Input/output masking experiment

A useful experiment is to solve with part of the machine interface intentionally
abstracted.

For example:

```text
known input positions:   {0, 1, 2}
unknown/masked inputs:   {3, 4, 5}
known output positions:  {20, 21}
unknown/masked outputs:  {22, 23}
```

The solver then asks:

```text
Which machine representations remain compatible with the
known interface constraints?
```

This can generate a spectrum rather than a single polymorph.

The important rule is that masking is a constraint on the *symbolic model* and
must not mutate the real input tape used by the eventual computation.

## Polymorphic spectrum

For a bounded constraint set `C`, define:

```text
P_C(T) = { T' | T' satisfies C and T' ~ T }
```

where `~` is the explicitly declared semantic equivalence relation.

Possible quantities:

```text
|P_C(T)|                       exact bounded spectrum size
N_found                       number of representatives found
shape_distance(T, T')         representation diversity
trace_distance(T, T')         execution/trace diversity
layout_distance(T, T')        state/tape layout diversity
linkability_score(T, T')      empirical origin-linking score
```

Exact cardinality may be infeasible. In that case report bounded counts or lower
bounds rather than pretending to know the complete spectrum.

## Relationship to hash/integrity

The canonical integrity statement must be specified separately from the literal
serialized representation.

This distinction is essential:

```text
same representation hash
!=
same semantic machine
```

A future canonical semantic commitment may bind the declared semantic statement,
while a polymorphic instance commitment binds the actual transformed graph. Both
must be explicit.

The existing graph-level hash camouflage experiment is one possible morphology
family. It preserves the input tape and inserts traceable neutral dependencies
before cloning the Boolean hash graph. The spectrum solver can later treat that
family as one generator among many instead of defining polymorphism solely in
terms of neutral-edge gadgets.

## Forensic analysis model

The useful research question is not simply:

> “Can a quantum computer analyze this?”

Instead define an explicit observation model and distinguisher.

For a representation `T'`, define an observation function:

```text
O(T') = all information the attacker is legitimately allowed to observe
```

Possible observations include:

- graph/topology metadata;
- serialized dimensions;
- state/tape counts;
- ciphertext counts and sizes;
- public profile identifiers;
- public round/timing structure;
- protocol metadata;
- any intentionally disclosed commitment fields.

Then define a distinguisher:

```text
D(O(T_i), O(T_j))
```

and measure whether it can identify:

- the canonical/base machine family;
- whether two jobs came from the same base machine;
- semantic job family;
- real versus dummy state roles;
- particular polymorphism generators.

## Classical and quantum analysis tiers

Use separate attacker models:

```text
Classical structural analysis
Classical statistical analysis
SAT/SMT bounded analysis
Symbolic machine synthesis
Quantum distinguisher model (future/theoretical)
```

A quantum tier must be specified as an actual algorithm/oracle/query model. It
should never be implemented as a vague “quantum forensic analyzer”.

The project should report:

```text
UNKNOWN
```

when no justified analysis is available. In particular, the absence of a known
quantum attack must not be reported as proof of quantum resistance.

## Solver output format

A future solver API could request:

```json
{
  "base_machine": "<canonical statement>",
  "constraints": {
    "max_states": 128,
    "max_rounds": 4096,
    "input_positions": [3, 7, 11],
    "output_positions": [42, 91]
  },
  "request": {
    "representatives": 100,
    "require_distinct_graphs": true
  }
}
```

The result should contain:

```text
status
representatives_found
bounded_spectrum_lower_bound
candidate machine images
canonical semantic statement
instance commitments
replay/verification receipts
analysis metadata
```

Every returned candidate must be concrete enough to replay through the existing
reference execution path.

## Development order

```text
1. tiny Boolean/TM symbolic examples
        |
2. bounded equivalence constraints
        |
3. generate one alternative representation
        |
4. generate N distinct representations
        |
5. measure structural diversity
        |
6. connect to existing polymorphism generators
        |
7. add classical linkability benchmark
        |
8. only then investigate quantum distinguisher models
```

The first milestone should be a tiny machine where exhaustive enumeration proves
that the generated representatives all compute the same function and where the
entire bounded spectrum can be counted exactly.
