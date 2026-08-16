#pragma once

#include "boolean_ir.hpp"

#include <array>

namespace v0id::integrity {

using KeccakStateWires = std::array<BoolWire, 1600>;

// Appends Keccak-f[1600] to an existing BooleanIR. The state is flattened as
// lane (x + 5*y), then little-endian bit z within the 64-bit lane. Rho and pi
// remain pure wire relabeling; only theta/chi/iota append Boolean gates.
KeccakStateWires append_keccak_f1600(BooleanIR& ir,
                                     const KeccakStateWires& input_state);

} // namespace v0id::integrity
