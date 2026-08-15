# V0ID execution-soundness audit: continuation notes

Session summary for whoever picks this up next (human or delegate agent).
Written because the session that did this work ran out of budget before the
slow end-to-end FHE run could be watched to completion.

## What this closes

ROADMAP.md sections 4-5: `v0id-malicious-evaluator-harness` (already upstream
before this session, commit `5175db7`/`c000446`) demonstrated that a "2/4
round" evaluator -- one that calls `RemoteEncryptedMachine::step()` only twice
against a 4-round job -- still returns the exact same accepted final output
and the exact same legacy FHE fingerprint as an honest 4-round evaluator, for
the harness's fixed-point demo program. That's because:

- the legacy `toy_fingerprint32_fhe` digest is computed from the *initial*
  program/tape/nonce only, never from anything round-dependent;
- the demo program (`increment`, tape `00001101`) reaches its final tape value
  by round 2 and rounds 3-4 are true no-ops for that specific input.

This session added a **round-receipt execution-bound audit** to close that
specific, demonstrated gap without overclaiming a general verifiable-
computation soundness proof.

## What was built (this session)

- `src/integrity/round_receipt.hpp` / `.cpp` -- the audit primitive. A SHA3-512
  hash chain over evaluator-visible per-round ciphertext digests, seeded from
  session_id/shape(rounds)/profile/job_id/epoch. See the header comment block
  for the exact, deliberately narrow claim boundary (what it detects vs. what
  it explicitly does not).
- `src/integrity/round_receipt_tests.cpp` -- fast, pure-logic negative tests
  (no FHE, runs in milliseconds): skip (short receipt + skip-and-resend-
  identical-ciphertext), replay (cross-job, stale-session), splice
  (final-result splice caught; interior-round splice deliberately documented
  as NOT caught). **14/14 PASS, verified this session.**
- `src/integrity/malicious_evaluator_harness.cpp` -- wired the round-receipt
  audit into the real BinFHE demo: builds a receipt during the honest 4-round
  run and verifies it accepts; builds a padded receipt for the 2/4 skip cheat
  and verifies it's REJECTED; adds real replay/splice checks reusing the same
  BinFHE-derived digests. Also added `Heartbeat` (a small RAII background-
  thread progress printer) and `std::cout << std::unitbuf` because STD128Q
  gate bootstrapping on this machine is slow enough (~2-2.5s/gate observed)
  that individual steps were running silently for minutes.
- `CMakeLists.txt` -- new `v0id-round-receipt-tests` target; `v0id_quine`
  library gained `round_receipt.cpp`; harness now links `v0id_quine` and
  `Threads::Threads` (for the heartbeat thread); library ordering was moved
  earlier in the file so the harness can link against `v0id_quine`.

## Verification status as of session end

- Full project build: **clean, 0 warnings** (`cmake --build build -j24`).
- `v0id-round-receipt-tests`: **14/14 PASS**.
- `v0id-quine-audit-tests` (pre-existing regression): **14/14 PASS**, unaffected.
- `v0id-malicious-evaluator-harness`: **NOT yet observed to complete
  end-to-end.** The legacy fingerprint computation alone (~60 FHE gates) took
  ~142s on this machine; a full honest 4-round run (~448 gates/round) could
  plausibly take over an hour, and the full harness (honest + skip + one-round
  + replay + splice) could take 1-2+ hours total. It got through BTKeyGen,
  encryption, the legacy fingerprint positive control, and started round 1
  successfully (no crash, no wrong-value throw) before the session ended.
- A detached (`nohup` + `disown`) copy may still be running on this machine at
  session end -- check `ps aux | grep v0id-malicious-evaluator-harness`. Its
  log was written to this session's scratchpad directory, which is **not**
  guaranteed to survive after the session closes. If the log is gone, just
  re-run it fresh:

  ```sh
  cd /home/pat/Downloads/V0ID-v0/build
  ./v0id-malicious-evaluator-harness
  ```

  Expect periodic `... <label> still running (Ns elapsed)` heartbeat lines
  every 10s during BTKeyGen/fingerprint/each round -- if those stop appearing,
  something is actually hung, not just slow. A correct run ends with exit
  code 0 and a "V0ID execution soundness summary" block; every `[PASS]`/
  `[BREAK]` line should read as documented in the source comments. Any
  `require(...)` failure throws and exits 2 -- that would mean a real bug,
  not the expected/documented architectural gap.

## Committed?

Check `git log -1` / `git status` when you pick this up -- the intent was to
commit once the fast test suites were green (they are) even though the full
slow harness run wasn't watched to completion, and to say so plainly in the
commit message rather than claim more verification than actually happened.
If you don't see a commit for `round_receipt.*` when you read this, the
session ended before that happened and the working tree changes are still
sitting uncommitted.

## What's still explicitly open (do not claim these are closed)

Same boundary `round_receipt.hpp` documents:

1. **Adaptive partial-work evaluator.** An evaluator that pays for a cheap
   ciphertext re-randomization (a handful of ordinary gates) instead of the
   real per-round transition circuit would produce genuinely distinct,
   genuinely-matching witnesses without doing the requested work. Closing
   this needs the witness to be bound to the transition circuit itself (a
   soundness property of real verifiable computation), not just to "some
   ciphertext changed."
2. **Interior-round splicing.** The audit only has independent ground truth
   for the *final* round's witness (it must match the actually-returned
   output). Interior rounds are counted, bound to their position via the hash
   chain, and required to be distinct -- but not otherwise validated. This is
   demonstrated (not hidden) by the `verdict_splice_interior.ok == true` test
   case in `round_receipt_tests.cpp`.
3. **Not wired into the live wire protocol.** `RoundReceiptContext` binds
   job_id/epoch, which the actual RMJ3/RMR3 wire format
   (`remote_machine_codec.hpp`) currently does *not* carry in
   `RemoteMachineResult` -- only session_id/shape/profile are echoed and
   checked there today. The round-receipt logic and its tests are real and
   sound on their own, but `remote_machine_demo.cpp`'s live client/server path
   was deliberately left untouched this session to keep the change small and
   avoid destabilizing the one existing (manually-verified, not automated)
   two-process demo. Wiring job_id/epoch into the actual result struct and
   adding round-receipt fields to RMJ3/RMR3 is the natural next step before
   this stops being "logic that exists" and becomes "protection that's
   actually in the loop."

## Idea for later: a coin/blockchain concept artifact

The user asked, low-priority / "if you ever get to it": revisit and possibly
improve the coin/blockchain concept in ROADMAP.md section 8-9 (the `WorkEvent`
MI/MV/MC + CI/CV/CC hybrid payout classification tree over `v0id_coin` /
`work_token.hpp`), and consider presenting it as a visual artifact (diagram of
the classification tree, the "freeze until verification catches up" gating
logic section 8 states, and how execution-soundness work like this round-
receipt audit is a prerequisite per section 9). Not started this session --
purely an idea to pick up later, explicitly framed by the user as optional.
