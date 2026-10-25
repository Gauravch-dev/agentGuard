# Application review of the Linux return round

Recorded 25 October 2026. Reviewed upstream checkpoint:
`a95e564ef2277535833fd99905415b957976229a`.

Member 2's return adds genuine process/file/connect observations, bounded packet
experiments, durable authenticated export, staged lifecycle evidence and actual
pinned local-model provider calls. Its committed lab artifacts remain unchanged.
Those experiments do not establish complete continuous monitoring or an admitted
Finance run. The default live reviewer still refuses without the sensor supervisor.

## Application fixes

| Finding | Resulting behavior |
|---|---|
| Identical core event replay could change collector provenance without detection | Replays compare source details and wire format; conflicts return 409 and retain the original event and metadata. Collector receipt time and server adapter-build changes remain valid replay differences. |
| A conflicting coverage ID was rejected but earlier complete coverage could still authorize output | Authenticated contradictions are retained as version-scoped conflict evidence. Admission, monitoring, output release and final success all hold for that revision, even after newer complete windows arrive. |
| Conflicts from an old contract revision contaminated a new revision's assessment | Old evidence stays in the audit trail; current findings and release gates use the current contract version. Historical unversioned conflict records belong to version 1. |
| Hook metadata could disagree with the operation or syscall return | The application bridge validates reviewed hook names, file/network operation classes and signed return semantics. A negative syscall return cannot become an observed effect or an enforcement claim. |
| Admission decisions read a shared diagnostic result after publishing it | Each invocation now uses its own assessment. A deterministic concurrent-review regression verifies that another capsule's passing diagnostics cannot approve a rejected capsule. |
| The UI exposed only a generic admission-review hold | The adapter returns bounded reason codes from that capsule's assessment, including missing continuous supervision and model setup. Arbitrary diagnostic text/paths are not exposed. |
| Malformed model envelopes could escape without a broker receipt; registry replies were buffered before their size check | Registry and inference replies are bounded while reading, strictly parsed and checked for object/registry shape. Invalid, ambiguous, incomplete or unexpected replies produce `MODEL_UNAVAILABLE` and an unknown-effect receipt. Stale metrics are cleared. |

The model provider keeps the fixed loopback target, disabled proxy/redirect use,
approved digest checks before and after inference, token limit and a shared
30-second acceptance deadline across the exchange. HTTP waits are bounded by the
remaining budget and the deadline is checked during and after reading. This is
not a replacement for the independent container watchdog or hard process deadline;
an in-progress socket wait may finish after the acceptance deadline before refusal.

Source-conflict rows retain identifiers, reason codes and keyed fingerprints,
not replacement raw payloads. Repeating the same contradiction is idempotent.
Exact coverage replays explicitly acknowledge `duplicate: true`. Conflicting
records cannot overwrite the first observation or be erased by newer coverage.
A new revision still requires prior capsule containment verification on the
staged runtime path. Historical released internal reports are retained; a later
conflict prevents verified completion rather than rewriting history.

## Validation and limits

The unmodified pulled checkpoint passed 146 Windows tests, with 11 Linux-specific
skips and 13 passing subtests. The new regressions use clearly labelled fixtures
or HTTP mocks; no actual model request, container launch or sensor installation
was performed on this application-review host.

New checks cover genuine hook-shaped records reaching the owner assessment,
attempt-versus-enforcement semantics, provenance/coverage contradictions, replay
after adapter upgrades, version isolation, report holds, final-success rejection,
concurrent admission decisions, bounded model responses, malformed registries,
ambiguous tool JSON, stale metrics and unknown broker receipts.

Final local results are in `application_review_validation.json`. All shared
contract/event JSON schemas and the four-field broker protocol are unchanged.
The dashboard TypeScript/build check is included; this round changes explanation
text and does not claim a new visual-browser or live Linux acceptance result.

Final results: **169 passed, 11 Linux-specific skips, 13 subtests passed**. Lint,
formatting, application types (20 source files), shared schema compatibility,
dashboard TypeScript/build, offline changed-source secret scanning and whitespace
checks passed. The existing Starlette TestClient/httpx deprecation warning remains.

## Return tasks for Member 2

1. Pull this checkpoint, rerun the complete suite on Linux, and rerun the genuine
   hook-to-export-queue-to-application pipeline. Preserve exact source identity
   and details on retries; receipt time and server build metadata may differ.
2. Validate real coverage rejection/recovery and contradiction handling. A denied
   output can be retried with a new request ID after genuine missing coverage
   recovers; a contradictory immutable source ID requires investigation and a
   new authorized revision, not relabelling or clearing its conflict.
3. Finish the independent continuous supervisor for all required scopes, including
   authenticated packet export, source identities, health, loss/reset/export
   failures, source gaps and clock compatibility. Queue EOF or a successful
   bounded observation must not produce complete coverage or admission.
4. Retest the live reviewer and warmed approved local model using the stricter
   response parser and acceptance budget. Record real model metrics/limits;
   malformed/error replies cannot count as a completed agent action.
5. Run admitted benign/injected Finance tasks only after the mandatory live gates
   pass. Complete report continuation, cancellation/expiry/outage/restart and the
   remaining S01–S16 cases with baseline/performance measurements.
6. Commit and push code and sanitized evidence back to this repository, update
   `docs/linux_return_round.md`, and return the exact commit/branch. Member 1 will
   pull and verify real findings/report outcomes for the next acceptance round.

Protected execution remains held until those live requirements are satisfied.
