# Heuristic Candidates Reference

The candidate system surfaces attack patterns the heuristic scanner catches
but the regex catalog misses. Engineers review candidates via CLI and promote
the real ones into the scan read path.

Always on. No configuration. The write path records candidates after every
scan. The read path checks promoted candidates during every scan.

---

## How it works

```
scan → heuristic fires MEDIUM+ with no regex match → fingerprint + skeleton stored (open)
                                                              ↓
                                                  engineer reviews via CLI
                                                   ↓              ↓
                                                dismiss        promote
                                                (dead end)        ↓
                                          affects future scans (MEDIUM finding injected)
                                                      ↓
                                        engineer writes regex rule → shai patterns apply
                                        retires the candidate
```

**Four statuses:** `open` (reporting only), `promoted` (active in scans),
`dismissed` (dead — never matched again), `retired` (replaced by a regex rule).

---

## Write path — automatic, after every scan

When `heuristic_scan` produces a MEDIUM or HIGH finding AND no regex-based
scanner (`injection_scan`, `jailbreak_scan`, `identity_spoof_scan`) produced
a finding in the same call, the system:

1. Extracts a **fingerprint** — bucketed sub-scores, structural marker flags,
   control token categories, and a MinHash signature of the text's bigram
   distribution.
2. Extracts a **skeleton** — structural markers and control tokens in order,
   all other content replaced with `···`, capped at 200 characters.
3. Checks existing `open` and `promoted` candidates by MinHash similarity.
   Similarity ≥ 0.7 → increment that candidate's hit count. No match → insert
   new row with `status=open`.

No raw user text is stored. The skeleton contains only attack scaffolding:
`[INST]`, `<|system|>`, `{"role":}`, control tokens like "ignore", "override".

Fire-and-forget — errors are logged and swallowed. Never affects the scan verdict.

---

## Read path — promoted candidates only

After all scanners complete but before the ensemble runs, the pipeline checks
the current text against promoted candidates by MinHash similarity, using the
same 0.7 threshold as the write path. The first match wins — the pipeline stops
looking once one candidate matches.

A match injects a synthetic finding:

```python
Finding(
    scanner="learned_candidate",
    category="heuristic_anomaly",
    severity=Severity.MEDIUM,
    method_family="structural_heuristic",
)
```

This finding is always MEDIUM, and it never blocks. Injection adds it to the
verdict's findings only — the action loop that decides BLOCK / WARN / REDACT
iterates the per-scanner results, which a synthetic finding never joins. No
boundary action can read it, whatever its severity ends up being.

It carries `structural_heuristic`, the same family as `heuristic_scan`, so the
scanner whose output produced the candidate cannot corroborate it.

Nor, in practice, can anything else: the finding's category is
`heuristic_anomaly`, and `ensemble.py` promotes only on a **shared** category
that no catalog rule uses. A promoted candidate therefore never reaches HIGH
through the ensemble. That is deliberate — see the "Why the shipped scanners
never promote each other" note in `ensemble.py`. The candidate still raises
`TurnSignals` risk, which weighs independent method families without requiring
them to have identified the same thing.

Promoted candidates are cached in memory. Because the CLI runs in a separate
process, a status change cannot invalidate a running harness's cache. Restart
the harness or invalidate the cache in that runtime process when immediate
pickup is required.

---

## Fingerprint

The fingerprint captures the shape of an anomaly without storing content:

```json
{
  "entropy": "high",
  "density": "medium",
  "coherence": "none",
  "structural": "high",
  "markers": ["<|system|>", "[INST]"],
  "control_tokens": ["ignore", "override", "call"],
  "length_bucket": "medium",
  "lsh": "a3f9b1c4e2d710863f0a91bb…"
}
```

Sub-scores are bucketed: `none | low | medium | high`.

`lsh` is a MinHash signature over character bigrams: 64 minima, each written as
8 hex characters, concatenated into one 512-character string. Similarity is the
**fraction of those 64 minima that agree** — an unbiased estimate of the Jaccard
overlap of the two bigram sets. Two texts differing by a word score ~0.95;
unrelated texts score ~0.20. Neither is reversible to content.

The whole signature is stored on purpose. Compressing it to a short digest — as
this field did before 0.7.0 — destroys the property the estimator depends on:
minima have to survive independently, and any avalanche hash turns one differing
minimum into an unrelated output, collapsing every non-identical pair to ~0.

Signatures of unequal length share nothing, so a row written under the older
format scores 0.0 against current text and is superseded rather than matched.

---

## Skeleton

The skeleton shows what triggered the heuristic, not what the user said:

```
··· [INST] ··· ignore override ··· {"role":"system"} ··· call send_email ···
```

This tells the engineer: someone embedded an `[INST]` tag, instruction
override tokens, a JSON role injection, and a tool coercion — all in one
message. Enough to evaluate and write a regex.

---

## CLI

### List candidates

```bash
shai patterns candidates --db state/patterns.db

#   id=12  hits=23  severity=HIGH  first=Jul-15  last=Jul-20  status=open
#     entropy=high  density=medium  markers=[<|system|>,[INST]]
#     skeleton: ··· [INST] ··· ignore override ··· {"role":"system"} ··· call send_email ···
#
#   id=8   hits=2   severity=MEDIUM  first=Jul-19  last=Jul-19  status=open
#     entropy=high  density=none  markers=[none]
#     skeleton: ··· (entropy/coherence anomaly) ···
```

### Filter by status

```bash
shai patterns candidates --db state/patterns.db --status promoted
shai patterns candidates --db state/patterns.db --status open
shai patterns candidates --db state/patterns.db --status open --all
```

Open candidates with fewer than three hits are hidden when filtering by
`--status open`; `--all` includes them.

### Promote — enters read path

```bash
shai patterns promote --db state/patterns.db --id 12
```

After this, future scans that match candidate 12's fingerprint get a MEDIUM
finding injected into the pipeline.

### Dismiss — false positive

```bash
shai patterns dismiss --db state/patterns.db --id 8
```

Dismissed candidates are never matched again. They remain in the DB for
audit purposes but are excluded from all lookups.

### Retire — replaced by regex rule

```bash
shai patterns retire --db state/patterns.db --id 12
```

Use after writing a proper regex rule via `shai patterns apply`. The
candidate is no longer needed — the regex rule is the permanent fix.

---

## Lifecycle: candidate to regex rule

1. **Detect** — heuristic scanner flags a MEDIUM+ anomaly the regex catalog missed.
2. **Record** — write path stores the fingerprint and skeleton automatically.
3. **Review** — engineer runs `shai patterns candidates`, reads the skeleton.
4. **Promote** — engineer runs
   `shai patterns promote --db state/patterns.db --id N`. After the runtime
   reloads its promoted-candidate cache, future similar texts get a MEDIUM
   finding that feeds the ensemble.
5. **Write rule** — engineer writes a targeted regex from the skeleton,
   signs it into a bundle, applies via `shai patterns apply`.
6. **Retire** — engineer runs
   `shai patterns retire --db state/patterns.db --id N`. The regex rule is now
   the permanent detection. The candidate served its purpose.

---

→ See `04-boundaries.md` for how findings flow through the ensemble.
→ See `02-harness-yaml.md` for the pattern-DB CLI workflow.
