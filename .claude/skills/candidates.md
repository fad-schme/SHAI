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
   control token categories, and a MinHash LSH of the text's bigram distribution.
2. Extracts a **skeleton** — structural markers and control tokens in order,
   all other content replaced with `···`, capped at 200 characters.
3. Checks existing candidates by LSH similarity. Match → increment hit count.
   No match → insert new row with `status=open`.

No raw user text is stored. The skeleton contains only attack scaffolding:
`[INST]`, `<|system|>`, `{"role":}`, control tokens like "ignore", "override".

Fire-and-forget — errors are logged and swallowed. Never affects the scan verdict.

---

## Read path — promoted candidates only

After all scanners complete but before the ensemble runs, the pipeline checks
the current text against promoted candidates by LSH similarity.

A match injects a synthetic finding:

```python
Finding(
    scanner="learned_candidate",
    category="heuristic_anomaly",
    severity=Severity.MEDIUM,
)
```

This finding is always MEDIUM. It never blocks on its own at `block_at: high`.
But it participates in the ensemble — if `injection_scan` also flags the same
category, the ensemble promotes both to HIGH.

Promoted candidates are cached in memory. The cache is invalidated when the
CLI changes a candidate's status.

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
  "lsh": "a3f9b1c4e2d71086"
}
```

Sub-scores are bucketed: `none | low | medium | high`. The LSH is a MinHash
over character bigrams — two texts with similar bigram distributions produce
similar hashes without being reversible to content.

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
```

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
4. **Promote** — engineer runs `shai patterns promote --id N`. Future similar
   texts get a MEDIUM finding that feeds the ensemble.
5. **Write rule** — engineer writes a targeted regex from the skeleton,
   signs it into a bundle, applies via `shai patterns apply`.
6. **Retire** — engineer runs `shai patterns retire --id N`. The regex rule
   is now the permanent detection. The candidate served its purpose.

---

## What candidates do NOT do

- **No auto-learning.** Open candidates never affect scans. Only human-promoted
  candidates enter the read path.
- **No raw text storage.** Fingerprints contain bucketed scores and LSH hashes.
  Skeletons contain only structural markers and control tokens.
- **No blocking on their own.** Promoted candidate findings are MEDIUM. They
  only cause a block when the ensemble combines them with another scanner's
  finding for the same category.
- **No replacement for regex rules.** Candidates are similarity-based discovery.
  Regex rules are precise permanent fixes. Candidates find the attack shape.
  Rules lock it down.

→ See `04-boundaries.md` for how findings flow through the ensemble.
→ See `02-harness-yaml.md` for `patterns_db` configuration (signed regex rules).
