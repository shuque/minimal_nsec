# Analysis of UltraDNS Minimally Covering NSEC Algorithm

## Background

UltraDNS, a commercial DNS provider, uses a variant of Minimally
Covered NSEC records in their DNSSEC implementation described in
RFC 4470 ( https://datatracker.ietf.org/doc/html/rfc4470 ). This
exercise tries to reverse engineer the UltraDNS epsilon function
used to compute the NSEC predecessor and successor names.

After the initial reverse engineering was completed, the results were
shared with colleagues at UltraDNS who reviewed them against the
actual source code. They confirmed the analysis was largely accurate
and provided clarifications on the internal structure of the algorithm,
including the distinction between the "relaxed" and "absolute" (RFC 4471
fallback) code paths, the actual mechanism behind variable-depth
predecessor padding, and edge case behavior for maximum-length labels
that we had not yet tested empirically. These clarifications are
annotated throughout this document.

## Character Alphabet

From the decrement observations, we can deduce the character set used by
UltraDNS's epsilon function. The key evidence is which characters map to
the same predecessor when decremented:

| Queried last char | Predecessor last char | ASCII gap |
|---|---|---|
| a (0x61) | \_ (0x5F) | skips \` (0x60) |
| \_ (0x5F) | 9 (0x39) | skips : ; < = > ? @ A-Z \[ \\ \] ^ (0x3A-0x5E) |
| 0 (0x30) | - (0x2D) | skips . / (0x2E-0x2F) |
| - (0x2D) | ! (0x21) | skips " # $ % & ' ( ) \* + , (0x22-0x2C) |
| \~ (0x7E) | z (0x7A) | skips { \| } (0x7B-0x7D) |

All characters between consecutive alphabet members decrement to the same
predecessor. For example:
- b" b# b\* b+ b all have predecessor `\~.b!\~` (all chars 0x22-0x2C -> !)
- b/ b. would have predecessor `\~.b-\~` (chars 0x2E-0x2F -> -)
- b: b; b@ b^ all have predecessor `\~.b9\~` (chars 0x3A-0x5E -> 9)
- b\` has predecessor `\~.b_\~` (char 0x60 -> \_)
- b{ b| b} all have predecessor `\~.bz\~` (chars 0x7B-0x7D -> z)

### Deduced Alphabet (ordered)

```
! - 0 1 2 3 4 5 6 7 8 9 _ a b c d e f g h i j k l m n o p q r s t u v w x y z ~
```

In hex: 0x21, 0x2D, 0x30-0x39, 0x5F, 0x61-0x7A, 0x7E

This is essentially: `!`, `-`, digits `0-9`, `_`, lowercase letters `a-z`, `~`

Total: 40 characters

Note: DNS is case-insensitive for comparisons, so uppercase A-Z maps to
lowercase a-z. The algorithm appears to operate in the lowercased space.

## Successor Function

**For NODATA responses** (name exists, wrong type):
- The NSEC owner = the queried name itself
- The NSEC next name = queried name with `!` appended
- `!` (0x21) is the smallest character in the alphabet
- This means the NSEC range `[name, name!)` contains only `name` itself

**For NXDOMAIN responses** (name doesn't exist):
- The NSEC next name = queried name with `!` appended
- Same as NODATA

**Special cases for names with children in the zone:**

For any name that has children in the zone — whether it is the zone apex,
an empty non-terminal, or a regular name with data — simply appending `!`
to the label would not work. In DNS canonical ordering, all children of a
name sort between the name and its next sibling. So if the successor were
`corp!`, the NSEC range `[corp, corp!)` would also cover `finance.corp` (a
legitimate child that exists in the zone), effectively denying its
existence. For the zone apex there is an additional reason: appending `!`
to the apex label would produce `ultratest!.huque.com.`, which is a name
in the parent `huque.com` zone, not in `ultratest.huque.com`. NSEC records
chain names within a single zone, so the next name must remain within the
zone's authority. Even if a validator doesn't enforce a same-zone check,
producing an out-of-zone next name would be semantically incorrect.
Beyond this, `ultratest!` would also sort after all child names in the zone,
creating the same coverage problem.

Instead, the successor must be a child of the name, sorting after the name
but before any real children:

- Zone apex NODATA: next name = `!.ultratest.huque.com.` (child label `!`,
  the alphabet minimum, which sorts before any real child)
- Name with children (corp): next name = `\000.corp.ultratest2.huque.com.`
  (a child label containing a single 0x00 byte). `corp` has data (TXT) but
  also has children (`finance.corp`), so the child-label approach is needed.
- Empty non-terminal (ent): next name = `\000.ent.ultratest.huque.com.`
  (same `\000` child label as any other non-apex name with children)

The zone apex uses `!` (the algorithm's alphabet minimum) as the child
label, while all other names with children use `\000` (the absolute DNS
minimum byte). We originally speculated this indicated separate code
paths with the ENT/child case falling back to a generic DNS minimum.

**Clarification from UltraDNS:** The actual code structure confirms two
distinct code paths, but the mechanism is different from what we
speculated. The algorithm has a "relaxed" successor function and an
"absolute" successor function (implementing RFC 4471 §3.1). The relaxed
function always tries to append `!` to the leaf label first (for all
non-apex names). It then performs an **acceptability check**: the
synthesized name must sort before the actual next name in the zone. For
names with children, this check fails — `corp!` sorts after `finance.corp`
in canonical order (children sort between a name and its next sibling),
so the relaxed result would incorrectly cover existing children. When
the acceptability check fails, the algorithm falls back to the absolute
successor function, which prepends a `\000` child label (the minimum
possible DNS byte). The zone apex has its own explicit case in the
relaxed function that directly prepends `!.` without going through the
append-then-check path.

**Edge case — maximum-length labels:** When the leaf label is already at
the maximum label size (63 bytes), appending `!` is impossible. Instead,
the relaxed function increments the last octet to the next character in
the pretty alphabet. For example, for a 63-byte label ending in `x`:
next name replaces the last octet with `y`. (Verified empirically — see
Appendix.)

**Conclusion: The successor function is always "append `!`"** for leaf
names (no children in the zone) whose labels are below maximum length.
For any name that has children in the zone — whether the zone apex, an
empty non-terminal, or a name with both data and children — a
child-label approach is used instead to avoid covering existing children
(`!` for the apex, `\000` via the absolute fallback for all others).
When the label is at maximum length (63 bytes), the last octet is
incremented in the pretty alphabet instead of appending.

## Scope of the Algorithm

For NODATA responses (name exists, wrong type), the algorithm operates
directly on the queried name.

For non-existent names (NXDOMAIN and wildcard-synthesized responses),
the predecessor and successor functions operate on the **first label
below the closest encloser** (the "next closer name", per RFC 5155)
of the queried name. The closest encloser
is the deepest existing ancestor of the query name within the zone. For
a direct child of the zone (e.g., `koala.ultratest.huque.com`), the
closest encloser is the zone apex and the algorithm operates on the
label `koala`. For a deeper name (e.g., `xxx.finance.corp.ultratest2
.huque.com`), the closest encloser is `finance.corp.ultratest2.huque
.com` and the algorithm operates on the label `xxx`. The remaining
labels (the closest encloser suffix) are carried through unchanged in
both the predecessor and successor names.

## Predecessor Function

The predecessor function is more complex. For a queried name Q:

1. Take the last character of Q
2. Decrement it to the previous character in the alphabet
3. Append `~` (the maximum character in the alphabet)
4. Prepend a child label `~`

The general form for predecessor of label `L` = `~.L[0..n-2] + prev(L[n-1]) + ~`

Where `prev(c)` is the previous character in the alphabet:
- prev(a) = \_
- prev(\_) = 9
- prev(0) = -
- prev(-) = !
- prev(\~) = z
- prev(b) = a, prev(c) = b, ..., prev(z) = y
- prev(1) = 0, prev(2) = 1, ..., prev(9) = 8

**Special case when last char is `!`** (the minimum character):
When the last character is already `!` (the minimum), you can't decrement it.
Instead, the predecessor drops the last character and prepends a child label `~`:
- pred(b!) = `\~.b` (i.e., the child label `~` under parent `b`)
- pred(c!) = `\~.c`

This makes sense because in canonical DNS ordering, `~.b` (i.e., a child `~`
under `b`) sorts just before `b!` (a sibling `b!`).

### Why `~` as child label and suffix?

`~` (0x7E) is the maximum character in the alphabet. By using it:
- As a child label prefix: maximizes the name in the "children come before
  siblings" DNS canonical ordering
- As a suffix after the decremented character: pushes the name as far forward
  as possible within that position

The result is a name that sorts immediately before the queried name in
canonical order, creating the tightest possible NSEC bracket.

The predecessor is not padded to maximum DNS name length (except for the
edge case of querying `!` itself, which produced a max-length 0xFF-filled
name — this is the absolute/RFC 4471 fallback).

**Edge case — maximum-length labels (confirmed with UltraDNS):** When the
leaf label is already at the maximum label size (63 bytes), step 3
(append `~`) is skipped because there is no room in the label. The
predecessor is formed by decrementing the last octet and prepending `~.`
child labels only. For example, for a 63-byte label of all `x`'s ending
in `z`, the predecessor is `~.` prepended to the label with the last
octet decremented to `y` — no `~` suffix appended. (Verified
empirically — see Appendix.)

## Variable-Depth Predecessor

The number of `~` child labels prepended to the predecessor base label
is not fixed — it varies depending on the zone content. The base label
computation is always the same (decrement last character, append `~`),
but the number of `~` child labels prepended equals the **subtree height
of the nearest preceding existing domain name within the zone** in DNS
canonical order.

### Rule

Given a query name Q, identify the closest encloser (see "Scope of the
Algorithm" above) and extract the first label L below it. Then:

1. Find the nearest existing domain name P within the zone that
   precedes L in DNS canonical order (at the same level below the
   closest encloser).
2. Compute the subtree height of P: the length of the longest
   descendant chain rooted at P within the zone.
   - Leaf node (no children): height = 1
   - Node with children but no grandchildren: height = 2
   - Node with grandchildren: height = 3, etc.
3. Prepend that many `~` child labels to the predecessor base label.
4. If no preceding name exists (Q sorts before all names at this level),
   use height = 0 (no `~` child labels).

### Verification with ultratest2.huque.com

The zone `ultratest2.huque.com` was constructed specifically to test this
theory, with names at various subtree depths:

**Zone structure (apex level):**
- `*` (wildcard, leaf)
- `aa` (leaf)
- `corp` (TXT) → `finance.corp` (TXT) → `foo.finance.corp` (A) — height 3
- `dd` (leaf)
- `ent` (ENT) → `kk.ent` (A) — height 2
- `gg`, `jj`, `mm`, `pp`, `ss`, `vv`, `yy` (all leaves)

**Apex-level queries (wildcard-synthesized responses):**

| Query | Preceding name | Subtree height | Depth | Predecessor |
|---|---|---|---|---|
| `a` | `*` (leaf) | 1 | 1 | `\~.\_\~` |
| `ab` | `aa` (leaf) | 1 | 1 | `\~.aa\~` |
| `bb` | `aa` (leaf) | 1 | 1 | `\~.ba\~` |
| `da` | `corp` (→finance→foo) | 3 | 3 | `\~.\~.\~.d\_\~` |
| `foo.da` | `corp` (→finance→foo) | 3 | 3 | `\~.\~.\~.d\_\~` (next closer name is `da`) |
| `ee` | `dd` (leaf) | 1 | 1 | `\~.ed\~` |
| `ff` | `ent` (→kk) | 2 | 2 | `\~.\~.fe\~` |
| `hh` | `gg` (leaf) | 1 | 1 | `\~.hg\~` |
| `ww` | `vv` (leaf) | 1 | 1 | `\~.wv\~` |
| `zz` | `yy` (leaf) | 1 | 1 | `\~.zy\~` |

**Subdomain-level queries (NXDOMAIN responses):**

| Query | Preceding name | Subtree height | Depth | Predecessor |
|---|---|---|---|---|
| `ab.corp` | (none) | 0 | 0 | `aa\~.corp` |
| `ga.corp` | `finance` (→foo) | 2 | 2 | `\~.\~.g\_\~.corp` |
| `ab.ent` | (none) | 0 | 0 | `aa\~.ent` |
| `zz.ent` | `kk` (leaf) | 1 | 1 | `\~.zy\~.ent` |
| `ab.finance.corp` | (none) | 0 | 0 | `aa\~.finance.corp` |
| `zz.finance.corp` | `foo` (leaf) | 1 | 1 | `\~.zy\~.finance.corp` |

### Verification with ultratest.huque.com

The original test zone confirms the same pattern:

**Zone structure (apex level):**
- `*` is not present at the apex (only under `wild`)
- `_`, `_foo` (leaves)
- `address1`, `address2` (leaves)
- `ent` (ENT) → `foo.ent` (A) — height 2
- `jaguar`, `panthro` (leaves)
- `wild` → `*.wild`, `bar.wild`, `explicit.wild` — height 2
- `yak` (leaf)

| Query | Preceding name | Subtree height | Depth | Notes |
|---|---|---|---|---|
| f–j | `ent` (→foo.ent) | 2 | 2 | between `ent` and `jaguar` |
| x–y | `wild` (→\*.wild, etc.) | 2 | 2 | between `wild` and `yak` |
| koala, m, etc. | various leaves | 1 | 1 | typical case |
| !a | (none before `*`) | 0 | 0 | sorts before all zone names |
| a.b | (none under `b`) | 0 | 0 | no children exist under `b` |

The boundary test from the original zone also confirms: `en` (depth-1,
predecessor `\~.em\~`) vs `eo` (depth-2, predecessor `\~.\~.en\~`). The
predecessor label for `en` is `em\~`, which sorts before `ent` in
canonical order — so the depth still reflects the leaf-like predecessor
`address2` or is within a safe range. For `eo`, the predecessor label
`en\~` would sort after `ent` (since `ent` < `en\~`), so the algorithm
accounts for `ent`'s subtree and uses depth-2.

### Why extra depth is not strictly required

In every observed case, a depth-1 (or even depth-0) predecessor would
produce a canonically valid NSEC. No existing zone names fall within the
tighter range. The extra depth produces a slightly narrower bracket:

```
(canonical order)
  ~.e~  <  ~.~.e~  <  f  <  f!
```

Both `[\~.e\~, f!)` and `[\~.\~.e\~, f!)` are valid — neither contains
any existing zone name.

### Rationale for Variable Depth (Speculative)

The extra depth is never required for correctness. A depth-0 predecessor
(just the base label, no `\~` child labels) always sorts after the
preceding name P and all of P's descendants in canonical order. This is
because the base label is lexicographically greater than P's label (since
the query Q > P, and the decrement only touches the last character). In
canonical ordering, the first-from-zone label comparison already decides
`base\_label > P\_label`, so all descendants of P (whose first-from-zone
label is `P\_label`) sort before even a depth-0 predecessor.

Our initial speculation was that the depth is a **natural emergent
property of a tree traversal**. When the online signer computes the
canonical predecessor of Q, it likely:

1. Walks an internal data structure (e.g., a red-black tree or trie)
   that indexes zone names in canonical order.
2. Finds the "previous entry" by descending to the **rightmost leaf**
   under the preceding sibling node.
3. That rightmost leaf sits at a depth equal to the subtree height.
4. The `\~` child labels are generated as the traversal ascends back up
   from that leaf — one per level.

In this model, the algorithm is not explicitly computing "subtree height
of the preceding name." It is simply performing a standard "find the
previous entry in a sorted tree" operation, and the depth is how deep
that traversal naturally goes. The `\~` labels (the maximum character in
the alphabet) at each level ensure the synthetic name sorts after every
real descendant at that level, mimicking a "go right as far as possible
at each level" tree walk.

### Actual Mechanism (Confirmed by UltraDNS)

The actual code uses an explicit label-count matching loop rather than
a tree traversal. After computing the predecessor base label (steps 1–3
above), the algorithm prepends `~.` child labels in a loop while:

- There is room in the name (at least 2 bytes under MAX\_NAME\_SIZE), AND
- The number of labels in the synthesized name is ≤ the number of labels
  in the **actual previous name** in the zone.

If there is no actual previous name (the query sorts before all names at
this level), a single `~.` label is prepended and the loop stops.

This produces the same result as our subtree-height theory: the actual
previous name's label count reflects its depth in the zone tree, which
equals the subtree height we observed. The mechanism is a label-count
comparison against the real previous name, not a subtree height
computation or tree walk — but the observable behavior is identical.

There is one theoretical scenario where extra depth could matter: if zone
names contained label bytes > 0x7E (the octet value of `\~`), then a
single `\~` child label would not be the maximum at that level, and a
real descendant could sort after it. Going deeper provides a wider safety
margin. However, UltraDNS almost certainly restricts zone names to their
defined 40-character alphabet (where `\~` is the maximum), making this a
theoretical rather than practical concern.

## Wildcard Coverage NSEC

For NXDOMAIN responses, a second NSEC proves no wildcard exists at the
closest encloser. For direct children of the zone, this is always:

```
!~.ultratest.huque.com. NSEC -.ultratest.huque.com.
```

This bracket `(!~, -)` covers `*` (0x2A) which would be the wildcard label.
- `!~` = `!` + `~`, which is the maximum name starting with `!`
- `-` is the next character in the alphabet after `!`
- So this range covers everything between `!~` and `-`, which includes `*`

Note: The zone does have `*.wild.ultratest.huque.com` but that's a wildcard
under the `wild` subdomain, not at the zone apex.

### Wildcard-synthesized response (nonexist.wild)

A query for `nonexist.wild.ultratest.huque.com. A` returned a
wildcard-synthesized answer (from `*.wild.ultratest.huque.com`). The
response included an NSEC proving that no name closer than the wildcard
exists:

```
~.nonexiss~.wild.ultratest.huque.com. NSEC nonexist!.wild.ultratest.huque.com.
```

This uses the same predecessor/successor algorithm, applied within the
`wild.ultratest.huque.com` subdomain: predecessor of `nonexist` is
`~.nonexiss~` (decrement `t` to `s`, append `~`, prepend child label `~`),
and successor is `nonexist!`. This proves no exact match for
`nonexist.wild` exists, so the wildcard synthesis is valid.

### Wildcard-synthesized response at zone apex (camel)

To test whether UltraDNS applies the same algorithm at the zone apex, a
temporary `*.ultratest.huque.com` wildcard was added. A query for
`camel.ultratest.huque.com. A` returned a wildcard-synthesized answer
with this NSEC in the authority section:

```
~.camek~.ultratest.huque.com. NSEC camel!.ultratest.huque.com.
```

This is the same predecessor/successor algorithm: predecessor of `camel` is
`~.camek~` (decrement `l` to `k`, append `~`, prepend child label `~`),
and successor is `camel!`. No wildcard coverage NSEC is needed since the
wildcard exists. This confirms no special-casing at the zone apex — the
algorithm is identical to the `nonexist.wild` case under a subdomain wildcard.

## Appendix: Raw Query Data

All names below are shown as labels relative to `ultratest.huque.com`
unless otherwise noted.

### NODATA Responses

| Query (name, type) | NSEC Owner | NSEC Next | Type Bitmap |
|---|---|---|---|
| address1 AAAA | address1 | address1! | A RRSIG NSEC |
| address2 A | address2 | address2! | AAAA RRSIG NSEC |
| jaguar AAAA | jaguar | jaguar! | A RRSIG NSEC |
| yak AAAA | yak | yak! | A RRSIG NSEC |
| \_ A | \_ | \_! | TXT RRSIG NSEC |
| ultratest.huque.com AAAA | ultratest.huque.com | !.ultratest.huque.com | A NS SOA RRSIG NSEC DNSKEY CAA |
| corp.ultratest2 TLSA | corp.ultratest2 | \\000.corp.ultratest2 | TXT RRSIG NSEC |
| ent A | ent | \\000.ent | RRSIG NSEC |

Note: `ent` is an empty non-terminal (has child `foo.ent` but no records
of its own). `corp.ultratest2` has data (TXT) but also has children
(`finance.corp`). Both use a `\000` child label rather than appending `!`,
because they have children in the zone. Per UltraDNS clarification, the
`\000` child label comes from the absolute (RFC 4471) fallback function —
the relaxed function tries appending `!` first but the acceptability
check fails because `corp!` would sort after the existing child
`finance.corp`.

### NXDOMAIN Responses — Name Coverage NSEC

Each NXDOMAIN response contains two NSECs. This table shows the NSEC that
covers the queried name (proves it doesn't exist).

| Query | Predecessor (NSEC owner) | Successor (NSEC next) | Notes |
|---|---|---|---|
| koala | `\~.koal_\~` | koala! | |
| apple | `\~.appld\~` | apple! | |
| zebra | `\~.zebr_\~` | zebra! | |
| abc | `\~.abb\~` | abc! | |
| m | `\~.l\~` | m! | single char |
| zzz | `\~.zzy\~` | zzz! | |
| ba | `\~.b_\~` | ba! | a decrements to \_ |
| bA | `\~.b_\~` | ba! | case-insensitive, same as ba |
| b0 | `\~.b-\~` | b0! | 0 decrements to - |
| b- | `\~.b!\~` | b-! | - decrements to ! |
| b\_ | `\~.b9\~` | b\_! | \_ decrements to 9 |
| b\~ | `\~.bz\~` | b\~! | \~ decrements to z |
| b! | `\~.b` | b!! | ! is minimum: drops char, uses child label |
| c! | `\~.c` | c!! | same ! minimum behavior |
| b" | `\~.b!\~` | b"! | non-alphabet char, maps to ! |
| b# | `\~.b!\~` | b#! | non-alphabet char, maps to ! |
| b\* | `\~.b!\~` | b\*! | non-alphabet char, maps to ! |
| b+ | `\~.b!\~` | b+! | non-alphabet char, maps to ! |
| b, | `\~.b!\~` | b,! | non-alphabet char, maps to ! |
| b/ | `\~.b-\~` | b/! | non-alphabet char, maps to - |
| b\` | `\~.b_\~` | b\`! | non-alphabet char, maps to \_ |
| b: | `\~.b9\~` | b:! | non-alphabet char, maps to 9 |
| b; | `\~.b9\~` | b;! | non-alphabet char, maps to 9 |
| b@ | `\~.b9\~` | b@! | non-alphabet char, maps to 9 |
| b^ | `\~.b9\~` | b^! | non-alphabet char, maps to 9 |
| b{ | `\~.bz\~` | b{! | non-alphabet char, maps to z |
| b\| | `\~.bz\~` | b\|! | non-alphabet char, maps to z |
| b} | `\~.bz\~` | b}! | non-alphabet char, maps to z |
| b1 | `\~.b0\~` | b1! | digit decrement |
| b9 | `\~.b8\~` | b9! | digit decrement |
| bz | `\~.by\~` | bz! | letter decrement |
| a | `\~._\~` | a! | single char, a decrements to \_ |
| cat | `\~.cas\~` | cat! | |
| abcdef | `\~.abcdee\~` | abcdef! | longer name |
| abcdefghij | `\~.abcdefghii\~` | abcdefghij! | longer name |
| address0 | `\~.address-\~` | address0! | 0 decrements to - |
| address1a | `\~.address1_\~` | address1a! | a decrements to \_ |
| zzzzz | `\~.zzzzy\~` | zzzzz! | |
| !a | `!_\~` | !a! | pred uses \_ (prev of a), no child label prepended |
| a.b | `_\~.b` | a!.b | multi-level: algorithm applied to first label under closest encloser b |
| f | `\~.\~.e\~` | f! | depth=2 predecessor (between ent and jaguar) |
| g | `\~.\~.f\~` | g! | depth=2 |
| h | `\~.\~.g\~` | h! | depth=2 |
| i | `\~.\~.h\~` | i! | depth=2 |
| j | `\~.\~.i\~` | j! | depth=2 |
| x | `\~.\~.w\~` | x! | depth=2 (between wild and yak) |
| y | `\~.\~.x\~` | y! | depth=2 |
| en | `\~.em\~` | en! | depth=1, just before boundary |
| eo | `\~.\~.en\~` | eo! | depth=2, at boundary |

### NXDOMAIN Responses — Wildcard Coverage NSEC

For all NXDOMAIN queries of direct children of the zone, the wildcard
coverage NSEC was identical:

```
!~.ultratest.huque.com. NSEC -.ultratest.huque.com. RRSIG NSEC
```

This covers `*` (0x2A), proving no wildcard exists at the zone apex.

For multi-level names, the wildcard NSEC covers the appropriate closest
encloser. For example, `a.b.ultratest.huque.com` produced:

```
!~.b.ultratest.huque.com. NSEC -.b.ultratest.huque.com. RRSIG NSEC
```

### Wildcard-Synthesized Response

| Query | NSEC Owner | NSEC Next | Notes |
|---|---|---|---|
| nonexist.wild | `\~.nonexiss\~.wild` | nonexist!.wild | proves no closer match than \*.wild |
| camel (apex wildcard) | `\~.camek\~` | camel! | proves no closer match than \*.ultratest.huque.com |

### Special Case: Querying "!" Itself

Querying `!.ultratest.huque.com` produced a predecessor consisting of a
maximum-length name filled with `\255` (0xFF) bytes across multiple labels,
representing the absolute maximum possible name that sorts before `!` in
the DNS namespace. The successor was `!!`. Per UltraDNS clarification,
this is the absolute predecessor function (RFC 4471 §3.1 fallback) —
the relaxed predecessor cannot go below `!` (the alphabet minimum), so
the absolute function takes over and produces the maximally-padded
0xFF name.

### Maximum-Length Label (63 bytes)

Tested after consultation with UltraDNS to verify edge case behavior
when the leaf label is at the maximum DNS label size (63 bytes).

A 63-byte label of all `x`'s was added to `ultratest2.huque.com`:

**NODATA response** (name exists, queried for AAAA):
```
xxxxxxx...x.ultratest2.huque.com.  NSEC  xxxxxxx...y.ultratest2.huque.com.
```
(63 x's → 62 x's + `y`)

The relaxed successor cannot append `!` because the label is already
at maximum length. Instead, it increments the last octet `x` to the
next character in the pretty alphabet: `y`. This is Sub-case B2 in the
UltraDNS code.

**Wildcard-synthesized response** (63-byte label ending in `z`, nonexistent):
```
owner: ~.xxxxxxx...y.ultratest2.huque.com.   (predecessor)
next:  xxxxxxx...~.ultratest2.huque.com.     (successor)
```
(predecessor: 62 x's + `y`, with `~.` child label; successor: 62 x's + `~`)

For the successor: last octet `z` is incremented to `~` (B2 again).

For the predecessor: last octet `z` is decremented to `y`, but the `~`
suffix cannot be appended because the label is full. Only the `~.` child
label padding is applied. This matches the documented Step 4 behavior:
append `~` only "if there is room in the label."
