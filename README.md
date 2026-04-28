# Minimally Covering NSEC Records

This project investigates minimally covering NSEC records (RFC 4470) —
also known as "white lies" — as deployed by commercial DNS providers.
The work includes reverse-engineering UltraDNS's specific epsilon
function implementation, developing a generalized approach to detect
minimally covering NSEC records from any provider, detecting Compact
Denial of Existence (RFC 9824), and classifying NSEC3 zones as
traditional (pre-computed) or white lies (RFC 7129).

## Background

DNSSEC authenticated denial of existence uses NSEC (or NSEC3) records
to prove that a queried name does not exist. In a traditional
pre-signed zone, the NSEC chain reveals all names in the zone, enabling
zone enumeration. Minimally covering NSEC records (RFC 4470) address
this by having an online signer dynamically generate NSEC records that
bracket only the queried name, using an "epsilon function" to compute
predecessor and successor names just before and after the query.

## UltraDNS Analysis

Detailed reverse engineering of UltraDNS's epsilon function, based on
empirical queries against test zones `ultratest.huque.com` and
`ultratest2.huque.com`.

- [UltraDNS.md](UltraDNS.md) — Full analysis: character alphabet
  (40 characters), successor function (`qname + '!'`), predecessor
  function (decrement last character, append `~`, prepend `~` child
  labels), variable-depth predecessor (depth = subtree height of
  nearest preceding name), wildcard handling, and special cases for
  the zone apex and empty non-terminals.

- [data/query\_results\_ultradns.txt](data/query_results_ultradns.txt) —
  Raw query data from both test zones.

### UltraDNS Detector

[detect\_ultradns\_nsec.py](detect_ultradns_nsec.py) — Detects
UltraDNS-style minimally covering NSEC records in a given zone by
probing with random queries and checking for the specific UltraDNS
predecessor/successor patterns.

```
./detect_ultradns_nsec.py [--doh] [--doh-server URL] [-v] ZONE
```

## Generalized Minimal NSEC Detection

A provider-agnostic approach to detecting minimally covering NSEC
records, based on measuring the prefix similarity between NSEC record
labels and the query name that produced them.

- [Minimal.md](Minimal.md) — Problem statement, approaches considered
  (canonical sort key distance, label-level distance), why raw distance
  metrics fail due to DNS tree structure, and the prefix similarity
  method that provides definitive separation between epsilon and static
  NSEC zones.

### General Detector

[detect\_minimal\_nsec.py](detect_minimal_nsec.py) — Detects minimally
covering NSEC records from any provider without knowledge of the
specific epsilon algorithm.

```
# Probe a zone automatically
./detect_minimal_nsec.py probe [--doh] [--doh-server URL] [-n NUM] ZONE

# Analyze a specific NSEC pair
./detect_minimal_nsec.py calc ZONE OWNER NEXT --qname QNAME
```

## Compact Denial of Existence (RFC 9824)

Compact Denial of Existence is a different approach to authenticated
denial in DNSSEC. Instead of generating epsilon predecessor/successor
names, the server returns NOERROR (rather than NXDOMAIN) for
nonexistent names, with an NSEC record of the form
`qname NSEC \000.qname`. This single NSEC covers only the queried
name, without revealing any other names in the zone. Implementations
that fully support RFC 9824 include the NXNAME meta-type (TYPE128) in
the NSEC type bitmap to signal that the name does not exist; some
implementations omit NXNAME.

### CDoE Detector

[detect\_compact\_nsec.py](detect_compact_nsec.py) — Detects Compact
Denial of Existence by probing for the CDoE NSEC pattern and checking
for the NXNAME signal. Tested against Cloudflare, NS1 (both with
NXNAME), and AWS Route53 (without NXNAME).

```
# Probe one or more zones
./detect_compact_nsec.py [--doh] [-v] [-n NUM] ZONE [ZONE ...]

# Read zones from a file
./detect_compact_nsec.py [--doh] [-v] -f FILE

# Bypass apex wildcard by probing under a known nonexistent name
./detect_compact_nsec.py [--doh] [-v] --known-nxd NAME ZONE
```

## NSEC3 Detection (RFC 5155 / RFC 7129 / RFC 9824)

Detects whether a zone uses traditional (pre-computed) NSEC3, NSEC3
White Lies (online-signed, RFC 7129 Appendix B), or Compact Denial of
Existence with NSEC3 (RFC 9824 Section 4).

**Traditional vs White Lies**: Probes the zone with random nonexistent
names, computes expected NSEC3 hashes using `dns.dnssec.nsec3_hash()`,
and measures the gap between NSEC3 owner and next hashed owner. White
lies produce a gap of exactly 2 (H-1 to H+1) for covering records and
1 for the closest encloser match; pre-computed chains produce gaps
proportional to 1/N of the hash space (typically 0.1%–1.7%). The
detector analyzes all three closest-encloser-proof roles: next closer
name (NCN) cover, closest encloser (CE) match, and wildcard (WC) cover.

**Compact Denial of Existence with NSEC3**: Detected when probes
return NOERROR with no answer data (NODATA) and the NSEC3 type bitmap
is minimal — empty, or containing only NXNAME (TYPE128). Reports
whether NXNAME is present.

**Salt rotation handling**: NSEC3 parameters (salt, iterations) are
extracted from the NSEC3 records in each individual response, not from
the NSEC3PARAM RR, which can be stale or absent with online signers.

**Wildcard zones**: Wildcard-synthesized NOERROR responses include an
NSEC3 record in the authority section covering the next closer name;
the detector extracts and analyzes these.

### NSEC3 Detector

[detect\_nsec3.py](detect_nsec3.py) — Detects traditional NSEC3,
NSEC3 white lies, and CDoE/NSEC3 with hash gap analysis. Tested
against huque.com (traditional, BIND 9), naomi.huque.com (white lies),
noire.huque.com (CDoE/NSEC3 with NXNAME), and third-party zones with
rotating salts and wildcards.

```
# Probe one or more zones
./detect_nsec3.py [--doh] [-v] [-n NUM] ZONE [ZONE ...]

# Read zones from a file
./detect_nsec3.py [--doh] [-v] -f FILE

# Relaxed white lies detection (allow gap up to 2*N for covers)
./detect_nsec3.py [--doh] --epsilon N ZONE
```

## Dependencies

- Python 3
- [dnspython](https://www.dnspython.org/) (`pip install dnspython`)
- For DoH support: `pip install dnspython[doh]`
