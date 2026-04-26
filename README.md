# Minimally Covering NSEC Records

This project investigates minimally covering NSEC records (RFC 4470) —
also known as "white lies" — as deployed by commercial DNS providers.
The work includes reverse-engineering UltraDNS's specific epsilon
function implementation, and developing a generalized approach to
detect minimally covering NSEC records from any provider.

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

## Utilities

- [sortdomainnames.py](sortdomainnames.py) — Sort domain names in DNS
  canonical order (RFC 4034 Section 6.1). Reads from a file, stdin, or
  command-line arguments (`-a`).

## Zone Data

- [zone.ultratest.txt](zone.ultratest.txt) — UltraDNS test zone with
  various name types (leaves, ENT, wildcard under subdomain).
- [zone.ultratest2.txt](zone.ultratest2.txt) — UltraDNS test zone with
  deeper hierarchy and apex wildcard, used to verify variable-depth
  predecessor behavior.
- [zone.nseczone.huque.com.txt](zone.nseczone.huque.com.txt) — Static
  NSEC zone used as a control for testing the generalized detector.

## Dependencies

- Python 3
- [dnspython](https://www.dnspython.org/) (`pip install dnspython`)
- For DoH support: `pip install dnspython[doh]`
