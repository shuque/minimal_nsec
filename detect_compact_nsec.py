#!/usr/bin/env python3

"""
Detect whether a DNS zone uses Compact Denial of Existence (RFC 9824).

Identifies the key CDoE signals:
  - NOERROR rcode for nonexistent names (instead of NXDOMAIN)
  - NSEC owner = qname, next = \\000.qname
  - TYPE128 (NXNAME) in the NSEC type bitmap
  - Apex NODATA uses the same NSEC pattern but without NXNAME

By default, uses the local system resolver. Use --doh to query via
DNS-over-HTTPS to Cloudflare (or a custom server with --doh-server).
"""

import sys
import string
import random
import argparse

import dns.name
import dns.query
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.flags

DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"

NXNAME_RRTYPE = 128


def query_dns(qname, rdtype, doh_url=None, resolver_ip=None):
    """Send a DNS query and return the response."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    q.flags |= dns.flags.AD
    if doh_url:
        return dns.query.https(q, doh_url)
    nameserver = resolver_ip or dns.resolver.Resolver().nameservers[0]
    return dns.query.udp(q, nameserver)


def random_label(length=10):
    """Generate a random lowercase label unlikely to exist."""
    return ''.join(random.choice(string.ascii_lowercase)
                   for _ in range(length))


def get_nsec_types(rdata):
    """Extract the set of RR type numbers from an NSEC rdata's bitmap."""
    types = set()
    for window, bitmap in rdata.windows:
        for i, byte_val in enumerate(bitmap):
            for bit in range(8):
                if byte_val & (0x80 >> bit):
                    types.add(window * 256 + i * 8 + bit)
    return types


def format_types(types):
    """Format a set of RR type numbers as a human-readable string."""
    parts = []
    for t in sorted(types):
        try:
            parts.append(dns.rdatatype.to_text(t))
        except Exception:
            parts.append(f"TYPE{t}")
    return ' '.join(parts)


def expected_cdoe_next(name):
    """Return the expected CDoE NSEC next name: \\000 prepended to name."""
    return dns.name.Name((b'\x00',) + name.labels)


def check_cdoe_nsec(name, rrset, rdata):
    """
    Check if an NSEC record matches the CDoE pattern for a given name:
      owner = name, next = \\000.name
    Returns (matches_pattern, has_nxname, types).
    """
    if rrset.name != name:
        return False, False, set()

    types = get_nsec_types(rdata)

    if rdata.next != expected_cdoe_next(name):
        return False, False, types

    return True, NXNAME_RRTYPE in types, types


def check_dnssec_enabled(zone_name, doh_url, resolver_ip=None):
    """Verify the zone has DNSSEC by looking for RRSIG in a SOA response."""
    response = query_dns(zone_name, "SOA", doh_url, resolver_ip)
    if response.rcode() != dns.rcode.NOERROR:
        return False, "SOA query failed"
    has_rrsig = any(
        rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer
    )
    if not has_rrsig:
        return False, "No RRSIG in SOA response"
    return True, "DNSSEC enabled"


def check_for_nsec3(zone_name, doh_url, resolver_ip=None):
    """Check if the zone uses NSEC3 instead of NSEC."""
    test_name = dns.name.from_text(f"{random_label()}.{zone_name}")
    response = query_dns(test_name, "A", doh_url, resolver_ip)
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC3:
            return True
    return False


def probe_nxdomain(zone_name, doh_url, num_queries=5, verbose=False,
                   nxname_parent=None, resolver_ip=None):
    """
    Query for random nonexistent names and check for the CDoE pattern:
    NOERROR rcode, NSEC owner = qname, next = \\000.qname.

    Tracks both the structural pattern match and the NXNAME (TYPE128)
    signal separately.

    If nxname_parent is set, random labels are appended under that name
    instead of the zone apex — useful for zones with apex wildcards.

    Returns (pattern_matches, nxname_matches, total_usable, details,
             has_wildcard).
    """
    pattern_matches = 0
    nxname_matches = 0
    total_usable = 0
    details = []
    has_wildcard = False

    parent = nxname_parent or zone_name

    for i in range(num_queries):
        label = random_label(8 + i)
        qname = dns.name.from_text(f"{label}.{parent}")
        response = query_dns(qname, "A", doh_url, resolver_ip)
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR and len(response.answer) > 0:
            has_wildcard = True
            if verbose:
                details.append(
                    f"  {qname}: wildcard-synthesized answer (skipping)")
            continue

        if rcode == dns.rcode.NXDOMAIN:
            total_usable += 1
            if verbose:
                details.append(f"  {qname}: NXDOMAIN rcode (not CDoE)")
            continue

        if rcode != dns.rcode.NOERROR:
            if verbose:
                details.append(
                    f"  {qname}: rcode {dns.rcode.to_text(rcode)}")
            continue

        total_usable += 1
        found_pattern = False
        found_nxname = False

        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.NSEC:
                continue
            for rdata in rrset:
                matches, has_nxname, types = check_cdoe_nsec(
                    qname, rrset, rdata)
                if matches:
                    found_pattern = True
                    if has_nxname:
                        found_nxname = True
                    if verbose:
                        tag = "NXNAME" if has_nxname else "no NXNAME"
                        details.append(
                            f"  {qname}: NOERROR, "
                            f"NSEC {rrset.name} -> {rdata.next} "
                            f"[{format_types(types)}] -- {tag}")
                elif verbose and rrset.name.is_subdomain(zone_name):
                    details.append(
                        f"  {qname}: NOERROR, "
                        f"NSEC {rrset.name} -> {rdata.next} "
                        f"(no CDoE match)")

        if found_pattern:
            pattern_matches += 1
        if found_nxname:
            nxname_matches += 1
        if not found_pattern and verbose:
            if not any("NSEC" in d for d in details[-1:]):
                details.append(f"  {qname}: NOERROR, no matching NSEC")

    return pattern_matches, nxname_matches, total_usable, details, has_wildcard


def probe_nodata(zone_name, doh_url, verbose=False, resolver_ip=None):
    """
    Check apex NODATA: query zone apex for a type unlikely to exist (LOC).
    CDoE zones return NSEC: apex -> \\000.apex with the real type bitmap
    (no NXNAME, since the apex exists).

    Returns (is_cdoe, detail_string).
    """
    response = query_dns(zone_name, "LOC", doh_url, resolver_ip)
    rcode = response.rcode()

    if rcode != dns.rcode.NOERROR:
        return False, f"unexpected rcode {dns.rcode.to_text(rcode)}"

    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC:
            continue
        for rdata in rrset:
            matches, has_nxname, types = check_cdoe_nsec(
                zone_name, rrset, rdata)
            if matches and not has_nxname:
                return True, (
                    f"{rrset.name} -> {rdata.next} "
                    f"[{format_types(types)}]")
            elif matches and has_nxname:
                return False, (
                    f"{rrset.name} -> {rdata.next} "
                    f"has NXNAME at apex (unexpected)")

    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            for rdata in rrset:
                return False, (
                    f"NSEC {rrset.name} -> {rdata.next} "
                    f"(not CDoE pattern)")

    return False, "no NSEC records in NODATA response"


def detect(zone_str, doh_url=None, num_queries=5, verbose=False,
           nxname_parent=None, resolver_ip=None):
    """
    Main detection routine.
    Returns True (detected), False (not detected), or None (inconclusive).
    """
    zone_name = dns.name.from_text(zone_str)
    print(f"\nAnalyzing zone: {zone_name}")
    print("=" * 60)

    print("\n[1] Checking DNSSEC...")
    enabled, msg = check_dnssec_enabled(zone_name, doh_url, resolver_ip)
    print(f"    {msg}")
    if not enabled:
        print("\nResult: INCONCLUSIVE -- DNSSEC not available")
        return None

    print("\n[2] Checking denial-of-existence method...")
    if check_for_nsec3(zone_name, doh_url, resolver_ip):
        print("    Zone uses NSEC3")
        print("\nResult: NOT CDoE (zone uses NSEC3)")
        return False
    print("    Zone uses NSEC")

    nxparent = None
    if nxname_parent:
        nxparent = dns.name.from_text(nxname_parent)

    if nxparent:
        print(f"\n[3] Probing for CDoE pattern under {nxparent} ...")
    else:
        print("\n[3] Probing for CDoE pattern (nonexistent names)...")
    pattern, nxname, total, details, has_wildcard = probe_nxdomain(
        zone_name, doh_url, num_queries, verbose, nxparent, resolver_ip)
    for d in details:
        print(d)
    if has_wildcard and total == 0 and not nxparent:
        print("    Zone has apex wildcard -- all queries synthesized")
    elif total > 0:
        print(f"    CDoE pattern:  {pattern}/{total}")
        print(f"    With NXNAME:   {nxname}/{total}")

    print("\n[4] Checking apex NODATA...")
    nodata_cdoe, nodata_msg = probe_nodata(zone_name, doh_url, verbose,
                                              resolver_ip)
    print(f"    {nodata_msg}")

    print(f"\n{'=' * 60}")
    if total > 0:
        pattern_str = f"{pattern}/{total}"
        nxname_str = f"{nxname}/{total}"
    else:
        pattern_str = "N/A (wildcard)"
        nxname_str = "N/A (wildcard)"
    nodata_str = "YES" if nodata_cdoe else "NO"
    print(f"  CDoE pattern:       {pattern_str}")
    print(f"  NXNAME signal:      {nxname_str}")
    print(f"  Apex NODATA CDoE:   {nodata_str}")

    if total > 0 and pattern == total and nxname == total and nodata_cdoe:
        print("\nResult: DETECTED -- "
              "Compact Denial of Existence (RFC 9824) with NXNAME")
        return True
    elif total > 0 and pattern == total and nxname == total:
        print("\nResult: LIKELY -- "
              "CDoE with NXNAME (apex NODATA inconclusive)")
        return True
    elif total > 0 and pattern == total and nodata_cdoe:
        print("\nResult: DETECTED -- "
              "Compact Denial of Existence (RFC 9824) without NXNAME")
        return True
    elif total > 0 and pattern == total:
        print("\nResult: LIKELY -- "
              "CDoE pattern without NXNAME")
        return True
    elif nodata_cdoe and (total == 0 or pattern > 0):
        print("\nResult: LIKELY -- "
              "apex NODATA matches CDoE pattern")
        return True
    elif pattern > 0:
        print(f"\nResult: POSSIBLY -- "
              f"partial CDoE pattern ({pattern}/{total})")
        return None
    else:
        print("\nResult: NOT DETECTED")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Detect Compact Denial of Existence (RFC 9824)")
    parser.add_argument("zones", nargs='*',
                        help="DNS zone name(s) to analyze")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="Read zone names from file (one per line)")
    parser.add_argument("-n", "--num-queries", type=int, default=5,
                        help="Number of probe queries (default: 5)")
    parser.add_argument("--known-nxd", metavar="NAME",
                        help="Known nonexistent name to probe under "
                        "(bypasses apex wildcard)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show per-query details")
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("--doh", action="store_true",
                           help="Use DNS-over-HTTPS (default: Cloudflare)")
    transport.add_argument("--doh-server", metavar="URL",
                           help="DoH server URL (implies --doh)")
    transport.add_argument("--resolver", metavar="IP",
                           help="Use this resolver IP address instead of system default")
    args = parser.parse_args()

    doh_url = None
    resolver_ip = None
    if args.doh or args.doh_server:
        doh_url = args.doh_server or DEFAULT_DOH_URL
    elif args.resolver:
        resolver_ip = args.resolver

    zones = list(args.zones)
    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    zones.append(line)

    if not zones:
        parser.error("no zones specified (use positional args or -f FILE)")

    for zone in zones:
        if not zone.endswith('.'):
            zone += '.'
        nxname = args.known_nxd
        if nxname and not nxname.endswith('.'):
            nxname += '.'
        try:
            detect(zone, doh_url, args.num_queries, args.verbose, nxname,
                   resolver_ip)
        except Exception as e:
            print(f"\nError analyzing {zone}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
