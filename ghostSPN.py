#!/usr/bin/env python3
from __future__ import annotations
import math
import os
import ipaddress
import argparse
import csv
import json
import re
import socket
import ssl
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set
from datetime import datetime, timedelta

from ldap3 import Server, Connection, ALL, NTLM, Tls, SUBTREE
from ldap3.utils.conv import escape_filter_chars
from tabulate import tabulate

COLOR_RESET = '\033[0m'
COLOR_HIGH = '\033[91m'
COLOR_MEDIUM = '\033[93m'
COLOR_LOW = '\033[94m'
COLOR_SELF = '\033[92m'
COLOR_EXCLUDED = '\033[90m'


def colorize(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    color_map = {
        'HIGH': COLOR_HIGH,
        'MEDIUM': COLOR_MEDIUM,
        'LOW': COLOR_LOW,
        'SELF': COLOR_SELF,
        'EXCLUDED': COLOR_EXCLUDED
    }
    color = color_map.get(severity, '')
    if not color:
        return text
    return f"{color}{text}{COLOR_RESET}"

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class tqdm:
        def __init__(self, iterable=None, total=None, desc=None, **kwargs):
            self.iterable = iterable
            self.total = total or (len(iterable) if iterable else 0)
            self.desc = desc or ""
            self.n = 0
        
        def __iter__(self):
            for item in self.iterable:
                yield item
                self.update(1)
        
        def update(self, n=1):
            self.n += n
            if self.total > 0:
                pct = (self.n / self.total) * 100
                print(f"\r{self.desc}: {self.n}/{self.total} ({pct:.1f}%)", end='', flush=True)
        
        def close(self):
            print()

try:
    import dns.resolver  # type: ignore
    HAS_DNSPYTHON = True
except ImportError:
    dns = None  # type: ignore
    HAS_DNSPYTHON = False

DNSPYTHON_WARNING_EMITTED = False

SPN_HOST_RE = re.compile(r'^[^/]+/([^/:]+)', re.IGNORECASE)

HIGH_RISK_SPNS = [
    'HTTP', 'HTTPS',
    'MSSQL', 'MSSQLSvc',
    'TERMSRV',
    'WSMAN',
    'HOST',
    'RestrictedKrbHost',
    'DNS',
    'FTP',
    'IMAP', 'POP', 'SMTP',
    'LDAP'
]

EXCLUDE_SPN_PATTERNS = [
    r'\.windows\.net$',
    r'\.onmicrosoft\.com$',
    r'\.nsatc\.net$',
    r'^aadg\.',
]

EXCLUDE_PATTERNS = [
    r'^dc\d*\.',
    r'^adfs\.',
    r'^exchange\.',
    r'^\w+\.microsoft\.com$',
]

# GUID pattern: 8-4-4-4-12 hexadecimal characters with dashes
# Also matches variants without dashes (32 hex chars) or with different separators
GUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
# Matches 32 hexadecimal characters (GUID without dashes)
GUID_NO_DASHES_RE = re.compile(r'^[0-9a-f]{32}$', re.IGNORECASE)


def is_guid_like(s: str) -> bool:
    """Check if a string looks like a GUID/UUID."""
    if not s or len(s) < 32:
        return False
    # Check standard GUID format (with dashes)
    if GUID_RE.match(s):
        return True
    # Check GUID without dashes
    if GUID_NO_DASHES_RE.match(s):
        return True
    return False


def is_microsoft_guid_path(spn: str, hostname: str) -> bool:
    """
    Detect Microsoft internal GUID paths like:
    E3514235-4B06-11D1-AB04-00C04FC2DCD2/0cc5fcab-58a4-4a38-9a25-b51bf21c4bb4/example.com
    
    These are AD forest/domain identifiers, not exploitable DNS entries.
    """
    # Primary check: if the extracted hostname itself is a GUID, it's definitely a GUID path
    if is_guid_like(hostname):
        return True
    
    # Detect GUID-based hostnames used for Microsoft DNS (e.g., GUID._msdcs.domain)
    hostname_lower = hostname.lower()
    if '._msdcs.' in hostname_lower:
        first_label = hostname_lower.split('.')[0]
        if is_guid_like(first_label):
            return True
    
    # Secondary check: detect GUID path structure in the SPN
    # Microsoft GUID paths typically have: GUID-SERVICE-NAME/GUID-PATH-SEGMENT/...
    parts = spn.split('/')
    if len(parts) < 2:
        return False
    
    # Check if the service name (first part) is a GUID
    # This indicates a Microsoft GUID-based SPN structure
    service_name = parts[0].split(':')[0]  # Remove port if present
    if is_guid_like(service_name):
        # If service name is a GUID and we have multiple path segments,
        # and the extracted hostname (which comes from parts[1]) is also a GUID,
        # this is a Microsoft GUID path
        if len(parts) > 2:
            hostname_part = parts[1].split(':')[0]  # Remove port if present
            if is_guid_like(hostname_part):
                return True
    
    # Additional check: if the hostname doesn't look like a valid domain/hostname
    # (no dots, not alphanumeric with hyphens) and the SPN path contains GUID segments,
    # it's likely part of a GUID path structure
    # Only apply this if hostname looks suspicious (no dots, just hex-like chars)
    if '.' not in hostname:
        guid_in_path = False
        for part in parts[1:]:  # Check all path segments after service name
            part_without_port = part.split(':')[0]
            if is_guid_like(part_without_port):
                guid_in_path = True
                break
        # If we found GUID segments and hostname has no dots (not a real domain),
        # and hostname itself could be part of the GUID path
        if guid_in_path and len(hostname) >= 32:
            # Hostname is long enough to be a GUID and path contains GUIDs
            return True
    
    return False


def parse_args():
    p = argparse.ArgumentParser(
        description="Find ghost SPNs in Active Directory (optimized)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    required = p.add_argument_group("Required Connection")
    required.add_argument('--server', required=True, help='LDAP server host or IP')
    required.add_argument('--domain', required=True, help='Target domain')
    required.add_argument('--username', required=True, help='DOMAIN\\user or user@domain')
    required.add_argument('--password', required=True, help='Password')

    retrieval = p.add_argument_group("Discovery & Filtering")
    retrieval.add_argument('--port', type=int, help='LDAP port (default 389 or 636 if --use-ssl)')
    retrieval.add_argument('--use-ssl', action='store_true', help='Use LDAPS (TLS)')
    retrieval.add_argument('--no-verify', action='store_true', help='Do not verify LDAP SSL cert')
    retrieval.add_argument('--base-dn', help='Base DN (defaults to domain-derived DN)')
    retrieval.add_argument('--svc', dest='svc_filter', help='Filter by SPN service type')
    retrieval.add_argument('--filter', dest='ldap_filter', help='Custom LDAP filter')
    retrieval.add_argument('--limit', type=int, help='Limit number of SPNs processed')
    retrieval.add_argument('--page-size', type=int, default=1000, help='LDAP page size')
    retrieval.add_argument('--high-risk-only', action='store_true', help='Only scan high-risk SPN types')
    retrieval.add_argument('--user-accounts-only', action='store_true', help='Only check user accounts')
    retrieval.add_argument('--quick-mode', action='store_true', help='Enable all optimizations')
    retrieval.add_argument('--no-default-excludes', action='store_true',
                           help='Do not filter out default Microsoft hosts (dc*, adfs, exchange, etc.)')

    analysis = p.add_argument_group("Analysis & Output")
    analysis.add_argument('--check-dns', action='store_true', help='Enable DNS resolution checks')
    analysis.add_argument('--nameserver', '--ns', dest='nameserver',
                          help='DNS server for --check-dns (default: domain controller IP)')
    analysis.add_argument('--threads', type=int, default=50, help='Parallel DNS lookup threads')
    analysis.add_argument('--timeout', type=float, default=2.0, help='DNS lookup timeout')
    analysis.add_argument('--cache-file', help='Cache file for known-good hosts')
    analysis.add_argument('--cache-ttl', type=int, default=7, help='Days to cache')
    analysis.add_argument('--output', help='Output file (.csv or .json)')
    analysis.add_argument('--show-duplicates', action='store_true', help='Show duplicate SPNs')
    analysis.add_argument('--ad-chunk-size', type=int, default=50,
                          help='Hosts per LDAP lookup batch for AD correlation')
    analysis.add_argument('--ad-confirm-threshold', type=int, default=5000,
                          help='Ask before AD lookups when host count exceeds this')
    analysis.add_argument('--skip-ad-confirm', action='store_true',
                          help='Skip confirmation even when host count exceeds threshold')
    analysis.add_argument('--ad-batch-seconds', type=float, default=2.0,
                          help='Estimated seconds per LDAP batch (for confirmation prompt)')
    p.epilog = """
EXAMPLES
========
Basic (LDAP/NTLM)
  python3 ghostSPN.py --server DC01 --domain corp.local --username corp\\admin --password Pass123

LDAPS with Channel Binding (UPN)
  python3 ghostSPN.py --server dc01.corp.local --use-ssl --username admin@corp.local --password Pass123 --no-verify
    (UPN format required when LDAPS channel binding is enforced)

Filter to Specific Services
  python3 ghostSPN.py --server DC01 --domain corp.local --username corp\\admin --password Pass123 --svc HTTP,MSSQL,DNS

Quick Mode with DNS Checks
  python3 ghostSPN.py --server DC01 --domain corp.local --username corp\\admin --password Pass123 --quick-mode --check-dns

COMMON SPN TYPES
================
HTTP, HTTPS, MSSQL, MSSQLSvc, TERMSRV, WSMAN, HOST, RestrictedKrbHost,
DNS, FTP, IMAP, POP, SMTP, LDAP
    """.strip()
    
    return p.parse_args()


def build_base_dn(domain: str) -> str:
    return ','.join(f'dc={p}' for p in domain.split('.'))


def format_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {int(secs)}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m"


def normalize_nameserver(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        try:
            return socket.gethostbyname(candidate)
        except (socket.gaierror, OSError):
            return None


def should_exclude_host(hostname: str, domain: str | None = None) -> bool:
    hostname_lower = hostname.lower()
    domain_lower = domain.lower() if domain else None
    for pattern in EXCLUDE_PATTERNS:
        if pattern == r'^dc\d*\.' and domain_lower and hostname_lower.endswith(domain_lower):
            continue
        if re.match(pattern, hostname_lower, re.IGNORECASE):
            return True
    return False


def load_host_cache(cache_file: str, ttl_days: int) -> Dict[str, bool]:
    if not cache_file or not os.path.exists(cache_file):
        return {}
    
    try:
        with open(cache_file, 'r') as f:
            cache = json.load(f)
        
        cutoff = (datetime.now() - timedelta(days=ttl_days)).isoformat()
        valid_cache = {
            host: data for host, data in cache.items()
            if data.get('timestamp', '0') > cutoff and data.get('resolved', False)
        }
        print(f"[+] Loaded {len(valid_cache)} valid entries from cache")
        return {host: data['resolved'] for host, data in valid_cache.items()}
    except Exception as e:
        print(f"[!] Error loading cache: {e}")
        return {}


def save_host_cache(cache_file: str, dns_results: Dict[str, bool]):
    if not cache_file:
        return
    
    try:
        existing = {}
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                existing = json.load(f)
        
        timestamp = datetime.now().isoformat()
        for host, resolved in dns_results.items():
            if resolved:
                existing[host] = {
                    'resolved': resolved,
                    'timestamp': timestamp
                }
        
        with open(cache_file, 'w') as f:
            json.dump(existing, f, indent=2)
        print(f"[+] Saved {len(existing)} entries to cache")
    except Exception as e:
        print(f"[!] Error saving cache: {e}")


def hostname_resolves(host: str, timeout: float, nameserver: str | None = None) -> bool:
    global DNSPYTHON_WARNING_EMITTED
    if nameserver and HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver(configure=True)  # type: ignore[attr-defined]
        resolver.nameservers = [nameserver]
        resolver.lifetime = timeout
        resolver.timeout = timeout
        try:
            answers = resolver.resolve(host)
            return bool(answers)
        except Exception:
            return False
    if nameserver and not HAS_DNSPYTHON and not DNSPYTHON_WARNING_EMITTED:
        print("[!] dnspython not available; falling back to system resolver (nameserver override ignored)")
        DNSPYTHON_WARNING_EMITTED = True
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(host, None)
            return len(infos) > 0
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        return False


def _choose_tls_version():
    if hasattr(ssl, 'PROTOCOL_TLS_CLIENT'):
        return ssl.PROTOCOL_TLSv1_2
    if getattr(ssl, 'PROTOCOL_TLSv1_3', None):
        return ssl.PROTOCOL_TLSv1_3
    return ssl.PROTOCOL_TLSv1_2


def connect_ldap(server_host: str, port: int, use_ssl: bool, no_verify: bool,
                 username: str, password: str, ca_certs_file: str = None,
                 bind_timeout: int = 30) -> Connection:
    ca_from_env = os.environ.get('LDAP_CA_FILE')
    ca_file = ca_certs_file or ca_from_env or (
        "/etc/ssl/certs/ca-certificates.crt" if os.path.exists("/etc/ssl/certs/ca-certificates.crt") else None
    )
    
    version = _choose_tls_version()
    
    is_ip = False
    try:
        ipaddress.ip_address(server_host)
        is_ip = True
    except Exception:
        pass
    
    if use_ssl:
        if no_verify:
            tls = Tls(validate=ssl.CERT_NONE, version=version)
        else:
            if ca_file:
                tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file, version=version)
            else:
                tls = Tls(validate=ssl.CERT_REQUIRED, version=version)
        
        if is_ip and not no_verify:
            raise ValueError("Server is an IP address with cert verification enabled. Use FQDN or --no-verify")
    else:
        tls = None
    
    srv = Server(server_host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)
    
    if '\\' in username:
        conn = Connection(srv, user=username, password=password, 
                         authentication=NTLM, receive_timeout=bind_timeout)
    else:
        conn = Connection(srv, user=username, password=password, 
                         receive_timeout=bind_timeout)
    
    try:
        bound = conn.bind()
    except ssl.SSLError as ssl_err:
        raise RuntimeError(f"SSL/TLS handshake failed: {ssl_err}") from ssl_err
    except Exception as e:
        raise RuntimeError(f"LDAP bind failed: {e}") from e
    
    if not bound:
        raise RuntimeError(f"LDAP bind failed: {conn.last_error} (result: {conn.result})")
    
    return conn


def paged_search_entries(conn: Connection, base_dn: str, search_filter: str,
                        attributes: List[str], page_size: int, max_entries: int = None):
    count = 0
    for entry in conn.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=attributes,
        paged_size=page_size,
        generator=True
    ):
        if entry.get('type') != 'searchResEntry':
            continue
        yield entry
        count += 1
        if max_entries and count >= max_entries:
            break


def build_optimized_filter(args) -> str:
    if args.ldap_filter:
        return args.ldap_filter
    
    filters = []
    filters.append("(servicePrincipalName=*)")
    
    if args.svc_filter:
        svc_types = [s.strip().upper() for s in args.svc_filter.split(',')]
        spn_filters = [f"(servicePrincipalName={svc}*)" for svc in svc_types]
        if len(spn_filters) == 1:
            filters.append(spn_filters[0])
        else:
            filters.append("(|" + "".join(spn_filters) + ")")
    
    if args.user_accounts_only or args.quick_mode:
        filters.append("(!(objectClass=computer))")
        filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=8192))")
    
    if args.high_risk_only or (args.quick_mode and not args.svc_filter):
        spn_filters = [f"(servicePrincipalName={svc}*)" for svc in HIGH_RISK_SPNS]
        filters.append("(|" + "".join(spn_filters) + ")")
    
    if len(filters) == 1:
        return filters[0]
    else:
        return "(&" + "".join(filters) + ")"


def enumerate_spns(conn: Connection, base_dn: str, page_size: int,
                   search_filter: str, limit: int = None,
                   apply_default_excludes: bool = True,
                   domain: str | None = None) -> List[Dict]:
    results = []
    attributes = ['servicePrincipalName', 'sAMAccountName', 'distinguishedName', 
                  'objectClass', 'userAccountControl', 'dNSHostName', 'lastLogonTimestamp', 'lastLogon']
    
    spn_count = 0
    for entry in paged_search_entries(conn, base_dn, search_filter, attributes, 
                                     page_size, max_entries=None):
        attrs = entry.get('attributes', {})
        spns = attrs.get('servicePrincipalName') or []
        obj_class = attrs.get('objectClass', [])
        
        # Convert Windows FILETIME to readable format
        def convert_filetime(filetime_value):
            if not filetime_value:
                return 'N/A'
            # ldap3 may return single values, lists, or datetime objects depending on schema info
            if isinstance(filetime_value, (list, tuple)):
                for val in filetime_value:
                    converted = convert_filetime(val)
                    if converted != 'N/A':
                        return converted
                return 'N/A'
            if isinstance(filetime_value, datetime):
                return filetime_value.strftime('%Y-%m-%d %H:%M:%S')
            if isinstance(filetime_value, str):
                generalized = filetime_value.rstrip('Z')
                generalized = generalized.split('.')[0]
                if generalized.isdigit() and len(generalized) > 14:
                    try:
                        filetime_value = int(generalized)
                    except (ValueError, TypeError):
                        pass
                else:
                    try:
                        dt = datetime.strptime(generalized, '%Y%m%d%H%M%S')
                        return dt.strftime('%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        try:
                            filetime_value = int(filetime_value)
                        except (ValueError, TypeError):
                            return 'N/A'
            try:
                timestamp = int(filetime_value)
                if timestamp == 0:
                    return 'Never'
                unix_timestamp = (timestamp - 116444736000000000) / 10000000
                return datetime.fromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError, OSError):
                return 'N/A'
        
        # Try lastLogonTimestamp first (replicated across DCs), then lastLogon (not replicated)
        last_logon_raw = attrs.get('lastLogonTimestamp') or attrs.get('lastLogon')
        last_logon = convert_filetime(last_logon_raw)
        
        for spn in spns:
            m = SPN_HOST_RE.match(spn)
            if m:
                host = m.group(1).lower()
                
                # Filter out Microsoft GUID paths (AD forest/domain identifiers)
                if is_microsoft_guid_path(spn, host):
                    continue
                
                if apply_default_excludes and should_exclude_host(host, domain):
                    continue
                
                results.append({
                    'spn': spn,
                    'hostname': host,
                    'account_dn': entry.get('dn'),
                    'account_sam': attrs.get('sAMAccountName'),
                    'account_dns': (attrs.get('dNSHostName') or '').lower(),
                    'is_computer': 'computer' in [c.lower() for c in obj_class],
                    'last_logon': last_logon
                })
                spn_count += 1
                if limit and spn_count >= limit:
                    return results
    
    return results


def _chunk_hosts(hosts: List[str], chunk_size: int):
    for i in range(0, len(hosts), chunk_size):
        yield hosts[i:i + chunk_size]


def batch_find_computers_for_hosts(conn: Connection, base_dn: str,
                                   hosts: List[str], page_size: int,
                                   search_timeout: int = 30,
                                   chunk_size: int = 50) -> Dict[str, List[Dict]]:
    found = {h: [] for h in hosts}
    if not hosts:
        return found

    attrs = ['distinguishedName', 'dNSHostName', 'sAMAccountName', 'cn']
    chunk_size = max(1, chunk_size)
    total_chunks = (len(hosts) + chunk_size - 1) // chunk_size
    chunk_iter = _chunk_hosts(hosts, chunk_size)

    if HAS_TQDM and total_chunks > 0:
        chunk_iter = tqdm(chunk_iter, total=total_chunks, desc="Checking hosts in AD", unit="batch")

    else:
        chunks_processed = 0

    for chunk in chunk_iter:
        filter_terms = set()
        variant_map = defaultdict(set)

        for host in chunk:
            host_lower = host.lower()
            short = host_lower.split('.')[0]
            short_sam = f"{short}$"

            variant_map[host_lower].add(host)
            variant_map[short].add(host)
            variant_map[short_sam].add(host)

            filter_terms.add(f"(dNSHostName={escape_filter_chars(host_lower)})")
            if short != host_lower:
                filter_terms.add(f"(dNSHostName={escape_filter_chars(short)})")
            filter_terms.add(f"(sAMAccountName={escape_filter_chars(short)})")
            filter_terms.add(f"(sAMAccountName={escape_filter_chars(short_sam)})")
            filter_terms.add(f"(cn={escape_filter_chars(short)})")
            filter_terms.add(f"(cn={escape_filter_chars(short_sam)})")

        if not filter_terms:
            continue

        filter_str = "(|" + "".join(sorted(filter_terms)) + ")"

        try:
            entries = conn.extend.standard.paged_search(
                search_base=base_dn,
                search_filter=filter_str,
                search_scope=SUBTREE,
                attributes=attrs,
                paged_size=page_size,
                generator=True,
                time_limit=search_timeout
            )
        except Exception:
            entries = []

        for entry in entries:
            if entry.get('type') != 'searchResEntry':
                continue

            attrs_e = entry.get('attributes', {})
            match_keys = set()

            dns_host = (attrs_e.get('dNSHostName') or '').lower()
            if dns_host:
                match_keys.add(dns_host)
                match_keys.add(dns_host.split('.')[0])

            sam = (attrs_e.get('sAMAccountName') or '').lower()
            if sam:
                match_keys.add(sam)
                if sam.endswith('$'):
                    match_keys.add(sam[:-1])

            cn = (attrs_e.get('cn') or '').lower()
            if cn:
                match_keys.add(cn)
                if cn.endswith('$'):
                    match_keys.add(cn[:-1])

            for key in match_keys:
                for host in variant_map.get(key, []):
                    existing_dns = {r['dn'] for r in found[host]}
                    if entry.get('dn') in existing_dns:
                        continue
                    found[host].append({
                        'dn': entry.get('dn'),
                        'dNSHostName': (attrs_e.get('dNSHostName') or '').lower(),
                        'sAMAccountName': (attrs_e.get('sAMAccountName') or ''),
                        'cn': (attrs_e.get('cn') or '')
                    })

        if not HAS_TQDM:
            chunks_processed += 1
            if total_chunks <= 20 or chunks_processed % max(total_chunks // 10, 1) == 0 or chunks_processed == total_chunks:
                print(f"\r[+] AD host lookup batches: {chunks_processed}/{total_chunks}", end='', flush=True)

    if not HAS_TQDM and total_chunks:
        print()

    return found


def detect_duplicate_spns(all_spn_entries: List[Dict]) -> Dict[str, List[Dict]]:
    mapping = {}
    for e in all_spn_entries:
        mapping.setdefault(e['spn'], []).append({
            'account_dn': e['account_dn'], 
            'account_sam': e.get('account_sam')
        })
    return {k: v for k, v in mapping.items() if len(v) > 1}


def assess_exploitability(entry: Dict, ad_computer_matches: Dict[str, List[Dict]],
                         dns_results: Dict[str, bool], check_dns_enabled: bool) -> tuple[str, str]:
    is_computer = entry.get('is_computer', False)
    account_dns = (entry.get('account_dns') or '').lower()
    hostname = entry['hostname'].lower()
    account_sam = (entry.get('account_sam') or '').lower()
    
    for pattern in EXCLUDE_SPN_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            return 'EXCLUDED', 'External/cloud infrastructure (Azure, O365, etc)'
    
    def normalize_hostname(h: str) -> tuple[str, str]:
        parts = h.split('.')
        return parts[0].lower(), h.lower()
    
    host_short, host_fqdn = normalize_hostname(hostname)
    
    if not is_computer:
        return 'LOW', 'User account SPNs cannot request service tickets'
    
    if account_dns:
        acct_short, acct_fqdn = normalize_hostname(account_dns)
        if host_short == acct_short or host_fqdn == acct_fqdn:
            return 'SELF', f'Computer points to itself ({account_dns})'
    
    if account_sam and account_sam.endswith('$'):
        acct_short_only = account_sam[:-1].lower()
        if host_short == acct_short_only:
            return 'SELF', 'Computer points to itself (same computer, different alias)'
    
    target_in_ad = bool(ad_computer_matches.get(hostname))
    target_resolves = dns_results.get(hostname) if check_dns_enabled else None
    
    if target_in_ad:
        if check_dns_enabled and target_resolves:
            return 'MEDIUM', 'Target exists in AD and resolves in DNS'
        return 'MEDIUM', 'Target exists in AD'
    
    if check_dns_enabled:
        if target_resolves:
            return 'MEDIUM', 'Target resolves in DNS'
    
    account_display = account_sam.rstrip('$') if account_sam else 'UNKNOWN'
    reason = f'{account_display}$ -> {hostname}'
    if check_dns_enabled and target_resolves is False:
        reason = f'{reason} (DNS unresolved)'
    return 'HIGH', reason


def write_output(path: str, rows: List[Dict]):
    if not rows:
        print("[!] No rows to write")
        return
    
    if path.lower().endswith('.csv'):
        keys = list(rows[0].keys())
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            writer.writerows(rows)
    elif path.lower().endswith('.json'):
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(rows, fh, indent=2)
    else:
        print(f"[!] Unsupported format: {path}")


def main():
    args = parse_args()
    
    if args.quick_mode:
        print("[+] Quick mode enabled - using all optimizations")
        args.high_risk_only = True
        args.user_accounts_only = True
    
    base_dn = args.base_dn or build_base_dn(args.domain)
    port = args.port or (636 if args.use_ssl else 389)
    
    try:
        conn = connect_ldap(args.server, port, args.use_ssl, args.no_verify,
                           args.username, args.password)
    except Exception as e:
        print(f"[!] LDAP connection failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    search_filter = build_optimized_filter(args)
    print(f"[+] Using LDAP filter: {search_filter}")
    
    print("[+] Enumerating SPNs...")
    spn_entries = enumerate_spns(
        conn,
        base_dn,
        args.page_size,
        search_filter,
        args.limit,
        apply_default_excludes=not args.no_default_excludes,
        domain=args.domain
    )
    print(f"[+] Found {len(spn_entries)} SPNs after filtering")
    
    duplicates = {}
    if args.show_duplicates:
        duplicates = detect_duplicate_spns(spn_entries)
        if duplicates:
            print(f"[!] Found {len(duplicates)} duplicate SPNs")
    
    unique_hosts = sorted({e['hostname'] for e in spn_entries})
    print(f"[+] Unique hostnames: {len(unique_hosts)}")
    
    dns_results = {}
    cached_hosts = {}
    dns_nameserver = None
    
    if args.check_dns:
        candidate_ns = args.nameserver or args.server
        dns_nameserver = normalize_nameserver(candidate_ns)
        if dns_nameserver:
            if args.nameserver:
                print(f"[+] Using custom DNS server for resolution: {dns_nameserver}")
            else:
                print(f"[+] Using domain controller DNS server: {dns_nameserver}")
        else:
            if args.nameserver:
                print(f"[!] Unable to use provided nameserver '{args.nameserver}'. Falling back to system resolver.")
            else:
                print(f"[!] Unable to determine domain controller IP for DNS lookups. Falling back to system resolver.")
    
    if args.check_dns:
        if args.cache_file:
            cached_hosts = load_host_cache(args.cache_file, args.cache_ttl)
            dns_results.update(cached_hosts)
        
        hosts_to_check = [h for h in unique_hosts if h not in cached_hosts]
        
        if hosts_to_check:
            print(f"[+] Performing DNS checks on {len(hosts_to_check)} hosts ({len(cached_hosts)} cached)...")
            
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futures = {
                    pool.submit(hostname_resolves, h, args.timeout, dns_nameserver): h
                    for h in hosts_to_check
                }
                
                for fut in as_completed(futures):
                    host = futures[fut]
                    try:
                        dns_results[host] = fut.result()
                    except Exception:
                        dns_results[host] = False
            
            if args.cache_file:
                save_host_cache(args.cache_file, dns_results)
        else:
            print("[+] All hosts found in cache, skipping DNS checks")
    
    if args.check_dns:
        unresolved = [h for h, ok in dns_results.items() if not ok]
        print(f"[+] Hosts that don't resolve in DNS: {len(unresolved)}")
        hosts_to_check = unresolved
    else:
        hosts_to_check = unique_hosts[:]
        print("[!] DNS validation not performed (--check-dns not supplied); exploitability ratings may include resolvable hosts.")
    
    hosts_to_check_count = len(hosts_to_check)
    ad_computer_matches = {h: [] for h in hosts_to_check}
    proceed_with_ad_lookup = True
    
    threshold = max(0, args.ad_confirm_threshold)
    if (
        hosts_to_check_count
        and threshold
        and hosts_to_check_count >= threshold
        and not args.skip_ad_confirm
    ):
        batches = math.ceil(hosts_to_check_count / max(1, args.ad_chunk_size))
        est_seconds = batches * max(0.1, args.ad_batch_seconds)
        print(f"[?] LDAP host checks queued: {hosts_to_check_count} hosts across ~{batches} batches "
              f"(estimated {format_duration(est_seconds)}).")
        choice = input("Proceed with LDAP host checks? [y/N]: ").strip().lower()
        if choice not in ('y', 'yes'):
            print("[-] Skipping AD host lookups at user request; results may include more false positives.")
            proceed_with_ad_lookup = False
    
    if hosts_to_check_count and proceed_with_ad_lookup:
        print(f"[+] Checking {hosts_to_check_count} hosts in AD...")
        ad_computer_matches = batch_find_computers_for_hosts(
            conn,
            base_dn,
            hosts_to_check,
            page_size=args.page_size,
            search_timeout=60,
            chunk_size=max(1, args.ad_chunk_size)
        )
    
    ghost_candidates = []
    for entry in spn_entries:
        host = entry['hostname']
        
        if ad_computer_matches.get(host):
            continue
        
        if args.check_dns and dns_results.get(host, False):
            continue
        
        exploitability = assess_exploitability(entry, ad_computer_matches, dns_results, args.check_dns)
        if args.check_dns:
            dns_value = dns_results.get(host)
            if dns_value is True:
                dns_status = 'Resolved'
            elif dns_value is False:
                dns_status = 'Not Resolved'
            else:
                dns_status = 'Unknown'
        else:
            dns_value = None
            dns_status = 'Not Checked'
        
        ghost_candidates.append({
            'spn': entry['spn'],
            'hostname': host,
            'dns_status': dns_status,
            'dns_resolved': dns_value,
            'account_sam': entry.get('account_sam') or '',
            'account_dn': entry.get('account_dn') or '',
            'is_computer_account': entry.get('is_computer', False),
            'last_logon': entry.get('last_logon') or 'N/A',
            'exploitability': exploitability[0],
            'reason': exploitability[1]
        })
    
    print(f"\n{'='*80}")
    print(f"[!] Found {len(ghost_candidates)} possible GHOST SPNs")
    print(f"{'='*80}\n")
    
    if ghost_candidates:
        severity_order = ['HIGH', 'MEDIUM', 'LOW', 'SELF', 'EXCLUDED']
        severity_labels = {
            'HIGH': ('[X]', 'HIGH RISK'),
            'MEDIUM': ('[~]', 'MEDIUM RISK'),
            'LOW': ('[i]', 'LOW RISK'),
            'SELF': ('[=]', 'SELF-REFERENCES'),
            'EXCLUDED': ('[ ]', 'EXCLUDED')
        }
        def sort_key(entry):
            last_logon = entry.get('last_logon') or ''
            if last_logon in ('N/A', 'Never', ''):
                return (0, datetime.min)
            try:
                dt = datetime.strptime(last_logon, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return (1, datetime.min)
            return (2, dt)
        
        for severity in severity_order:
            subset = [g for g in ghost_candidates if g['exploitability'] == severity]
            if not subset:
                continue
            title_suffix = ''
            if severity == 'LOW':
                title_suffix = ' - User accounts with SPNs'
            elif severity == 'SELF':
                title_suffix = ' - Not exploitable'
            elif severity == 'EXCLUDED':
                title_suffix = ' - Legitimate infrastructure'
            icon, title = severity_labels.get(severity, ('[ ]', severity))
            label = f"{icon} {title}"
            colored_label = colorize(label, severity)
            print(f"{colored_label} ({len(subset)}{title_suffix})\n")
            sorted_subset = sorted(subset, key=sort_key, reverse=True)
            table = []
            for g in sorted_subset:
                row = [g['spn'], g['account_sam'], g['hostname']]
                if args.check_dns:
                    row.append(g.get('dns_status', 'Unknown'))
                row.extend([g['last_logon'], g['reason']])
                table.append(row)
            headers = ["SPN", "Account", "Hostname"]
            if args.check_dns:
                headers.append("DNS")
            headers.extend(["Last Logon", "Reason"])
            print(tabulate(table, headers=headers, tablefmt="fancy_grid"))
            print()
    else:
        print("[+] No ghost SPNs detected!")
    
    if duplicates:
        print(f"\n{'='*80}")
        print(f"[!] DUPLICATE SPNs: {len(duplicates)}")
        print(f"{'='*80}\n")
        for spn, entries in sorted(duplicates.items())[:10]:
            print(f"SPN: {spn}")
            for e in entries:
                print(f"  -> {e.get('account_sam','')} ({e.get('account_dn','')})")
            print("")
        if len(duplicates) > 10:
            print(f"... and {len(duplicates) - 10} more")
    
    if args.output and ghost_candidates:
        write_output(args.output, ghost_candidates)
        print(f"\n[+] Results written to {args.output}")
    
    try:
        conn.unbind()
    except Exception:
        pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)
