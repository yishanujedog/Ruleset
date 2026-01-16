import asyncio  # noqa: D100
import contextlib
import ipaddress
import re
from typing import Any

import anyio
import httpx
import orjson
import polars as pl
import yaml

ASN_CACHE: dict[str, list[str]] = {}
POOL = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, pool=30.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
    http2=True,
)


SINGBOX_ALIAS = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-SET": "domain_suffix",
    "URL-REGEX": "domain_regex",
    "DOMAIN-WILDCARD": "domain_regex",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "IP6-CIDR": "ip_cidr",
    "SRC-IP": "source_ip_cidr",
    "SRC-IP-CIDR": "source_ip_cidr",
    "IP-ASN": "ip_asn",
    "DEST-PORT": "port",
    "DST-PORT": "port",
    "IN-PORT": "port",
    "SRC-PORT": "source_port",
    "SOURCE-PORT": "source_port",
    "PROCESS-NAME": "process_name",
    "PROCESS-PATH": "process_path",
    "PROCESS-PATH-REGEX": "process_path_regex",
    "PROCESS-NAME-REGEX": "process_name_regex",
    "PROTOCOL": "protocol",
    "NETWORK": "network",
    "HOST": "domain",
    "HOST-SUFFIX": "domain_suffix",
    "HOST-KEYWORD": "domain_keyword",
    "USER": "user",
    "USER-ID": "user_id",
    "PACKAGE-NAME": "package_name",
    "UID": "user_id",
    "CLASH-MODE": "clash_mode",
    "NETWORK-TYPE": "network_type",
    "NETWORK-IS-EXPENSIVE": "network_is_expensive",
    "NETWORK-IS-CONSTRAINED": "network_is_constrained",
    "WIFI-SSID": "wifi_ssid",
    "WIFI-BSSID": "wifi_bssid",
    "RULE-SET": "rule_set",
    "RULE-SET-IPCIDR-MATCH-SOURCE": "rule_set_ipcidr_match_source",
    "RULE-SET-IP-CIDR-MATCH-SOURCE": "rule_set_ip_cidr_match_source",
    "PREFERRED-BY": "preferred_by",
    "AUTH-USER": "auth_user",
    "CLIENT": "client",
    "IP-VERSION": "ip_version",
    "INBOUND": "inbound",
    "AND": "and",
    "OR": "or",
}


MIHOMO_ALIAS = {
    "DOMAIN": "DOMAIN",
    "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
    "DOMAIN-SET": "DOMAIN-SUFFIX",
    "URL-REGEX": "DOMAIN-REGEX",
    "DOMAIN-WILDCARD": "DOMAIN-WILDCARD",
    "DOMAIN-REGEX": "DOMAIN-REGEX",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR",
    "IP6-CIDR": "IP-CIDR",
    "IP-SUFFIX": "IP-SUFFIX",
    "SRC-IP": "SRC-IP-CIDR",
    "SRC-IP-CIDR": "SRC-IP-CIDR",
    "SRC-IP-SUFFIX": "SRC-IP-SUFFIX",
    "IP-ASN": "IP-ASN",
    "SRC-IP-ASN": "SRC-IP-ASN",
    "DEST-PORT": "DST-PORT",
    "DST-PORT": "DST-PORT",
    "IN-PORT": "IN-PORT",
    "IN-TYPE": "IN-TYPE",
    "IN-USER": "IN-USER",
    "IN-NAME": "IN-NAME",
    "SRC-PORT": "SRC-PORT",
    "SOURCE-PORT": "SRC-PORT",
    "PROCESS-NAME": "PROCESS-NAME",
    "PROCESS-PATH": "PROCESS-PATH",
    "PROCESS-PATH-REGEX": "PROCESS-PATH-REGEX",
    "PROCESS-NAME-REGEX": "PROCESS-NAME-REGEX",
    "PROTOCOL": "NETWORK",
    "NETWORK": "NETWORK",
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "GEOIP": "GEOIP",
    "GEOSITE": "GEOSITE",
    "SRC-GEOIP": "SRC-GEOIP",
    "UID": "UID",
    "DSCP": "DSCP",
    "RULE-SET": "RULE-SET",
    "AND": "AND",
    "OR": "OR",
    "NOT": "NOT",
    "SUB-RULE": "SUB-RULE",
    "MATCH": "MATCH",
}


SINGBOX_ORDER = [
    "inbound",
    "ip_version",
    "auth_user",
    "protocol",
    "client",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_geoip",
    "geoip",
    "source_ip_cidr",
    "source_ip_is_private",
    "ip_cidr",
    "ip_is_private",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "user",
    "user_id",
    "clash_mode",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "interface_address",
    "network_interface_address",
    "default_interface_address",
    "wifi_ssid",
    "wifi_bssid",
    "preferred_by",
    "rule_set",
    "rule_set_ipcidr_match_source",
    "rule_set_ip_cidr_match_source",
    "invert",
]


MIHOMO_ORDER = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN-WILDCARD",
    "GEOSITE",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "SRC-IP-ASN",
    "SRC-GEOIP",
    "IP-CIDR",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-PORT",
    "DST-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-NAME",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH",
    "PROCESS-PATH-REGEX",
    "NETWORK",
    "UID",
    "DSCP",
    "RULE-SET",
    "AND",
    "OR",
    "NOT",
    "SUB-RULE",
    "MATCH",
]


SINGBOX_DENY = frozenset(
    {
        "USER-AGENT",
        "CELLULAR-RADIO",
        "DEVICE-NAME",
        "MAC-ADDRESS",
        "FINAL",
        "GEOIP",
        "GEOSITE",
        "SOURCE-GEOIP",
        "NOT",
        "RULE-SET-IPCIDR-MATCH-SOURCE",
    },
)


MIHOMO_DENY = frozenset(
    {
        "USER-AGENT",
        "CELLULAR-RADIO",
        "DEVICE-NAME",
        "MAC-ADDRESS",
        "FINAL",
        "IP-IS-PRIVATE",
        "SOURCE-IP-IS-PRIVATE",
        "NETWORK-IS-EXPENSIVE",
        "NETWORK-IS-CONSTRAINED",
        "WIFI-SSID",
        "WIFI-BSSID",
        "PREFERRED-BY",
        "AUTH-USER",
        "CLIENT",
        "IP-VERSION",
        "INBOUND",
        "PACKAGE-NAME",
        "USER",
        "USER-ID",
        "CLASH-MODE",
        "NETWORK-TYPE",
        "INTERFACE-ADDRESS",
        "NETWORK-INTERFACE-ADDRESS",
        "DEFAULT-INTERFACE-ADDRESS",
        "RULE-SET-IPCIDR-MATCH-SOURCE",
        "RULE-SET-IP-CIDR-MATCH-SOURCE",
    },
)


SINGBOX_ALIASES = tuple(SINGBOX_ALIAS.keys())


MIHOMO_ALIASES = tuple(MIHOMO_ALIAS.keys())


_NETWORK_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP"})
_SUPPORTED_PROTOCOLS = frozenset({"TLS", "HTTP", "QUIC", "STUN"})
_SUPPORTED_CLIENTS = frozenset({"CHROMIUM", "SAFARI", "FIREFOX", "QUIC-GO"})
_NETWORK_TYPES = frozenset({"wifi", "cellular", "ethernet", "other"})
_IP_VERSIONS = frozenset({4, 6})
_PORT_PATTERNS = frozenset({"DEST-PORT", "DST-PORT", "PORT"})
_SOURCE_PORT_PATTERN = frozenset({"SRC-PORT"})
_SOURCE_IP_PATTERNS = frozenset({"SRC-IP", "SRC-IP-CIDR"})
_CHINA_IP_FILENAMES = frozenset({"china-ip", "china-ip-ipv6"})


async def ingest(url: str) -> pl.DataFrame:  # noqa: C901, D103
    if url.startswith("file://"):
        async with await anyio.Path(url[7:]).open("r", encoding="utf-8") as handle:
            payload = await handle.read()
    else:
        resp = await POOL.get(url)
        resp.raise_for_status()
        payload = resp.text

    def _parse_yaml_item(item: str) -> dict[str, str]:
        if "," in item:
            parts = item.split(",", 2)
            return {"pattern": parts[0].strip(), "address": parts[1].strip()}
        entry = item.strip("'\"")
        try:
            ipaddress.ip_network(entry, strict=False)
            pattern = "IP-CIDR"
        except ValueError:
            pattern = "DOMAIN-SUFFIX" if entry.startswith("+") else "DOMAIN"
        address = (
            entry.removeprefix("+").lstrip(".") if entry.startswith("+") else entry
        )
        return {"pattern": pattern, "address": address}

    def _parse_text_line(line: str) -> dict[str, str]:
        if "," in line:
            parts = line.split(",", 2)
            if len(parts) > 2 and parts[2].strip():  # noqa: PLR2004
                address = f"{parts[1].strip()},{parts[2].strip()}"
            elif len(parts) > 1:
                address = parts[1].strip()
            else:
                address = ""
            return {"pattern": parts[0].strip(), "address": address}
        return {"pattern": "DOMAIN-SUFFIX", "address": line}

    if url.endswith((".yaml", ".yml")):
        with contextlib.suppress(yaml.YAMLError):
            parsed = yaml.safe_load(payload)
            if isinstance(parsed, dict):
                payload_items = parsed.get("payload")
                if isinstance(payload_items, (list, tuple)):
                    return pl.DataFrame(
                        [_parse_yaml_item(item) for item in payload_items]
                    )

    lines = [
        line.strip()
        for line in payload.strip().split("\n")
        if line and not line.startswith("#")
    ]
    return pl.DataFrame([_parse_text_line(line) for line in lines])


async def merge(asn_list: list[str]) -> list[str]:  # noqa: D103
    async def _fetch_asn(asn: str) -> list[str]:
        if (cached := ASN_CACHE.get(asn)) is not None:
            return cached

        asn_id = (
            asn.removeprefix("AS")
            .removeprefix("as")
            .removesuffix("AS")
            .removesuffix("as")
        )

        def _extract_bgpview(body: dict[str, Any]) -> list[str]:
            data = body.get("data", {})
            return [
                item["prefix"]
                for item in data.get("ipv4_prefixes", [])
                + data.get("ipv6_prefixes", [])
            ]

        def _extract_ripe(body: dict[str, Any]) -> list[str]:
            return [
                item["prefix"]
                for item in body.get("data", {}).get("prefixes", [])
                if "prefix" in item
            ]

        apis = [
            (f"https://api.bgpview.io/asn/{asn_id}/prefixes", _extract_bgpview),
            (
                f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_id}",
                _extract_ripe,
            ),
        ]

        for url, extractor in apis:
            with contextlib.suppress(httpx.HTTPError, orjson.JSONDecodeError, KeyError):
                resp = await POOL.get(url)
                if resp.status_code == 200:  # noqa: PLR2004
                    body = orjson.loads(resp.content)
                    if body.get("status") == "ok" and (cidrs := extractor(body)):
                        ASN_CACHE[asn] = cidrs
                        return cidrs

        ASN_CACHE[asn] = []
        return []

    bundles = await asyncio.gather(
        *(_fetch_asn(asn) for asn in asn_list), return_exceptions=True
    )
    return [cidr for bundle in bundles if isinstance(bundle, list) for cidr in bundle]


def validate_regex(pattern: str) -> bool:  # noqa: D103
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def mask_regex(pattern: str) -> str:  # noqa: D103
    masked = pattern.lstrip(".")
    char_map = {".": r"\.", "*": r"[\w.-]*?", "?": r"[\w.-]"}
    return "^" + "".join(char_map.get(char, char) for char in masked) + "$"


def normalize_cidr(entry: str) -> str:  # noqa: D103
    if "/" in entry:
        return entry
    try:
        addr = ipaddress.ip_address(entry)
    except ValueError:
        return entry
    return f"{entry}/32" if addr.version == 4 else f"{entry}/128"  # noqa: PLR2004


def process_ports(addresses: list[str]) -> tuple[list[str], list[str]]:  # noqa: D103
    if not addresses:
        return [], []

    def _split_port(item: str) -> tuple[str | None, int | None]:
        if ":" in item or "-" in item:
            token = ":" if ":" in item else "-"
            parts = item.split(token)
            if len(parts) == 2:  # noqa: PLR2004
                with contextlib.suppress(ValueError):
                    start, end = int(parts[0]), int(parts[1])
                    return f"{start}:{end}", None
            return None, None
        with contextlib.suppress(ValueError):
            return None, int(item)
        return None, None

    port_results = [_split_port(item) for item in addresses]
    filtered_results = [
        (None, span) if span is not None else (value, None)
        for span, value in port_results
        if span is not None or value is not None
    ]

    if not filtered_results:
        return [], []

    ports, ranges = zip(*filtered_results, strict=False)
    return [p for p in ports if p], [r for r in ranges if r]


def compose_singbox_json(frame: pl.DataFrame, cidrs: list[str]) -> dict[str, Any]:  # noqa: C901, D103, PLR0912, PLR0915
    def _parse_logical_rule_content(content: str) -> list[str]:
        if "),(" in content:
            parts = content.split("),(")
        elif "), (" in content:
            parts = content.split("), (")
        else:
            return [content]

        if parts and parts[0].startswith("(") and parts[-1].endswith(")"):
            return [parts[0][1:], *parts[1:-1], parts[-1][:-1]]
        return parts

    def _build_sub_rule(sub_pattern: str, address: str) -> dict[str, Any]:  # noqa: C901, PLR0911, PLR0912
        pattern_upper = sub_pattern.upper()
        address_upper = address.upper()
        address_lower = address.lower()

        if pattern_upper == "DOMAIN":
            return {"domain": [address]}
        if pattern_upper == "DOMAIN-SUFFIX":
            return {"domain_suffix": [address]}
        if pattern_upper == "DOMAIN-KEYWORD":
            return {"domain_keyword": [address]}
        if pattern_upper == "NETWORK":
            return {"network": [address_lower]}
        if pattern_upper == "PROTOCOL":
            return (
                {"protocol": [address_lower]}
                if address_upper in _SUPPORTED_PROTOCOLS
                else {}
            )
        if pattern_upper == "CLIENT":
            return (
                {"client": [address_lower]}
                if address_upper in _SUPPORTED_CLIENTS
                else {}
            )
        if pattern_upper == "PROCESS-NAME":
            return {"process_name": [address]}
        if pattern_upper == "PROCESS-PATH":
            return {"process_path": [address]}
        if pattern_upper == "PROCESS-PATH-REGEX":
            return {"process_path_regex": [address]} if validate_regex(address) else {}
        if pattern_upper == "PROCESS-NAME-REGEX":
            return {"process_name_regex": [address]} if validate_regex(address) else {}
        if pattern_upper in _SOURCE_IP_PATTERNS:
            return {"source_ip_cidr": [normalize_cidr(address)]}
        if pattern_upper in _PORT_PATTERNS:
            return {"port": [int(address)]} if address.isdigit() else {}
        if pattern_upper in _SOURCE_PORT_PATTERN:
            return {"source_port": [int(address)]} if address.isdigit() else {}
        if pattern_upper == "IP-CIDR":
            return {"ip_cidr": [normalize_cidr(address)]}
        if pattern_upper == "DOMAIN-REGEX":
            return {"domain_regex": [address]} if validate_regex(address) else {}
        if pattern_upper == "DOMAIN-WILDCARD":
            masked = mask_regex(address)
            return {"domain_regex": [masked]} if validate_regex(masked) else {}
        if pattern_upper == "USER":
            return {"user": [address]}
        if pattern_upper == "USER-ID":
            return {"user_id": [int(address)]} if address.isdigit() else {}
        if pattern_upper == "PACKAGE-NAME":
            return {"package_name": [address]}
        if pattern_upper == "AUTH-USER":
            return {"auth_user": [address]}
        if pattern_upper == "NETWORK-TYPE":
            return (
                {"network_type": [address_lower]}
                if address_lower in _NETWORK_TYPES
                else {}
            )
        if pattern_upper == "WIFI-SSID":
            return {"wifi_ssid": [address]}
        if pattern_upper == "WIFI-BSSID":
            return {"wifi_bssid": [address]}
        if pattern_upper == "RULE-SET":
            return {"rule_set": [address]}
        if pattern_upper == "IP-VERSION":
            return (
                {"ip_version": [int(address)]}
                if address.isdigit() and int(address) in _IP_VERSIONS
                else {}
            )
        if pattern_upper == "INBOUND":
            return {"inbound": [address]}
        if pattern_upper == "IP-IS-PRIVATE":
            return {"ip_is_private": address_lower == "true"}
        if pattern_upper == "SOURCE-IP-IS-PRIVATE":
            return {"source_ip_is_private": address_lower == "true"}
        return {}

    def _process_logical_rules(addresses: list[str], mode: str) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        for addr in addresses:
            if not (addr.startswith("((") and addr.endswith("))")):
                continue

            inner_content = addr[2:-2].strip()
            rule_parts = _parse_logical_rule_content(inner_content)

            sub_rules: list[dict[str, Any]] = []
            for rule in rule_parts:
                stripped_rule = rule.strip()
                if "," not in stripped_rule:
                    continue

                parts = stripped_rule.split(",", 1)
                if len(parts) != 2:  # noqa: PLR2004
                    continue

                sub_pattern, address = parts[0].strip(), parts[1].strip()
                sub_rule = _build_sub_rule(sub_pattern, address)
                if sub_rule:
                    sub_rules.append(sub_rule)

            if sub_rules:
                rules.append(
                    {
                        "type": "logical",
                        "mode": mode,
                        "rules": sub_rules,
                        "invert": False,
                    },
                )
        return rules

    def _process_domain_regex(addresses: list[str]) -> list[str]:
        return [addr for addr in addresses if validate_regex(addr)]

    def _process_domain_wildcard(addresses: list[str]) -> list[str]:
        patterns: list[str] = []
        for item in addresses:
            masked = mask_regex(item)
            if masked and validate_regex(masked):
                patterns.append(masked)
        return patterns

    def _process_ip_cidr(addresses: list[str]) -> list[str]:
        result: list[str] = []
        for addr in addresses:
            if addr.endswith(",no-resolve"):
                result.append(normalize_cidr(addr.rsplit(",", 1)[0]))
            else:
                result.append(normalize_cidr(addr))
        return result

    def _filter_network_protocols(addresses: list[str]) -> list[str]:
        return [
            entry.lower() for entry in addresses if entry.upper() in _NETWORK_PROTOCOLS
        ]

    def _filter_supported_protocols(addresses: list[str]) -> list[str]:
        return [
            entry.lower()
            for entry in addresses
            if entry.upper() in _SUPPORTED_PROTOCOLS
        ]

    def _filter_supported_clients(addresses: list[str]) -> list[str]:
        return [
            entry.lower() for entry in addresses if entry.upper() in _SUPPORTED_CLIENTS
        ]

    def _filter_network_types(addresses: list[str]) -> list[str]:
        return [entry.lower() for entry in addresses if entry.lower() in _NETWORK_TYPES]

    def _filter_user_ids(addresses: list[str]) -> list[int]:
        return [int(user_id_str) for user_id_str in addresses if user_id_str.isdigit()]

    def _filter_ip_versions(addresses: list[str]) -> list[int]:
        return [
            int(version_str)
            for version_str in addresses
            if version_str.isdigit() and int(version_str) in _IP_VERSIONS
        ]

    def _parse_boolean_value(addresses: list[str]) -> bool | None:
        return addresses[0].lower() == "true" if addresses else None

    logical_rules: list[dict[str, Any]] = []
    regular_rule: dict[str, Any] = {}

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    pattern_dict = {
        block["pattern"]: block["address"] for block in grouped.iter_rows(named=True)
    }

    for pattern in ("and", "or"):
        if pattern in pattern_dict:
            logical_rules.extend(_process_logical_rules(pattern_dict[pattern], pattern))

    for pattern in SINGBOX_ORDER:
        if pattern not in pattern_dict:
            continue

        addresses = pattern_dict[pattern]

        match pattern:
            case "domain":
                regular_rule.setdefault("domain", []).extend(addresses)
            case "domain_suffix":
                regular_rule.setdefault("domain_suffix", []).extend(addresses)
            case "domain_keyword":
                regular_rule.setdefault("domain_keyword", []).extend(addresses)
            case "domain_regex":
                if valid_regexes := _process_domain_regex(addresses):
                    regular_rule.setdefault("domain_regex", []).extend(valid_regexes)
            case "domain_wildcard":
                if regex_patterns := _process_domain_wildcard(addresses):
                    regular_rule.setdefault("domain_regex", []).extend(regex_patterns)
            case "ip_cidr":
                regular_rule.setdefault("ip_cidr", []).extend(
                    _process_ip_cidr(addresses)
                )
            case "source_ip_cidr":
                regular_rule.setdefault("source_ip_cidr", []).extend(
                    normalize_cidr(item) for item in addresses
                )
            case "port" | "source_port":
                ports, ranges = process_ports(addresses)
                field_prefix = "" if pattern == "port" else "source_"
                if ports:
                    regular_rule.setdefault(f"{field_prefix}port", []).extend(ports)
                if ranges:
                    regular_rule.setdefault(f"{field_prefix}port_range", []).extend(
                        ranges
                    )
            case "process_name":
                regular_rule.setdefault("process_name", []).extend(addresses)
            case "process_path":
                regular_rule.setdefault("process_path", []).extend(addresses)
            case "network":
                if proto := _filter_network_protocols(addresses):
                    regular_rule.setdefault("network", []).extend(proto)
            case "protocol":
                if supported_protocols := _filter_supported_protocols(addresses):
                    regular_rule.setdefault("protocol", []).extend(supported_protocols)
            case "client":
                if supported_clients := _filter_supported_clients(addresses):
                    regular_rule.setdefault("client", []).extend(supported_clients)
            case "auth_user":
                regular_rule.setdefault("auth_user", []).extend(addresses)
            case "user":
                regular_rule.setdefault("user", []).extend(addresses)
            case "user_id":
                if user_ids := _filter_user_ids(addresses):
                    regular_rule.setdefault("user_id", []).extend(user_ids)
            case "clash_mode":
                if addresses:
                    regular_rule["clash_mode"] = addresses[0]
            case "network_type":
                if network_types := _filter_network_types(addresses):
                    regular_rule.setdefault("network_type", []).extend(network_types)
            case "network_is_expensive":
                if value := _parse_boolean_value(addresses):
                    regular_rule["network_is_expensive"] = value
            case "network_is_constrained":
                if value := _parse_boolean_value(addresses):
                    regular_rule["network_is_constrained"] = value
            case "wifi_ssid":
                regular_rule.setdefault("wifi_ssid", []).extend(addresses)
            case "wifi_bssid":
                regular_rule.setdefault("wifi_bssid", []).extend(addresses)
            case "rule_set":
                regular_rule.setdefault("rule_set", []).extend(addresses)
            case "ip_version":
                if ip_versions := _filter_ip_versions(addresses):
                    regular_rule.setdefault("ip_version", []).extend(ip_versions)
            case "inbound":
                regular_rule.setdefault("inbound", []).extend(addresses)
            case "process_path_regex":
                if valid_regexes := _process_domain_regex(addresses):
                    regular_rule.setdefault("process_path_regex", []).extend(
                        valid_regexes
                    )
            case "process_name_regex":
                if valid_regexes := _process_domain_regex(addresses):
                    regular_rule.setdefault("process_name_regex", []).extend(
                        valid_regexes
                    )
            case "ip_is_private":
                if value := _parse_boolean_value(addresses):
                    regular_rule["ip_is_private"] = value
            case "source_ip_is_private":
                if value := _parse_boolean_value(addresses):
                    regular_rule["source_ip_is_private"] = value

    if cidrs:
        regular_rule.setdefault("ip_cidr", []).extend(
            normalize_cidr(item) for item in cidrs
        )

    regular_rule = {
        key: (
            sorted(set(value))
            if key in {"port", "source_port"}
            else list(dict.fromkeys(value))
        )
        for key, value in regular_rule.items()
        if isinstance(value, list)
    }

    ordered_regular = {
        field: regular_rule[field] for field in SINGBOX_ORDER if regular_rule.get(field)
    }
    ordered_regular.update(
        {
            field: value
            for field, value in regular_rule.items()
            if field not in ordered_regular and value
        },
    )

    final_rules = logical_rules + ([ordered_regular] if ordered_regular else [])

    return {"version": 4, "rules": final_rules or []}


def compose_mihomo_yaml(  # noqa: C901, D103, PLR0912, PLR0915
    frame: pl.DataFrame,
    cidrs: list[str],
    category: str,
    filename: str = "",
) -> dict[str, Any] | None:
    def _is_china_ip_file() -> bool:
        return category == "ip" and any(
            name in filename for name in _CHINA_IP_FILENAMES
        )

    def _format_domain_suffix(addr: str) -> str:
        return f"DOMAIN-SUFFIX,{addr.lstrip('.')}"

    def _format_ip_cidr(addr: str, *, is_china_ip: bool) -> str:
        if is_china_ip:
            return normalize_cidr(
                addr.removesuffix(",no-resolve")
                if addr.endswith(",no-resolve")
                else addr
            )
        if addr.endswith(",no-resolve"):
            return (
                f"IP-CIDR,{normalize_cidr(addr.removesuffix(',no-resolve'))},no-resolve"
            )
        return f"IP-CIDR,{normalize_cidr(addr)}"

    def _format_ip_asn(addr: str) -> str:
        if addr.endswith(",no-resolve"):
            return f"IP-ASN,{addr.removesuffix(',no-resolve')},no-resolve"
        return f"IP-ASN,{addr}"

    def _format_geoip(addr: str) -> str:
        if addr.endswith(",no-resolve"):
            return f"GEOIP,{addr.removesuffix(',no-resolve')},no-resolve"
        return f"GEOIP,{addr}"

    def _filter_valid_regex(addresses: list[str]) -> list[str]:
        return [addr for addr in addresses if validate_regex(addr)]

    def _filter_network_protocols(addresses: list[str]) -> list[str]:
        return [
            entry.upper() for entry in addresses if entry.upper() in _NETWORK_PROTOCOLS
        ]

    def _process_logical_rule(addr: str, pattern: str) -> str | None:
        if not addr or addr.startswith("(("):
            return None

        parts = addr.split(",", 1)
        if len(parts) == 2:  # noqa: PLR2004
            mapped_pattern = MIHOMO_ALIAS.get(parts[0].strip(), parts[0].strip())
            return f"{pattern},{mapped_pattern},{parts[1].strip()}"
        return f"{pattern},{addr.strip()}"

    def _process_nested_logical_rule(addr: str, pattern: str) -> str:
        processed_addr = addr
        for original, mapped in MIHOMO_ALIAS.items():
            processed_addr = processed_addr.replace(f"({original},", f"({mapped},")
        return f"{pattern},{processed_addr.strip() if processed_addr else ''}"

    def _process_logical_rules(addresses: list[str], pattern: str) -> list[str]:
        results: list[str] = []
        for addr in addresses:
            if result := _process_logical_rule(addr, pattern):
                results.append(result)
            elif addr:
                results.append(_process_nested_logical_rule(addr, pattern))
        return results

    def _process_ports(addresses: list[str], pattern: str) -> list[str]:
        ports, ranges = process_ports(addresses)
        results: list[str] = []
        if ports:
            results.extend(f"{pattern},{port}" for port in ports)
        if ranges:
            results.extend(f"{pattern},{range_val}" for range_val in ranges)
        return results

    is_china_ip = _is_china_ip_file()
    grouped = frame.group_by("pattern").agg(pl.col("address"))
    pattern_dict = {
        block["pattern"]: block["address"] for block in grouped.iter_rows(named=True)
    }

    payload: list[str] = []

    for pattern in MIHOMO_ORDER:
        if pattern not in pattern_dict:
            continue

        addresses = pattern_dict[pattern]

        match pattern:
            case "DOMAIN":
                payload.extend(f"DOMAIN,{addr}" for addr in addresses)
            case "DOMAIN-SUFFIX":
                payload.extend(_format_domain_suffix(addr) for addr in addresses)
            case "DOMAIN-KEYWORD":
                payload.extend(f"DOMAIN-KEYWORD,{addr}" for addr in addresses)
            case "DOMAIN-REGEX":
                payload.extend(
                    f"DOMAIN-REGEX,{addr}" for addr in _filter_valid_regex(addresses)
                )
            case "DOMAIN-WILDCARD":
                payload.extend(f"DOMAIN-WILDCARD,{addr}" for addr in addresses)
            case "GEOSITE":
                payload.extend(f"GEOSITE,{addr}" for addr in addresses)
            case "IP-CIDR":
                payload.extend(
                    _format_ip_cidr(addr, is_china_ip=is_china_ip) for addr in addresses
                )
            case "IP-SUFFIX":
                payload.extend(f"IP-SUFFIX,{addr}" for addr in addresses)
            case "IP-ASN":
                payload.extend(_format_ip_asn(addr) for addr in addresses)
            case "GEOIP":
                payload.extend(_format_geoip(addr) for addr in addresses)
            case "SRC-IP-CIDR":
                payload.extend(
                    f"SRC-IP-CIDR,{normalize_cidr(addr)}" for addr in addresses
                )
            case "SRC-IP-SUFFIX":
                payload.extend(f"SRC-IP-SUFFIX,{addr}" for addr in addresses)
            case "SRC-IP-ASN":
                payload.extend(f"SRC-IP-ASN,{addr}" for addr in addresses)
            case "SRC-GEOIP":
                payload.extend(f"SRC-GEOIP,{addr}" for addr in addresses)
            case "DST-PORT" | "SRC-PORT" | "IN-PORT":
                payload.extend(_process_ports(addresses, pattern))
            case "PROCESS-NAME":
                payload.extend(f"PROCESS-NAME,{addr}" for addr in addresses)
            case "PROCESS-PATH":
                payload.extend(f"PROCESS-PATH,{addr}" for addr in addresses)
            case "NETWORK":
                if proto := _filter_network_protocols(addresses):
                    payload.extend(f"NETWORK,{p}" for p in proto)
            case "IN-TYPE":
                payload.extend(f"IN-TYPE,{addr}" for addr in addresses)
            case "IN-USER":
                payload.extend(f"IN-USER,{addr}" for addr in addresses)
            case "IN-NAME":
                payload.extend(f"IN-NAME,{addr}" for addr in addresses)
            case "PROCESS-NAME-REGEX":
                payload.extend(
                    f"PROCESS-NAME-REGEX,{addr}"
                    for addr in _filter_valid_regex(addresses)
                )
            case "PROCESS-PATH-REGEX":
                payload.extend(
                    f"PROCESS-PATH-REGEX,{addr}"
                    for addr in _filter_valid_regex(addresses)
                )
            case "UID":
                payload.extend(f"UID,{addr}" for addr in addresses)
            case "DSCP":
                payload.extend(f"DSCP,{addr}" for addr in addresses)
            case "RULE-SET":
                pass
            case "AND" | "OR" | "NOT" | "SUB-RULE":
                payload.extend(_process_logical_rules(addresses, pattern))
            case "MATCH":
                payload.extend(f"MATCH,{addr}" for addr in addresses)

    if cidrs:
        payload.extend(f"IP-CIDR,{normalize_cidr(item)}" for item in cidrs)

    if is_china_ip:
        yaml_lines = ["payload:"]
        yaml_lines.extend(f'- "{item}"' for item in payload)
        return {"__custom_yaml__": "\n".join(yaml_lines)}

    return {"payload": payload} if payload else None


def compose_mihomo_text(  # noqa: C901, D103, PLR0915
    frame: pl.DataFrame,
    cidrs: list[str],
    category: str,
    filename: str = "",
) -> list[str] | None:
    def _is_china_ip_file() -> bool:
        return category == "ip" and any(
            name in filename for name in _CHINA_IP_FILENAMES
        )

    def _format_domain_suffix(addr: str) -> str:
        return f"+{addr}" if addr.startswith(".") else f"+.{addr}"

    def _format_ip_cidr(addr: str, *, is_china_ip: bool) -> str:
        if is_china_ip:
            return normalize_cidr(
                addr.removesuffix(",no-resolve")
                if addr.endswith(",no-resolve")
                else addr
            )
        if addr.endswith(",no-resolve"):
            return (
                f"IP-CIDR,{normalize_cidr(addr.removesuffix(',no-resolve'))},no-resolve"
            )
        return f"IP-CIDR,{normalize_cidr(addr)}"

    def _format_ip_asn(addr: str, *, is_ip_category: bool) -> str:
        if addr.endswith(",no-resolve"):
            return f"IP-ASN,{addr.removesuffix(',no-resolve')},no-resolve"
        return f"IP-ASN,{addr}{',no-resolve' if is_ip_category else ''}"

    def _format_geoip(addr: str, *, is_ip_category: bool) -> str:
        if addr.endswith(",no-resolve"):
            return f"GEOIP,{addr.removesuffix(',no-resolve')},no-resolve"
        return f"GEOIP,{addr}{',no-resolve' if is_ip_category else ''}"

    def _filter_valid_regex(addresses: list[str]) -> list[str]:
        return [addr for addr in addresses if validate_regex(addr)]

    def _filter_network_protocols(addresses: list[str]) -> list[str]:
        return [
            entry.upper() for entry in addresses if entry.upper() in _NETWORK_PROTOCOLS
        ]

    def _process_logical_rule(addr: str, pattern: str) -> str | None:
        if not addr or addr.startswith("(("):
            return None

        parts = addr.split(",", 1)
        if len(parts) == 2:  # noqa: PLR2004
            mapped_pattern = MIHOMO_ALIAS.get(parts[0].strip(), parts[0].strip())
            return f"{pattern},{mapped_pattern},{parts[1].strip()}"
        return f"{pattern},{addr.strip()}"

    def _process_nested_logical_rule(addr: str, pattern: str) -> str:
        processed_addr = addr
        for original, mapped in MIHOMO_ALIAS.items():
            processed_addr = processed_addr.replace(f"({original},", f"({mapped},")
        return f"{pattern},{processed_addr.strip() if processed_addr else ''}"

    def _process_logical_rules(addresses: list[str], pattern: str) -> list[str]:
        results: list[str] = []
        for addr in addresses:
            if result := _process_logical_rule(addr, pattern):
                results.append(result)
            elif addr:
                results.append(_process_nested_logical_rule(addr, pattern))
        return results

    def _process_ports(addresses: list[str], pattern: str) -> list[str]:
        ports, ranges = process_ports(addresses)
        results: list[str] = []
        if ports:
            results.extend(f"{pattern},{port}" for port in ports)
        if ranges:
            results.extend(f"{pattern},{range_val}" for range_val in ranges)
        return results

    def _process_domainset_rules(grouped: pl.DataFrame) -> list[str]:
        domain_rules: list[str] = []
        suffix_rules: list[str] = []

        for block in grouped.iter_rows(named=True):
            pattern, addresses = block["pattern"], block["address"]
            if pattern == "DOMAIN":
                domain_rules.extend(addresses)
            elif pattern == "DOMAIN-SUFFIX":
                suffix_rules.extend(_format_domain_suffix(addr) for addr in addresses)

        return domain_rules + suffix_rules

    def _process_regular_rules(  # noqa: C901, PLR0912, PLR0915
        pattern_dict: dict[str, list[str]],
        *,
        is_china_ip: bool,
        is_ip_category: bool,
    ) -> list[str]:
        rules: list[str] = []

        for pattern in MIHOMO_ORDER:
            if pattern not in pattern_dict:
                continue

            addresses = pattern_dict[pattern]

            match pattern:
                case "DOMAIN":
                    rules.extend(f"DOMAIN,{addr}" for addr in addresses)
                case "DOMAIN-SUFFIX":
                    rules.extend(
                        f"DOMAIN-SUFFIX,{addr.lstrip('.')}" for addr in addresses
                    )
                case "DOMAIN-KEYWORD":
                    rules.extend(f"DOMAIN-KEYWORD,{addr}" for addr in addresses)
                case "DOMAIN-REGEX":
                    rules.extend(
                        f"DOMAIN-REGEX,{addr}"
                        for addr in _filter_valid_regex(addresses)
                    )
                case "DOMAIN-WILDCARD":
                    rules.extend(f"DOMAIN-WILDCARD,{addr}" for addr in addresses)
                case "GEOSITE":
                    rules.extend(f"GEOSITE,{addr}" for addr in addresses)
                case "IP-CIDR":
                    rules.extend(
                        _format_ip_cidr(addr, is_china_ip=is_china_ip)
                        for addr in addresses
                    )
                case "IP-SUFFIX":
                    rules.extend(f"IP-SUFFIX,{addr}" for addr in addresses)
                case "IP-ASN":
                    rules.extend(
                        _format_ip_asn(addr, is_ip_category=is_ip_category)
                        for addr in addresses
                    )
                case "GEOIP":
                    rules.extend(
                        _format_geoip(addr, is_ip_category=is_ip_category)
                        for addr in addresses
                    )
                case "SRC-IP-CIDR":
                    rules.extend(
                        f"SRC-IP-CIDR,{normalize_cidr(addr)}" for addr in addresses
                    )
                case "SRC-IP-SUFFIX":
                    rules.extend(f"SRC-IP-SUFFIX,{addr}" for addr in addresses)
                case "SRC-IP-ASN":
                    rules.extend(f"SRC-IP-ASN,{addr}" for addr in addresses)
                case "SRC-GEOIP":
                    rules.extend(f"SRC-GEOIP,{addr}" for addr in addresses)
                case "DST-PORT" | "SRC-PORT" | "IN-PORT":
                    rules.extend(_process_ports(addresses, pattern))
                case "PROCESS-NAME":
                    rules.extend(f"PROCESS-NAME,{addr}" for addr in addresses)
                case "PROCESS-PATH":
                    rules.extend(f"PROCESS-PATH,{addr}" for addr in addresses)
                case "NETWORK":
                    if proto := _filter_network_protocols(addresses):
                        rules.extend(f"NETWORK,{p}" for p in proto)
                case "IN-TYPE":
                    rules.extend(f"IN-TYPE,{addr}" for addr in addresses)
                case "IN-USER":
                    rules.extend(f"IN-USER,{addr}" for addr in addresses)
                case "IN-NAME":
                    rules.extend(f"IN-NAME,{addr}" for addr in addresses)
                case "PROCESS-NAME-REGEX":
                    rules.extend(
                        f"PROCESS-NAME-REGEX,{addr}"
                        for addr in _filter_valid_regex(addresses)
                    )
                case "PROCESS-PATH-REGEX":
                    rules.extend(
                        f"PROCESS-PATH-REGEX,{addr}"
                        for addr in _filter_valid_regex(addresses)
                    )
                case "UID":
                    rules.extend(f"UID,{addr}" for addr in addresses)
                case "DSCP":
                    rules.extend(f"DSCP,{addr}" for addr in addresses)
                case "RULE-SET":
                    rules.extend(f"RULE-SET,{addr}" for addr in addresses)
                case "AND" | "OR" | "NOT" | "SUB-RULE":
                    rules.extend(_process_logical_rules(addresses, pattern))
                case "MATCH":
                    rules.extend(f"MATCH,{addr}" for addr in addresses)

        return rules

    is_china_ip = _is_china_ip_file()
    is_ip_category = category == "ip"
    grouped = frame.group_by("pattern").agg(pl.col("address"))
    pattern_dict = {
        block["pattern"]: block["address"] for block in grouped.iter_rows(named=True)
    }

    if category == "domainset":
        rules = _process_domainset_rules(grouped)
    else:
        rules = _process_regular_rules(
            pattern_dict, is_china_ip=is_china_ip, is_ip_category=is_ip_category
        )

    if cidrs:
        if is_china_ip:
            rules.extend(normalize_cidr(addr) for addr in cidrs)
        else:
            rules.extend(f"IP-CIDR,{normalize_cidr(addr)}" for addr in cidrs)

    return rules or None


async def prepare_frame(  # noqa: D103
    url: str,
    aliases: tuple[str, ...],
    deny: frozenset[str],
) -> tuple[pl.DataFrame, list[str]] | None:
    frame = await ingest(url)
    if frame.height == 0 or not frame.columns:
        return None

    _excluded_addresses = frozenset(
        {
            "th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
            "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
        },
    )

    frame = frame.filter(
        ~pl.col("pattern").str.contains("#")
        & ~pl.col("address").is_in(_excluded_addresses)
        & pl.col("pattern").is_in(aliases),
    )
    if frame.height == 0:
        return None

    invalid = frame.filter(pl.col("pattern").is_in(list(deny)))
    if invalid.height > 0:
        obsolete = list(set(invalid["pattern"].unique().to_list()) & set(deny))
        if obsolete:
            frame = frame.filter(~pl.col("pattern").is_in(obsolete))

    asn_view = frame.filter(pl.col("pattern") == "IP-ASN")
    cidrs: list[str] = []
    if asn_view.height > 0:
        cidrs = await merge(asn_view["address"].unique().to_list())

    return frame, cidrs


async def emit_mihomo_yaml(
    url: str, directory: str, category: str
) -> anyio.Path | None:  # noqa: D103
    result = await prepare_frame(url, MIHOMO_ALIASES, MIHOMO_DENY)
    if result is None:
        return None

    frame, cidrs = result
    frame = frame.with_columns(pl.col("pattern").replace(MIHOMO_ALIAS))

    await anyio.Path(directory).mkdir(exist_ok=True, parents=True)

    filename = anyio.Path(url).stem.replace("_", "-")
    rules = compose_mihomo_yaml(frame, cidrs, category, filename)
    if not rules:
        return None

    file_name = anyio.Path(directory, f"{filename}.{category}.yaml")
    async with await anyio.Path(file_name).open("w", encoding="utf-8") as handle:
        if "__custom_yaml__" in rules:
            await handle.write(rules["__custom_yaml__"])
        else:
            await handle.write(
                yaml.dump(rules, default_flow_style=False, sort_keys=False)
            )

    return file_name


async def emit_mihomo_text(
    url: str, directory: str, category: str
) -> anyio.Path | None:  # noqa: D103
    result = await prepare_frame(url, MIHOMO_ALIASES, MIHOMO_DENY)
    if result is None:
        return None

    frame, cidrs = result
    frame = frame.with_columns(pl.col("pattern").replace(MIHOMO_ALIAS))

    await anyio.Path(directory).mkdir(exist_ok=True, parents=True)

    filename = anyio.Path(url).stem.replace("_", "-")
    rules = compose_mihomo_text(frame, cidrs, category, filename)
    if not rules:
        return None

    file_name = anyio.Path(directory, f"{filename}.{category}.txt")
    async with await anyio.Path(file_name).open("w", encoding="utf-8") as handle:
        await handle.write("\n".join(rules))

    return file_name


async def emit_singbox_json(
    url: str, directory: str, category: str
) -> anyio.Path | None:  # noqa: D103
    result = await prepare_frame(url, SINGBOX_ALIASES, SINGBOX_DENY)
    if result is None:
        return None

    frame, cidrs = result
    frame = frame.with_columns(pl.col("pattern").replace(SINGBOX_ALIAS))

    await anyio.Path(directory).mkdir(exist_ok=True, parents=True)

    rules = compose_singbox_json(frame, cidrs)
    if not rules.get("rules"):
        return None

    filename = anyio.Path(url).stem.replace("_", "-")
    file_name = anyio.Path(directory, f"{filename}.{category}.json")
    async with await anyio.Path(file_name).open("wb") as handle:
        await handle.write(orjson.dumps(rules, option=orjson.OPT_INDENT_2))

    return file_name


async def find_directory(*paths: str) -> anyio.Path | None:  # noqa: D103
    for path in paths:
        dir_path = anyio.Path(path)
        if await dir_path.exists():
            return dir_path
    return None


async def create_subdirectories(
    base_dirs: list[anyio.Path], subdirs: frozenset[str]
) -> None:  # noqa: D103
    await asyncio.gather(
        *(
            (base_dir / subdir).mkdir(exist_ok=True, parents=True)
            for base_dir in base_dirs
            for subdir in subdirs
        ),
    )


async def collect_conf_files(
    list_dir: anyio.Path, categories: frozenset[str]
) -> list[tuple[anyio.Path, str]]:  # noqa: D103
    conf_files: list[tuple[anyio.Path, str]] = []
    for category in categories:
        subdir_path = list_dir / category
        if await subdir_path.exists():
            conf_files.extend(
                [
                    (conf_file, category)
                    async for conf_file in subdir_path.glob("*.conf")
                ]
            )
    return conf_files


async def create_emit_tasks(  # noqa: D103
    conf_files: list[tuple[anyio.Path, str]],
    base_dir: anyio.Path,
    emit_func: any,
) -> list[asyncio.Task]:
    return [
        asyncio.create_task(
            emit_func(
                f"file://{await conf_file.absolute()}",
                str(base_dir / category),
                category,
            ),
        )
        for conf_file, category in conf_files
    ]


async def main() -> None:  # noqa: D103
    _subdirs = frozenset({"domainset", "ip", "non_ip", "dns"})
    _categories = frozenset({"domainset", "ip", "non_ip"})

    list_dir = await find_directory("dist/List", "../dist/List")
    if list_dir is None:
        return

    singbox_json_base = anyio.Path("sing-box/json")
    singbox_srs_base = anyio.Path("sing-box/srs")
    mihomo_yaml_base = anyio.Path("mihomo/yaml")
    mihomo_text_base = anyio.Path("mihomo/text")
    mihomo_mrs_base = anyio.Path("mihomo/mrs")

    await create_subdirectories([singbox_json_base, singbox_srs_base], _subdirs)
    await create_subdirectories(
        [mihomo_yaml_base, mihomo_text_base, mihomo_mrs_base], _subdirs
    )

    conf_files = await collect_conf_files(list_dir, _categories)

    singbox_tasks = await create_emit_tasks(
        conf_files, singbox_json_base, emit_singbox_json
    )
    mihomo_yaml_tasks = await create_emit_tasks(
        conf_files, mihomo_yaml_base, emit_mihomo_yaml
    )
    mihomo_text_tasks = await create_emit_tasks(
        conf_files, mihomo_text_base, emit_mihomo_text
    )

    modules_dir = await find_directory(
        "dist/Modules/Rules/sukka_local_dns_mapping",
        "../dist/Modules/Rules/sukka_local_dns_mapping",
    )
    if modules_dir is not None:
        dns_files = [(f, "dns") async for f in modules_dir.glob("*.conf")]

        singbox_tasks.extend(
            await create_emit_tasks(dns_files, singbox_json_base, emit_singbox_json)
        )
        mihomo_yaml_tasks.extend(
            await create_emit_tasks(dns_files, mihomo_yaml_base, emit_mihomo_yaml)
        )
        mihomo_text_tasks.extend(
            await create_emit_tasks(dns_files, mihomo_text_base, emit_mihomo_text)
        )

    all_tasks = singbox_tasks + mihomo_yaml_tasks + mihomo_text_tasks
    if all_tasks:
        await asyncio.gather(*all_tasks, return_exceptions=False)

    await POOL.aclose()


if __name__ == "__main__":
    asyncio.run(main())
