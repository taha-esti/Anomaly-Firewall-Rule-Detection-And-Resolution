import csv
import itertools
import logging
import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Tuple, Union, Optional


# -------------------------
# Parsing helpers
# -------------------------

def split_list(cell: str) -> List[str]:
    """Split comma-separated cell into tokens, stripping whitespace."""
    if cell is None:
        return []
    s = str(cell).strip()
    if not s:
        return []
    return [t.strip() for t in s.split(",") if t.strip()]


def sniff_delimiter(path: str) -> str:
    """Auto-detect delimiter; your sample looks tab-separated."""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", "\t", ";", "|"])
        return dialect.delimiter
    except csv.Error:
        # Default to tab because your example is TSV-looking.
        return "\t"


# -------------------------
# Value models: IPs & ports
# -------------------------

IPNet = ipaddress._BaseNetwork  # IPv4Network or IPv6Network


def parse_ip_tokens(tokens: List[str]) -> Tuple[bool, List[IPNet], List[str]]:
    """
    Returns: (is_any, parsed_networks, non_ip_tokens)
    - IPs become /32 (or /128)
    - CIDRs become networks
    - non-IP tokens (like "any", "NetGroup_X") are kept as strings
    """
    # In FMC exports, an empty cell typically means "ANY".
    if not tokens:
        return True, [], []

    is_any = False
    nets: List[IPNet] = []
    others: List[str] = []

    for t in tokens:
        tl = t.lower()
        if tl in {"any", "all"}:
            is_any = True
            continue

        # Some FMC exports might contain object names; treat as string token.
        try:
            if "/" in t:
                nets.append(ipaddress.ip_network(t.strip(), strict=False))
            else:
                ip = ipaddress.ip_address(t.strip())
                nets.append(ipaddress.ip_network(ip.exploded + ("/32" if ip.version == 4 else "/128"), strict=False))
        except ValueError:
            others.append(t)

    return is_any, nets, others


PortInterval = Tuple[int, int]  # inclusive range


def parse_port_tokens(tokens: List[str]) -> Tuple[bool, List[PortInterval], List[str]]:
    """
    Supports:
      - "80"
      - "80-90"
      - named groups like "scom_ports"
      - "any"
    """
    # In FMC exports, an empty cell typically means "ANY".
    if not tokens:
        return True, [], []

    is_any = False
    intervals: List[PortInterval] = []
    others: List[str] = []

    for t in tokens:
        tl = t.lower()
        if tl in {"any", "all"}:
            is_any = True
            continue

        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", t)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            lo, hi = min(a, b), max(a, b)
            intervals.append((lo, hi))
            continue

        if re.fullmatch(r"\d+", t):
            p = int(t)
            intervals.append((p, p))
            continue

        # Named port object / group
        others.append(t)

    return is_any, intervals, others


def intervals_overlap(a: PortInterval, b: PortInterval) -> bool:
    return not (a[1] < b[0] or b[1] < a[0])


def intervals_subset(a: PortInterval, b: PortInterval) -> bool:
    return b[0] <= a[0] and a[1] <= b[1]


# -------------------------
# Rule object (adapted to your CSV)
# -------------------------

@dataclass
class Rule:
    name: str
    actions: str  # keep same attribute name used by resolver: rule.actions
    src_zones: List[str] = field(default_factory=list)
    dst_zones: List[str] = field(default_factory=list)
    app_filters: List[str] = field(default_factory=list)

    src_any: bool = False
    src_nets: List[IPNet] = field(default_factory=list)
    src_non_ip: List[str] = field(default_factory=list)

    dst_any: bool = False
    dst_nets: List[IPNet] = field(default_factory=list)
    dst_non_ip: List[str] = field(default_factory=list)

    sp_any: bool = False
    sp_intervals: List[PortInterval] = field(default_factory=list)
    sp_non_num: List[str] = field(default_factory=list)

    dp_any: bool = False
    dp_intervals: List[PortInterval] = field(default_factory=list)
    dp_non_num: List[str] = field(default_factory=list)

    enabled: Optional[bool] = None
    raw: dict = field(default_factory=dict)  # keep original row if you want to write back later

    def __str__(self) -> str:
        return f"Rule(name={self.name!r}, action={self.actions}, src={self.raw.get('Source Networks_translated') or self.raw.get('Source Networks')}, dst={self.raw.get('Destination Networks_translated') or self.raw.get('Destination Networks')})"

    # ---- overlap/subset helpers per dimension ----

    @staticmethod
    def _zones_overlap(a: List[str], b: List[str]) -> bool:
        if not a or not b:
            return True  # empty = ANY
        return bool(set(a) & set(b))

    @staticmethod
    def _zones_subset(a: List[str], b: List[str]) -> bool:
        # Empty list means ANY.
        # ANY is only a subset of ANY; ANY is not a subset of a specific set of zones.
        if not a:
            return not b
        # If b is ANY, it covers everything.
        if not b:
            return True
        return set(a).issubset(set(b))

    @staticmethod
    def _apps_overlap(a: List[str], b: List[str]) -> bool:
        if not a or not b:
            return True
        return bool(set(a) & set(b))

    @staticmethod
    def _apps_subset(a: List[str], b: List[str]) -> bool:
        if not a:
            return True if not b else False  # ANY apps is not subset of specific apps
        return set(a).issubset(set(b)) if b else True

    @staticmethod
    def _ip_overlap(a_any: bool, a_nets: List[IPNet], a_other: List[str],
                    b_any: bool, b_nets: List[IPNet], b_other: List[str]) -> bool:
        if a_any or b_any:
            return True

        # string tokens overlap only if they match
        if a_other and b_other and (set(a_other) & set(b_other)):
            return True

        # network overlap
        for an in a_nets:
            for bn in b_nets:
                if an.version != bn.version:
                    continue
                if an.overlaps(bn):
                    return True

        # If one side has only "others" and the other has only nets, we can't prove overlap; treat as unknown -> assume overlap
        # (safer to avoid false "disjoint")
        if (a_other and b_nets) or (b_other and a_nets):
            return True

        return False

    @staticmethod
    def _ip_subset(a_any: bool, a_nets: List[IPNet], a_other: List[str],
                   b_any: bool, b_nets: List[IPNet], b_other: List[str]) -> bool:
        # "ANY" is broad; it's only subset of ANY.
        if a_any:
            return b_any
        if b_any:
            return True

        # If rule uses named objects, only consider subset if all names are contained
        if a_other:
            if not b_other:
                return False
            if not set(a_other).issubset(set(b_other)):
                return False

        # Each a_net must be contained in at least one b_net
        for an in a_nets:
            covered = False
            for bn in b_nets:
                if an.version != bn.version:
                    continue
                if an.subnet_of(bn):
                    covered = True
                    break
            if not covered:
                return False

        # If a has nets but b has none (and not ANY), not subset
        if a_nets and not b_nets and not b_other:
            return False

        return True

    @staticmethod
    def _ports_overlap(a_any: bool, a_int: List[PortInterval], a_other: List[str],
                       b_any: bool, b_int: List[PortInterval], b_other: List[str]) -> bool:
        if a_any or b_any:
            return True

        if a_other and b_other and (set(a_other) & set(b_other)):
            return True

        for ai in a_int:
            for bi in b_int:
                if intervals_overlap(ai, bi):
                    return True

        if (a_other and b_int) or (b_other and a_int):
            return True

        return False

    @staticmethod
    def _ports_subset(a_any: bool, a_int: List[PortInterval], a_other: List[str],
                      b_any: bool, b_int: List[PortInterval], b_other: List[str]) -> bool:
        if a_any:
            return b_any
        if b_any:
            return True

        if a_other:
            if not b_other:
                return False
            if not set(a_other).issubset(set(b_other)):
                return False

        # every a interval must be covered by some b interval
        for ai in a_int:
            covered = False
            for bi in b_int:
                if intervals_subset(ai, bi):
                    covered = True
                    break
            if not covered:
                return False

        if a_int and not b_int and not b_other:
            return False

        return True

    # ---- API expected by your resolver code ----

    def disjoint(self, other: "Rule") -> bool:
        # If ANY dimension has no overlap, rules are disjoint.
        if not self._zones_overlap(self.src_zones, other.src_zones):
            return True
        if not self._zones_overlap(self.dst_zones, other.dst_zones):
            return True
        if not self._apps_overlap(self.app_filters, other.app_filters):
            return True
        if not self._ip_overlap(self.src_any, self.src_nets, self.src_non_ip,
                                other.src_any, other.src_nets, other.src_non_ip):
            return True
        if not self._ip_overlap(self.dst_any, self.dst_nets, self.dst_non_ip,
                                other.dst_any, other.dst_nets, other.dst_non_ip):
            return True
        if not self._ports_overlap(self.sp_any, self.sp_intervals, self.sp_non_num,
                                   other.sp_any, other.sp_intervals, other.sp_non_num):
            return True
        if not self._ports_overlap(self.dp_any, self.dp_intervals, self.dp_non_num,
                                   other.dp_any, other.dp_intervals, other.dp_non_num):
            return True
        return False

    def issubset(self, other: "Rule") -> bool:
        # self is subset of other if all dimensions are subset
        if not self._zones_subset(self.src_zones, other.src_zones):
            return False
        if not self._zones_subset(self.dst_zones, other.dst_zones):
            return False
        if not self._apps_subset(self.app_filters, other.app_filters):
            return False
        if not self._ip_subset(self.src_any, self.src_nets, self.src_non_ip,
                               other.src_any, other.src_nets, other.src_non_ip):
            return False
        if not self._ip_subset(self.dst_any, self.dst_nets, self.dst_non_ip,
                               other.dst_any, other.dst_nets, other.dst_non_ip):
            return False
        if not self._ports_subset(self.sp_any, self.sp_intervals, self.sp_non_num,
                                  other.sp_any, other.sp_intervals, other.sp_non_num):
            return False
        if not self._ports_subset(self.dp_any, self.dp_intervals, self.dp_non_num,
                                  other.dp_any, other.dp_intervals, other.dp_non_num):
            return False
        return True


# -------------------------
# Resolver adapted to CSV fields
# -------------------------

class AnomalyResolver:
    # Adapted to your CSV dimensions (instead of direction/nw_proto/...):
    # These are used mainly by the tree-merge features; detection/resolution uses Rule methods.
    attr_list = [
        "Source Zones",
        "Destination Zones",
        "Source Networks",
        "Destination Networks",
        "Application filters",
        "Source Ports",
        "Destination Ports",
        "actions",
        "None",
    ]
    attr_dict = {}
    tree = None

    def __init__(self, log_output="console", log_level="INFO"):
        for key in self.attr_list:
            self.attr_dict[key] = 0

        self.resolver_logger = logging.getLogger("AnomalyResolver")
        self.resolver_logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        if log_level not in ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]:
            log_level = "INFO"
        log_level = eval("logging." + log_level)

        if "file" in log_output:
            self.LOG_FILENAME = "anomaly_resolver.log"
            file_handler = logging.FileHandler(self.LOG_FILENAME)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            self.resolver_logger.addHandler(file_handler)

        if "console" in log_output:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(log_level)
            self.resolver_logger.addHandler(console_handler)

        self.resolver_logger.info("Start Anomaly Resolver (CSV-adapted)")

    def _fmt_rule(self, rule: Rule) -> str:
        """Compact, log-friendly rendering of a rule using translated columns when present."""
        def _cell(*keys: str) -> str:
            for k in keys:
                v = rule.raw.get(k)
                if v is None:
                    continue
                s = str(v).strip()
                if s:
                    return s
            return "*"

        src = _cell("Source Networks_translated", "Source Networks")
        dst = _cell("Destination Networks_translated", "Destination Networks")
        sp = _cell("Source Ports_translated", "Source Ports")
        dp = _cell("Destination Ports_translated", "Destination Ports")
        zones = (rule.raw.get("Source Zones") or "*", rule.raw.get("Destination Zones") or "*")
        apps = rule.raw.get("Application filters") or ""
        name = rule.name or "<unnamed>"
        return f"{name}: <SZ:{zones[0]} DZ:{zones[1]} SRC:{src} SP:{sp} DST:{dst} DP:{dp} APP:{apps} ACT:{rule.actions}>"

    def detect_anomalies(self, rules_list: List[Rule]):
        anomalies = self.find_anomalies(rules_list)
        self.resolver_logger.info("Perform Detection (pairwise anomalies only)")
        for anomaly_type, rule_0, rule_1 in anomalies:
            self.resolver_logger.info(
                "%s\n\t%s\n\t%s", anomaly_type, self._fmt_rule(rule_0), self._fmt_rule(rule_1)
            )
        return anomalies

    def find_anomalies(self, rules_list: List[Rule]):
        """
        Returns a list of (anomaly_type, rule_a, rule_b) for all overlapping pairs.
        anomaly_type is one of: 'Redundancy Anomaly', 'Shadowing Anomaly', 'Correlation Anomaly'.
        """
        anomalies = []
        for rule_0, rule_1 in itertools.combinations(rules_list, 2):
            if rule_0.disjoint(rule_1):
                continue

            if rule_0.issubset(rule_1) or rule_1.issubset(rule_0):
                if rule_0.actions == rule_1.actions:
                    anomalies.append(("Redundancy Anomaly", rule_0, rule_1))
                else:
                    anomalies.append(("Shadowing Anomaly", rule_0, rule_1))
                continue

            if (
                (not rule_0.issubset(rule_1))
                and (not rule_1.issubset(rule_0))
                and (rule_0.actions != rule_1.actions)
            ):
                anomalies.append(("Correlation Anomaly", rule_0, rule_1))
                continue
        return anomalies

    def resolve_anomalies(self, old_rules_list: List[Rule]) -> List[Rule]:
        """
        Safe resolver for your FMC CSV:
        - Removes truly redundant rules (subset + same action).
        - Keeps everything else (does not attempt range splitting).
        """
        self.resolver_logger.info(
            "Perform Resolving\nOld rules list:\n\t" + "\n\t".join(map(str, old_rules_list))
        )

        new_rules_list: List[Rule] = list(old_rules_list)
        removed_ids = set()

        for a, b in itertools.combinations(list(new_rules_list), 2):
            if id(a) in removed_ids or id(b) in removed_ids:
                continue
            if a.disjoint(b):
                continue

            # remove the smaller redundant one (subset + same action)
            if a.issubset(b) and a.actions == b.actions:
                self.resolver_logger.info("Redundant rule (removed): %s  ⊆  %s", a.name, b.name)
                removed_ids.add(id(a))
            elif b.issubset(a) and a.actions == b.actions:
                self.resolver_logger.info("Redundant rule (removed): %s  ⊆  %s", b.name, a.name)
                removed_ids.add(id(b))

        new_rules_list = [r for r in new_rules_list if id(r) not in removed_ids]

        self.resolver_logger.info(
            "New rules list:\n\t" + "\n\t".join(map(str, new_rules_list))
        )
        self.resolver_logger.info("Finish anomalies resolving (safe mode)")
        return new_rules_list


# -------------------------
# Load rules from your CSV/TSV
# -------------------------

def load_rules_from_csv(path: str) -> Tuple[List[Rule], List[str], str]:
    delim = sniff_delimiter(path)

    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=delim)
        headers = reader.fieldnames or []

        rules: List[Rule] = []
        for row in reader:
            name = (row.get("Rule Name") or "").strip()
            action = (row.get("Action") or "").strip().upper() or "ALLOW"

            # Prefer *_translated columns if present
            src_cell = row.get("Source Networks_translated") or row.get("Source Networks") or ""
            dst_cell = row.get("Destination Networks_translated") or row.get("Destination Networks") or ""
            sp_cell = row.get("Source Ports_translated") or row.get("Source Ports") or ""
            dp_cell = row.get("Destination Ports_translated") or row.get("Destination Ports") or ""

            src_tokens = split_list(src_cell)
            dst_tokens = split_list(dst_cell)
            sp_tokens = split_list(sp_cell)
            dp_tokens = split_list(dp_cell)

            src_any, src_nets, src_other = parse_ip_tokens(src_tokens)
            dst_any, dst_nets, dst_other = parse_ip_tokens(dst_tokens)
            sp_any, sp_int, sp_other = parse_port_tokens(sp_tokens)
            dp_any, dp_int, dp_other = parse_port_tokens(dp_tokens)

            enabled_val = row.get("Enabled_bool") or row.get("Enabled")
            enabled = None
            if enabled_val is not None and str(enabled_val).strip() != "":
                enabled = str(enabled_val).strip().lower() in {"true", "1", "yes"}

            r = Rule(
                name=name,
                actions=action,
                src_zones=split_list(row.get("Source Zones", "")),
                dst_zones=split_list(row.get("Destination Zones", "")),
                app_filters=split_list(row.get("Application filters", "")),
                src_any=src_any, src_nets=src_nets, src_non_ip=src_other,
                dst_any=dst_any, dst_nets=dst_nets, dst_non_ip=dst_other,
                sp_any=sp_any, sp_intervals=sp_int, sp_non_num=sp_other,
                dp_any=dp_any, dp_intervals=dp_int, dp_non_num=dp_other,
                enabled=enabled,
                raw=row,
            )
            rules.append(r)

    return rules, headers, delim


def write_rules_to_csv(path: str, rules: List[Rule], headers: List[str], delimiter: str):
    # Write back the original rows in the same schema, just filtered/reordered by `rules`
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers, delimiter=delimiter)
        w.writeheader()
        for r in rules:
            w.writerow(r.raw)

def write_anomalies_to_csv(path: str, anomalies, delimiter: str = ","):
    """
    Writes anomaly pairs to a CSV for review.
    """
    headers = [
        "Anomaly Type",
        "Rule A Name",
        "Rule A Action",
        "Rule A Source Zones",
        "Rule A Destination Zones",
        "Rule A Source Networks",
        "Rule A Source Ports",
        "Rule A Destination Networks",
        "Rule A Destination Ports",
        "Rule A Application filters",
        "Rule B Name",
        "Rule B Action",
        "Rule B Source Zones",
        "Rule B Destination Zones",
        "Rule B Source Networks",
        "Rule B Source Ports",
        "Rule B Destination Networks",
        "Rule B Destination Ports",
        "Rule B Application filters",
    ]

    def _cell(rule: Rule, *keys: str) -> str:
        for k in keys:
            v = rule.raw.get(k)
            if v is None:
                continue
            s = str(v).strip()
            if s:
                return s
        return ""

    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter=delimiter)
        w.writerow(headers)
        for anomaly_type, a, b in anomalies:
            w.writerow(
                [
                    anomaly_type,
                    a.name,
                    a.actions,
                    _cell(a, "Source Zones"),
                    _cell(a, "Destination Zones"),
                    _cell(a, "Source Networks_translated", "Source Networks"),
                    _cell(a, "Source Ports_translated", "Source Ports"),
                    _cell(a, "Destination Networks_translated", "Destination Networks"),
                    _cell(a, "Destination Ports_translated", "Destination Ports"),
                    _cell(a, "Application filters"),
                    b.name,
                    b.actions,
                    _cell(b, "Source Zones"),
                    _cell(b, "Destination Zones"),
                    _cell(b, "Source Networks_translated", "Source Networks"),
                    _cell(b, "Source Ports_translated", "Source Ports"),
                    _cell(b, "Destination Networks_translated", "Destination Networks"),
                    _cell(b, "Destination Ports_translated", "Destination Ports"),
                    _cell(b, "Application filters"),
                ]
            )


# -------------------------
# Example CLI usage
# -------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Detect/remove redundant FMC rules from CSV/TSV export.")
    p.add_argument("input_csv", help="Path to your exported rules file (TSV/CSV).")
    p.add_argument("--log-level", default="INFO", help="INFO/DEBUG/WARNING/ERROR")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--detect-only",
        action="store_true",
        help="Only print detected anomalies (no output file, no changes).",
    )
    mode.add_argument(
        "--resolve",
        action="store_true",
        help="Remove redundant rules and write an output file.",
    )
    p.add_argument("--output", default="resolved_rules.csv", help="Output file path (used with --resolve).")
    p.add_argument("--report", help="Write detected anomaly pairs to this CSV path.")
    args = p.parse_args()

    rules, headers, delim = load_rules_from_csv(args.input_csv)

    resolver = AnomalyResolver(log_output="console", log_level=args.log_level)

    # Optional: only analyze enabled rules
    enabled_rules = [r for r in rules if r.enabled is not False]

    anomalies = resolver.detect_anomalies(enabled_rules)
    if args.report:
        write_anomalies_to_csv(args.report, anomalies, delimiter=",")
        print(f"Saved anomaly report to: {args.report}")
    if args.resolve:
        resolved = resolver.resolve_anomalies(enabled_rules)
        write_rules_to_csv(args.output, resolved, headers, delim)
        print(f"Saved resolved rules to: {args.output}")
