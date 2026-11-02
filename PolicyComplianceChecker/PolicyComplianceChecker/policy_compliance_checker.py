"""
Policy Compliance Checker (base version)

Evaluates resources (servers, buckets, databases, etc.) against a set of
compliance rules and reports every violation.

Rules and resources are plain JSON. Example rule:

    {"id": "ENC-001", "description": "Storage must be encrypted",
     "resource_type": "storage", "field": "encrypted",
     "operator": "equals", "expected": true, "severity": "HIGH"}

Example resource:

    {"name": "customer-data", "type": "storage", "encrypted": false}

Supported operators: equals, not_equals, in, not_in, exists, gte, lte

Usage:
    python policy_compliance_checker.py                         # built-in demo
    python policy_compliance_checker.py rules.json resources.json

Exit codes: 0 = compliant, 1 = violations found, 2 = HIGH severity violations found.
"""

import json
import sys
from dataclasses import dataclass
from typing import Any, Callable

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Rule:
    id: str
    description: str
    field: str
    operator: str
    expected: Any = None
    resource_type: str = "*"
    severity: str = "MEDIUM"


@dataclass
class Violation:
    rule_id: str
    description: str
    resource: str
    field: str
    expected: Any
    actual: Any
    severity: str


_MISSING = object()

OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "equals": lambda actual, expected: actual == expected,
    "not_equals": lambda actual, expected: actual != expected,
    "in": lambda actual, expected: actual in expected,
    "not_in": lambda actual, expected: actual not in expected,
    "exists": lambda actual, expected: (actual is not _MISSING) == bool(expected),
    "gte": lambda actual, expected: actual is not _MISSING and actual >= expected,
    "lte": lambda actual, expected: actual is not _MISSING and actual <= expected,
}


def load_rules(raw_rules: list[dict]) -> list[Rule]:
    rules = []
    for item in raw_rules:
        rule = Rule(**item)
        if rule.operator not in OPERATORS:
            raise ValueError(f"Rule {rule.id}: unknown operator '{rule.operator}'")
        if rule.severity not in SEVERITY_ORDER:
            raise ValueError(f"Rule {rule.id}: unknown severity '{rule.severity}'")
        rules.append(rule)
    return rules


def evaluate(rules: list[Rule], resources: list[dict]) -> list[Violation]:
    violations = []
    for resource in resources:
        for rule in rules:
            if rule.resource_type not in ("*", resource.get("type")):
                continue

            actual = resource.get(rule.field, _MISSING)

            # For every operator except "exists", a missing field is a violation.
            if actual is _MISSING and rule.operator != "exists":
                passed = False
            else:
                try:
                    passed = OPERATORS[rule.operator](actual, rule.expected)
                except TypeError:
                    passed = False  # incomparable types, e.g. str >= int

            if not passed:
                violations.append(Violation(
                    rule_id=rule.id,
                    description=rule.description,
                    resource=resource.get("name", "<unnamed>"),
                    field=rule.field,
                    expected=rule.expected,
                    actual=None if actual is _MISSING else actual,
                    severity=rule.severity,
                ))

    violations.sort(key=lambda v: (SEVERITY_ORDER[v.severity], v.resource, v.rule_id))
    return violations


def print_report(rules: list[Rule], resources: list[dict], violations: list[Violation]) -> None:
    print("=== Policy Compliance Report ===")
    print(f"Resources checked: {len(resources)} | Rules loaded: {len(rules)}\n")

    if not violations:
        print("All resources are compliant.")
        return

    for v in violations:
        print(f"[{v.severity:<6}] {v.rule_id}  {v.resource}")
        print(f"           {v.description}")
        print(f"           field '{v.field}': expected {v.expected!r}, found {v.actual!r}")

    counts = {s: sum(1 for v in violations if v.severity == s) for s in SEVERITY_ORDER}
    non_compliant = len({v.resource for v in violations})
    score = round(100 * (len(resources) - non_compliant) / len(resources))
    print(f"\nSummary: {len(violations)} violation(s) -> "
          f"HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}")
    print(f"Compliant resources: {len(resources) - non_compliant}/{len(resources)} ({score}%)")


def exit_code(violations: list[Violation]) -> int:
    if not violations:
        return 0
    return 2 if any(v.severity == "HIGH" for v in violations) else 1


# ---------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------

DEMO_RULES = [
    {"id": "ENC-001", "description": "Storage must be encrypted at rest",
     "resource_type": "storage", "field": "encrypted", "operator": "equals",
     "expected": True, "severity": "HIGH"},
    {"id": "NET-001", "description": "Resources must not be publicly accessible",
     "field": "public_access", "operator": "equals",
     "expected": False, "severity": "HIGH"},
    {"id": "LOG-001", "description": "Logging must be enabled",
     "field": "logging_enabled", "operator": "equals",
     "expected": True, "severity": "MEDIUM"},
    {"id": "BKP-001", "description": "Databases need at least 7 days of backups",
     "resource_type": "database", "field": "backup_retention_days", "operator": "gte",
     "expected": 7, "severity": "MEDIUM"},
    {"id": "TAG-001", "description": "Resources must have an owner tag",
     "field": "owner", "operator": "exists",
     "expected": True, "severity": "LOW"},
]

DEMO_RESOURCES = [
    {"name": "customer-data", "type": "storage", "encrypted": False,
     "public_access": True, "logging_enabled": True, "owner": "data-team"},
    {"name": "orders-db", "type": "database", "public_access": False,
     "logging_enabled": False, "backup_retention_days": 3, "owner": "backend-team"},
    {"name": "audit-archive", "type": "storage", "encrypted": True,
     "public_access": False, "logging_enabled": True, "owner": "security-team"},
    {"name": "web-server-01", "type": "server", "public_access": False,
     "logging_enabled": True},
]


def main() -> int:
    if len(sys.argv) == 3:
        with open(sys.argv[1], encoding="utf-8") as f:
            raw_rules = json.load(f)
        with open(sys.argv[2], encoding="utf-8") as f:
            resources = json.load(f)
    else:
        print("(No files given - running built-in demo)\n")
        raw_rules, resources = DEMO_RULES, DEMO_RESOURCES

    rules = load_rules(raw_rules)
    violations = evaluate(rules, resources)
    print_report(rules, resources, violations)
    return exit_code(violations)


if __name__ == "__main__":
    sys.exit(main())
