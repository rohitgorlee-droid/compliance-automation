# Policy Compliance Checker (base version)

Evaluates resources against compliance rules and reports every violation.

## Requirements
Python 3.9+ (standard library only)

## Run
    python policy_compliance_checker.py                                          # built-in demo
    python policy_compliance_checker.py samples/rules.json samples/resources.json

## Operators
equals, not_equals, in, not_in, exists, gte, lte

## Exit codes
0 = compliant, 1 = violations found, 2 = HIGH severity violations found
