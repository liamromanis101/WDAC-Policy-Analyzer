# WDAC-Policy-Analyzer
WDAC Policy Analyzer Script - Powershell

# WDAC Runtime Assessment Tool

This project provides a **non-admin, CLM-safe Windows Defender Application Control (WDAC) assessment script** that:

-   Parses WDAC XML CI policies
-   Tests real binaries on disk
-   Performs rename/relocation execution attempts
-   Attributes blocks to WDAC, Defender, AppLocker, or Unknown
-   Detects signer coverage gaps
-   Rates severity automatically
-   Produces a CSV findings report
-   Prints posture + enforcement summary to stdout

It is designed for:

-   WDAC configuration reviews
-   CI policy validation
-   Bypass discovery
-   Red/blue team assurance
-   Enterprise hardening assessments

No elevation required.

------------------------------------------------------------------------

## Features

### Policy Analysis

-   Enumerates Allow + Deny rules
-   Handles malformed rules (friendly name only, missing paths, etc.)
-   Always outputs one CSV row per rule
-   Checks whether rule targets actually exist on disk

### Runtime Enforcement Testing

For each existing binary:

-   Copies and renames it
-   Attempts execution
-   Determines outcome:

BlockedByWDAC\
BlockedByDefender\
BlockedByAppLocker\
UnknownBlock\
Allowed

Uses polling to avoid Defender timing race conditions.

### WDAC Decision Mapping

Each execution is classified as:

-   BlockedByWDAC
-   AllowedByWDAC
-   NotBlockedByWDAC

This explicitly answers:

Did WDAC enforce this?

### Identity Enforcement

Uses Authenticode to detect:

Yes / No / Unsigned / Unknown

### Severity Auto-Rating

Deny rule allowed -- Critical\
Unsigned binary allowed -- Critical\
Signed but signer not enforced -- High\
Not blocked by WDAC -- Low\
Blocked by WDAC -- Info\
Binary missing -- Info

### Global WDAC Posture (stdout)

-   XML PolicyRuleOptions
-   Registry CI flags
-   Code Integrity log presence
-   WDAC block count
-   Last WDAC block timestamp
-   AppLocker service
-   Defender service

Active policy enumeration is non-admin and based on Code Integrity event 3099.

The script advises:

Run 'citool -lp' as Administrator to enumerate active policies.

### CSV Output

Produces WDAC_Runtime_Assessment.csv

Columns:

RuleID\
RuleType\
RuleValue\
ResolvedBinary\
ExistsOnSystem\
WDACDecision\
ExecutionOutcome\
Publisher\
IdentityEnforced\
Severity\
Notes

### Final Stdout Summary

Includes counts for:

AllowedByWDAC\
NotBlockedByWDAC\
BlockedByWDAC\
BlockedByDefender\
BlockedByAppLocker\
BlockedByUnknown\
ExecutedWithoutAnyBlock\
Critical findings\
High findings

------------------------------------------------------------------------

## Requirements

-   Windows 10 / 11 or Server with WDAC capability
-   PowerShell 5.1+
-   Read access to CodeIntegrity logs

Works in Constrained Language Mode and standard user context.

------------------------------------------------------------------------

## Usage

powershell -NoProfile -File Test-WDACRuntime.ps1 -PolicyXml policy.xml

------------------------------------------------------------------------

## Recommended Workflow

1.  Export WDAC policy XML
2.  Copy script + XML to target system
3.  Run script as standard user
4.  Review CSV
5.  If admin available, confirm active policies:

citool -lp

------------------------------------------------------------------------

## What This Tool Answers

-   Is WDAC actually enforcing?
-   Which binaries bypass WDAC?
-   Which are only blocked by Defender/AppLocker?
-   Are deny rules effective?
-   Are unsigned binaries allowed?
-   Is signer coverage complete?
-   Are binaries referenced by policy even present?
-   How much real execution exposure exists?

------------------------------------------------------------------------

## Important Notes

-   Defender blocks are asynchronous; script polls logs to avoid false
    UnknownBlock results.
-   WDAC has no Windows service -- enforcement is kernel-based.
-   Registry is used only for posture flags, not active policy
    enumeration.
-   CSV always includes every rule, even if invalid.

------------------------------------------------------------------------

## Disclaimer

This tool performs live execution tests.

Use only on systems you own or are authorized to assess.
