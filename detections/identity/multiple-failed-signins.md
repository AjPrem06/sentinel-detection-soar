# Multiple Failed Sign-ins by Single User

## Goal
Detect user accounts that experience multiple failed sign-in attempts
within a 24-hour period. This may indicate password guessing or
unauthorized access attempts.

## Data Sources
- SigninLogs

## Query
```kql
let timeframe = 24h;
let failureThreshold = 5;
let trustedIPs = dynamic([
    "10.0.0.1",
    "10.0.0.2"
]);

SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType != 0
| where IPAddress !in (trustedIPs)
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts >= failureThreshold
```

## MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique: T1110 – Brute Force

## Expected Output
- UserPrincipalName
- IPAddress
- FailedAttempts

## Tuning / False Positives
- Users repeatedly mistyping passwords
- Sign-ins from corporate VPN IPs
- Service or automation accounts

## Tuning / False Positives
- Users mistyping passwords
- Sign-ins from trusted corporate or VPN IP addresses
- Automated service accounts

Tuning ideas:
- Maintain a trusted IP allow-list
- Adjust failure threshold based on environment size
- Exclude known service accounts



