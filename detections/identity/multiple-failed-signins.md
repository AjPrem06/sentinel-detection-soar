# Multiple Failed Sign-ins by Single User

## Goal
Detect user accounts that experience multiple failed sign-in attempts
within a 24-hour period. This may indicate password guessing or
unauthorized access attempts.

## Data Sources
- SigninLogs

## Query
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
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

Tuning ideas:
- Exclude known trusted IP ranges
- Increase threshold for privileged accounts

## Response Recommendations
- Review sign-in failures by IP address
- Check if IP is known or suspicious
- Validate user activity
- Reset credentials if malicious behavior is confirmed


