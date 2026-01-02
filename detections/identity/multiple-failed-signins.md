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
| summarize FailedAttempts = count() by UserPrincipalName
| where FailedAttempts >= 5
```

## MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique: T1110 – Brute Force

## Expected Output
- UserPrincipalName
- FailedAttempts

## Tuning / False Positives
- Users who mistype passwords
- New users unfamiliar with credentials
- Service accounts (should be excluded in production)

## Response Recommendations
- Review sign-in details and source IPs
- Confirm with user if activity is expected
- Reset credentials if suspicious behavior is confirmed

