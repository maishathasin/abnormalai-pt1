# External Messaging Safety Rules

The draft must be safe for customer-facing publication.

## Never Include

- Internal hostnames, database names, queue names, or environment identifiers.
- Engineer names, internal email addresses, Slack handles, or PagerDuty assignees.
- PR numbers, commit SHAs, file paths, or deployment diffs.
- Credentials, tokens, IP addresses, or internal URLs.
- Speculative root cause claims presented as confirmed facts.
- Raw monitoring values unless they are translated into customer impact.

## Preferred Transformations

- "database connection pool exhausted" becomes "service performance degradation"
- "p99 latency reached 15 seconds" becomes "significantly slower response times"
- "rollback of PR #12345" becomes "a mitigation was implemented"
- "increased HTTP timeout from 10s to 30s" becomes "a recent configuration change"

## Review Gates

- Every draft must pass leakage checks before publish.
- Every draft must remain grounded in the provided incident brief.
- Every draft must preserve customer trust by prioritizing accuracy over detail.
- If deployment timing helps explain sequence or resolution progress, keep the timing but abstract the technical details.
