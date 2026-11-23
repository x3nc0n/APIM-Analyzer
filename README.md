# apim-incident-tools

PowerShell scripts for checking whether an Azure tenant may be affected by the **Azure API Management (APIM) Classic-tier security issue** that Microsoft notified customers about in November 2026, reviewing Key Vault audit logs for signs of misuse, and performing selected, individually confirmed credential operations.

> **Status: untested, community-style tooling.** The scripts were written quickly during an incident and have been run in only one environment. Review them before running, and verify results independently. They do not replace Microsoft's guidance or your own security team's judgement.

## Background

Microsoft's notice states that a security issue affected APIM **Classic** tiers (Consumption, Developer, Basic, Standard, Premium) but not the **v2** tiers. It was identified on 18 November 2026 and the access path was closed on 19 November 2026. Instances may have been accessed if they:

- lacked the network integration described in Microsoft's "Network security" guidance for secret management, or
- stored secrets in APIM instead of referencing them from Azure Key Vault.

Potentially exposed items include named-value secrets, identity provider and OpenID Connect client secrets, subscription keys and management tokens.

Because the exact reach of the issue is not fully documented, these tools also look at Key Vaults that APIM managed identities can reach. That is a precaution, not a confirmed attack path.

### Which instances are in scope

**Microsoft's own list is authoritative.** In the Azure portal, open Service Health > Security advisories, select the advisory, and go to **Impacted Resources**. Use **Export to CSV** and pass the file to the exposure script:

```powershell
pwsh ./Check-ApimExposure.ps1 -ImpactedResourcesCsv ./impacted-resources.csv
```

If your account may read the advisory's impacted resources through the API (Owner/Contributor, or a role with `Microsoft.ResourceHealth/events/fetchEventDetails/action`), the script fetches the list itself.

Without that list, the script falls back to a rule: **Classic dedicated tiers** (Developer, Basic, Standard, Premium, Isolated).
- **v2 tiers** (`BasicV2`, `StandardV2`, `PremiumV2`) are out of scope under the fallback rule.
- **Consumption** (multi-tenant platform `mtv1`) is out of scope by default. Microsoft's notice names it among the Classic tiers, but in the tenants checked so far Microsoft's impacted-resources list included only dedicated-tier instances. Add `-IncludeConsumption` to include it anyway.
- **Platform version** is shown but not used. Instances on `stv2.1` were listed as impacted.

All three scripts share these explicit SKU rules in `Apim-Helpers.ps1`:

| SKU | Family | Fallback scope |
|---|---|---|
| `Developer`, `Basic`, `Standard`, `Premium`, `Isolated` | Classic | Included for review; inclusion is not proof of impact |
| `Consumption` | Classic (Consumption) | Included only with `-IncludeConsumption` |
| `BasicV2`, `StandardV2`, `PremiumV2` | v2 | Excluded, unless the scope file explicitly includes them |
| Missing or unrecognized SKU, including a future name ending in `V2` | Unknown | Warn and retain for manual review; exposure status is `UNCHECKED`, even if an old scope file excludes it |

SKU matching ignores case and surrounding whitespace. The supported names follow the [service SKU reference](https://learn.microsoft.com/en-us/rest/api/apimanagement/api-management-service/get?view=rest-apimanagement-2024-05-01#skutype) and the [tier comparison](https://learn.microsoft.com/en-us/azure/api-management/api-management-features), which also documents Premium v2.

> **stv2 is not v2.** `stv1`, `stv2` and `stv2.1` in `platformVersion` are the compute platforms of the **Classic** tiers. Nearly every Classic instance runs on stv2.x today. The **v2 tiers** are a separate product line, identified by the SKU. The `tierFamily` column (`Classic`, `Classic (Consumption)`, `v2` or `Unknown`) in `scope.csv` and `summary.csv` shows which one an instance is. The console shows it next to each status, for example `LIKELY EXPOSED [Classic, stv2.1]`.

**Matching Microsoft's list.** Instances are matched on resource ID when the list has one (case-insensitive), and on name otherwise.

**A v2 instance on Microsoft's list.** If Microsoft lists an instance that is now a v2 tier, it was probably migrated from Classic after the incident. It stays in scope, because its secrets may have been exposed while it was Classic, but it is rated `REVIEW (v2 tier)` and never `LIKELY EXPOSED`. The script prints a warning for it.

The decision per instance is written to `apim-exposure/scope.csv`. The audit and analysis scripts use that file when it exists, so all three scripts work on the same set.

Malformed, duplicate or unrecognized `inScope` values stop the run rather than silently excluding resources. If a current instance is missing from an older scope file, the scripts warn and apply the tier fallback to that instance. Regenerate the scope file to reconcile new or removed resources. `-IncludeConsumption` is available on all three scripts and only affects the fallback, not an explicit scope-file decision.

## What is in this repo

| File | Purpose |
|---|---|
| `Check-ApimExposure.ps1` | Finds APIM instances across all subscriptions you can read, flags Classic tiers, and checks network settings. Lists named values, certificates, identity providers and other secret-bearing objects, APIM subscriptions, and whether the direct management API and Git access are enabled. Also maps what each instance's managed identity can reach. |
| `Check-KeyVaultAudit.ps1` | Can run without the exposure scan. Finds the vaults that APIM managed identities can read from, or can grant themselves access to. Checks whether audit logging is enabled, and queries Log Analytics for identity activity and new callers in a time window. |
| `Analyze-Findings.ps1` | Follow-up analysis of the two scripts' output. Classifies the secrets held by APIM and flags environment mixing, reused secret names, all-access subscriptions, leftover logger credentials and literal backend credentials. Resolves flagged Key Vault callers in Entra ID, drills into their log history and gives each a heuristic verdict. Writes a Markdown report and can compare with a previous run. |
| `Rotate-ApimCredential.ps1` | Opt-in, one-at-a-time subscription and legacy management key regeneration, APIM secret named-value updates, and Key Vault named-value refreshes. Requires a matching in-scope exposure scan and confirmation. |
| `Apim-Helpers.ps1` | Shared SKU, scope, identity, CLI, timestamp and response validation. Must remain alongside the entry scripts. |
| `docs/response-checklist.md` | Generic checklist for persistence checks, rotation and reporting steps. Not legal advice. |
| `docs/DEVLOG.md` | What changed in the scripts and why, plus open ideas. |
| `tests/` | Offline Pester 5 tests for scope, status decisions, audit-window queries and API failure handling (`Invoke-Pester ./tests`). GitHub Actions runs them on every pull request. |

## Requirements

- PowerShell 7+
- Keep `Apim-Helpers.ps1` alongside the entry scripts; clone/download the repository rather than copying one script alone
- Azure CLI (`az`), signed in with `az login`
- **Reader** on the subscriptions you want to cover
- For the audit script: **Log Analytics Reader** on the workspaces that hold Key Vault logs
- For the follow-up analysis: also directory read access in Entra ID, to resolve object IDs

The three analysis scripts are read-only. **The separate rotation script changes Azure resources** and requires suitable write/action permissions in addition to Reader.

## Usage

```powershell
az login

# 1. Find Classic instances, network settings and secrets stored in APIM
pwsh ./Check-ApimExposure.ps1

# 2. Review Key Vault audit logs for the incident window
pwsh ./Check-KeyVaultAudit.ps1
# optional: -WindowStart 2026-11-16 -WindowEnd 2026-11-21 -LookbackDays 90

# 3. Follow-up analysis of both outputs (same window as step 2)
pwsh ./Analyze-Findings.ps1
# later runs: compare with the previous result
pwsh ./Analyze-Findings.ps1 -OutDir ./incident-analysis-2 -CompareTo ./incident-analysis
```

Output goes to `./apim-exposure/`, `./kv-audit/` and `./incident-analysis/`. It contains real resource names, IDs, identities and IP addresses. **Do not commit it.** The folders, and report formats such as `.docx` and `.pdf`, are listed in `.gitignore`.

Windows are UTC, with an inclusive start and exclusive end. Timestamps without a timezone are treated as UTC; local timestamps are converted to UTC. Sub-day boundaries are preserved in queries and analysis snapshots. `WindowStart` must precede `WindowEnd`, and `LookbackDays` must be positive. If the window predates the requested lookback, the scripts warn that the logs may not cover it.

Warnings use PowerShell's warning stream. To preserve them locally, invoke the script directly from PowerShell, for example `.\Check-ApimExposure.ps1 3> .\scan-warnings.log`. Failed CLI commands, malformed responses, repeated continuation links and invalid required metadata never become successful empty scans. Log Analytics partial-error responses are treated as failed queries.

### Rotating credentials

Review [Microsoft's rotation guide](https://techcommunity.microsoft.com/blog/integrationsonazureblog/rotating-credentials-in-azure-api-management/4575478) and test in a non-production instance first. Run the exposure scan, review `scope.csv` and its preflight and failures, then select an explicit in-scope resource ID and credential. An in-scope finding is a precaution, not proof of compromise; an old scan may no longer reflect your environment. The script refuses targets absent from or excluded by `scope.csv`; it does not apply the SKU fallback.

Each invocation performs **one** operation and prompts for confirmation by default. `-WhatIf` previews without contacting Azure. Regenerating a key immediately invalidates that key: first move and test every caller on the other key; regenerate and test the replacement; move callers to it before separately regenerating the other key. Do not rotate both keys together. Management actions target the legacy Direct Management API, not Git keys.

```powershell
$id = '/subscriptions/<azure-subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.ApiManagement/service/<apim-name>'
# APIM subscription entity ID from apim-subscriptions.csv, not the Azure subscription ID
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action SubscriptionPrimary -ItemId '<apim-subscription-id>' -WhatIf
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action SubscriptionPrimary -ItemId '<apim-subscription-id>'
# Only after callers have switched and been tested:
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action SubscriptionSecondary -ItemId '<apim-subscription-id>'
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action ManagementPrimary
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action ManagementSecondary

# Named value ID from named-values.csv; the replacement is prompted for with hidden input
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action NamedValue -ItemId '<named-value-id>'
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action RefreshKeyVault -ItemId '<named-value-id>'
```

For named values, first create the replacement at its issuer. For Key Vault references, store the replacement in Key Vault and update any version-pinned reference before refresh. A `202 Accepted` response is **not completion**: check provisioning and test before revoking the old credential. The script does not read or print existing secrets, but avoid terminal recording and transcripts when entering replacements. Updating APIM does not revoke the old issuer credential. See [the response checklist](docs/response-checklist.md#2-rotate) for backend, OAuth, identity provider, logger, certificate, policy, Git and other externally managed credentials, which are not automatically changed.

### Reading the follow-up analysis

`analysis-report.md` summarises everything. The CSVs next to it hold the details:
- `flags.csv`
- `named-value-categories.csv`
- `subscription-scopes.csv`
- `backend-credentials.csv`
- `logger-credentials.csv`
- `caller-drilldown.csv`
- `caller-ip-history.csv`
- `caller-clients.csv`
- `flagged-ip-other-callers.csv`

**Caller verdicts.** Each caller the audit script flagged is checked against its own history in the logs:

| Verdict | When |
|---|---|
| `SUSPICIOUS` | An APIM managed identity was used from an unexpected IP, or the identity can't be found in the directory. |
| `INVESTIGATE` | The identity was never seen before the window, its in-window requests failed, it used a client not seen before, or its volume was more than three times its own baseline. |
| `NOT ANALYSED` | Directory lookup or log queries failed, required log data is unavailable, or live checks were skipped. A failed directory lookup is not evidence that an identity was deleted. |
| `LIKELY CI/CD` | A known service principal or managed identity with a known client, calling from an Azure address or with an automation client such as Terraform. |
| `LIKELY BENIGN` | A known identity and client calling from a new IP. |

These are indicators, not proof. A stolen credential used with the same tool would look the same, so confirm every case with the owner, the sign-in logs or the pipeline history.

**Other heuristics.**
- **Environment** is inferred from names. Names without a `test`/`dev`/`prod` style marker are assumed to be production.
- **Secret types** are inferred from display names.
- **Backends** are checked for credential structure only. Credential values returned by the management API are inspected in memory to count literals and references; they are never printed or written out.

**Comparing runs.** `-CompareTo` lists what changed since the earlier run's `snapshot.json`: instance status, vault verdicts, caller verdicts, flags and totals. Compare runs made in the same mode. A `-SkipLive` run has no backend, logger or caller data, so those show up as changes.

**Failed live checks.** If backend or logger enumeration fails, analysis stops with the failed URL and API error instead of treating inaccessible objects as an empty list. Resolve the error and rerun before relying on the output; files from an earlier or interrupted run may still be present.

### Reading the first script's output

1. Check the preflight line first. `Preflight clean` means every subscription was readable and the direct and Resource Graph counts agree. Any warning means those subscriptions were not properly checked.
2. The per-instance summary uses these statuses: `LIKELY EXPOSED`, `REVIEW` and `UNCHECKED`. There is deliberately no "safe" status, because the script cannot prove that nothing was accessed.
   - `LIKELY EXPOSED` means there is no VNet or private endpoint, or APIM holds secrets itself. That covers secret named values not in Key Vault, certificates uploaded directly, and identity provider, OpenID Connect or authorization server configurations, which may carry client secrets.
   - `UNCHECKED` means the SKU or network metadata is unknown, or named values, certificates or those client-secret objects could not be listed. Object kinds that the pricing tier explicitly reports as unsupported, such as identity providers on Consumption, are not counted as failures. Direct management API and Git checks are `n/a` on Consumption and v2.
   - Only `Approved` private endpoints count as protection. Pending and rejected connections do not. `approvedPrivateEndpoints` in `summary.csv` records the approved count; unknown connection states produce a warning and `UNCHECKED`.
   - `loggerCredentials` counts the `Logger-Credentials-…` named values that APIM creates for Application Insights loggers. They are shown separately from `secretsInApim` and don't affect the status. Repeated deployments can leave many of them behind.
3. `activeSubscriptions`, `directMgmtApi` and `gitAccess` are there for rotation planning and do not change the status. Every active APIM subscription has keys held in APIM. If `directMgmtApi` is `True`, management tokens could have been issued. `gitAccess` is often `True` without anyone having turned it on, and its keys exist either way. Subscription metadata goes to `apim-subscriptions.csv`. The keys themselves are never read.
4. Backends are listed in `other-secret-objects.csv` but their credentials (basic-auth headers, client certificates) are not inspected. Review them by hand.

### Reading the second script's output

- A vault counts as reachable when an APIM identity has an access policy on it, or a role that gives one of these:
  - data access on an RBAC-mode vault, such as Key Vault Secrets User;
  - the right to create role assignments, such as Owner or User Access Administrator;
  - the right to write vault settings or access policies on an access-policy vault, such as Contributor.
  Assignments that give none of these, such as Reader, go to `excluded-role-assignments.csv`. Roles that cannot be resolved are counted as reachable.
- An unknown vault authorization mode produces a warning and includes both possible authorization paths rather than silently excluding an RBAC-only grant.
- Role assignments inherited from management groups and the tenant root are included.
- Expected source IPs include the instance's primary and additional-region public/private addresses, including multi-region Premium deployments.
- `SUSPICIOUS - review` means an APIM identity was used **inside the selected window** from an address that is not one of the instance's own, or a caller and IP pair that was not seen before the window read secrets, keys or certificates inside it. New pairs can be benign. Investigate before concluding anything.
- `REVIEW` means there was APIM identity activity whose source IP cannot be checked. Either the instance has no static IP, or the log row has no caller IP.
- The script warns when authenticated data-plane rows lack a caller IP or object ID, which usually means the column mapping doesn't match that workspace. Such gaps prevent a `no anomaly found` verdict and produce `PARTIAL COVERAGE` unless another finding already requires investigation. 401 authentication challenges and control-plane operations such as `VaultGet` are left out, because they never carry an object ID.
- The script warns when the logs start later than `-LookbackDays`, which usually means the workspace's retention is shorter. The warning also says roughly when the window's first day will age out. `baselineDays` in `vault-verdicts.csv` shows how much history came before the window. With a short baseline, ordinary callers often show up as new, such as CI agents on changing IPs or admins on another network. Check the client and the caller's history before treating one as suspicious.
- `NO AUDIT LOGGING`, `NO LOG DATA` and `PARTIAL COVERAGE` mean there is no evidence either way. Treat those vaults as potentially accessed.
- `DIAGNOSTIC SETTINGS FAILED` means the script could not read or interpret the logging settings; it does not mean logging was disabled. The API/schema error is retained in `vault-logging.csv` and the verdict's `note`.
- `no anomaly found in available logs` requires the earliest and latest log timestamps to bracket the selected window, with complete caller fields. `logsFrom` and `logsTo` in `vault-verdicts.csv` expose those bounds. This is conservative: a quiet vault may receive `PARTIAL COVERAGE` even if logging was enabled. Bracketing timestamps still do not prove continuous logging or the absence of misuse.

## Known limitations

- Resource Graph hides resources you cannot read without reporting an error. The first script's preflight is meant to catch this, but it cannot see everything, for example deny assignments.
- Role assignments are only visible if your account can read them. A tenant administrator should confirm managed identity permissions for important instances.
- Group membership is not expanded. A role given to a group that contains an APIM identity is not detected.
- The vault-access check tests a small set of representative Key Vault operations against each role definition. Unusual custom roles may be classified incorrectly.
- Consumption-tier instances have no static IP, so the source-IP check cannot be applied to them. They also have no direct management API or Git access to check.
- Azure service-tag classification in the analysis is IPv4-only. IPv6 callers have an unknown Azure-IP classification, not a confirmed non-Azure classification.
- Log queries read both the `AzureDiagnostics` and the resource-specific `AZKVAuditLogs` schema. The `AZKVAuditLogs` column names were checked against Microsoft's table reference. The object-ID claim layout was not verified in every workspace.
- Access through any unlogged path will not appear in Key Vault's logs.
- Written and tested on Windows with PowerShell 7. Behaviour elsewhere is unknown.
- Azure Resource Manager is called directly with a token from `az account get-access-token`, not through `az rest`. On Windows, `az` is a batch file that cuts URLs at `&`, which broke paging in earlier versions.

## Offline validation

The regression suite covers all nine supported SKU names, unknown values, scope-file decisions, booleans, managed identities, API failures, paging, audit windows and log-response schemas. Workflow tests execute all three scripts with synthetic data and mocked CLI/HTTP calls; they do not contact Azure.

```powershell
Import-Module Pester -RequiredVersion 5.7.1
Invoke-Pester .\tests
```

GitHub Actions uses the same pinned Pester version and parses every PowerShell file.

## Contributing

Issues and pull requests are welcome, especially fixes for schema differences and other platforms. Please do not include real tenant data in issues or pull requests.

## Author

Mathias Haas, Fidelity Consulting AB

Contact (base64-encoded): `bWF0aGlhcy5oYWFzQGZpZGVsaXR5Y29uc3VsdGluZy5zZQ==`

## License

[MIT](LICENSE). The scripts are provided as is, without warranty of any kind. You are responsible for reviewing them and verifying their results before acting on them.
