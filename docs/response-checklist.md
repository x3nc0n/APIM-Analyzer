# Response checklist: APIM Classic incident

A generic working checklist. The reporting section is **not legal advice**; involve your security lead, data protection officer and legal counsel.

## 1. Check for persistence

Look back as far as your logs allow, with extra attention to the period around the incident (identified 18 Nov 2026, closed 19 Nov 2026). Flag any change that nobody can tie to a ticket.

### Entra ID
- [ ] New secrets or certificates on app registrations and service principals, starting with apps whose client secrets were stored in APIM
- [ ] Newly created app registrations and service principals
- [ ] New federated credentials
- [ ] New app owners, app role assignments or consents
- [ ] New members of administrator roles
- [ ] Conditional Access changes
- [ ] Service principal sign-ins from new IP addresses

If Entra logs go to Log Analytics:

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Add owner to application",
    "Add app role assignment to service principal",
    "Add member to role",
    "Consent to application",
    "Add service principal",
    "Add application")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

Otherwise use Entra admin center → Monitoring → Audit logs with the same filters.

### Azure resources (Activity Log)
- [ ] New or changed role assignments, especially Owner, Contributor and User Access Administrator
- [ ] Key Vault changes: access policies, firewall rules, unexpected secret creation
- [ ] Resources that can give a foothold: Automation accounts and runbooks, Function Apps, Logic Apps, VMs and VM extensions
- [ ] New SAS tokens, regenerated storage keys or new access keys on databases, Service Bus and Event Hubs

### API Management
- [ ] Policies at every level (global, product, API, operation); look for `send-request`, `set-backend-service`, `log-to-eventhub` or anything forwarding traffic or tokens
- [ ] New or changed backends, named values, loggers and certificates
- [ ] New users, subscriptions and identity providers
- [ ] Diff against source control or infrastructure-as-code where available

### After rotation
- [ ] Watch for failed authentication attempts using the **old** secrets; they indicate someone is still trying stolen credentials
- [ ] Repeat the checks above after rotating

## 2. Rotate

Follow [Microsoft's credential rotation guide](https://techcommunity.microsoft.com/blog/integrationsonazureblog/rotating-credentials-in-azure-api-management/4575478), testing first in non-production. The optional `Rotate-ApimCredential.ps1` handles one in-scope subscription or legacy management key, APIM secret named value, or Key Vault named-value refresh at a time; see the README for prerequisites and commands. An accepted asynchronous refresh/update is not proof of completion.

- [ ] Rotate secrets stored in APIM and in Key Vaults reachable by APIM managed identities, production first
- [ ] Rotate at the issuer; updating APIM alone does not invalidate the old credential
- [ ] Regenerate subscription keys and move callers between primary and secondary keys
- [ ] Regenerate the direct management API and Git access keys; disable both if they are not used
- [ ] Replace certificates that were uploaded directly to APIM (their private keys were held by APIM)
- [ ] Enable `AuditEvent` diagnostic logging on every Key Vault and keep retention long
- [ ] Export relevant logs and extend retention before they age out

For credentials not changed by the script:
- [ ] Backends: create the replacement at the backend, update headers, query credentials or certificates without overwriting unrelated settings, and test before revoking the old credential
- [ ] OAuth, OpenID Connect, developer portal identity providers and Credential Manager: create a replacement at the identity provider, update the matching APIM configuration, test and republish the developer portal if needed, then revoke the old credential
- [ ] Event Hubs and other loggers: switch to a replacement connection string or identity, verify new events and other consumers, then renew/revoke the old issuer key
- [ ] Policies: replace literal credentials at their issuer and reference a Key Vault-backed named value; inspect global, product, API and operation policies, then test before revocation
- [ ] Git access and other credentials not supported by this script: rotate using the applicable Microsoft guidance and verify their consumers

## 3. Reporting timeline

The reporting clocks usually start when the organisation becomes aware of the incident. When that was in your case is a legal question, so record it.

### Immediately
- [ ] Escalate to the security lead, IT management and the data protection officer
- [ ] Start an incident log: timestamps, findings, decisions and who made them
- [ ] Open a support case with Microsoft

### Within 24 hours
- [ ] Assess whether personal data may be involved
- [ ] Assess whether NIS2 applies to you (in Sweden, the cybersäkerhetslagen). If so, an early warning is generally due within 24 hours of becoming aware of a significant incident
- [ ] Review customer and partner contracts for incident-notification duties

### Within 72 hours
- [ ] GDPR: where a personal data breach is likely to result in a risk to individuals, notify the supervisory authority within 72 hours of becoming aware; document the decision if you choose not to notify
- [ ] NIS2: incident notification with an initial assessment of severity and impact
- [ ] Inform affected individuals if the risk is high

### Within one month
- [ ] NIS2: final report covering cause, mitigation and impact, if the incident is significant

### Ongoing
- [ ] Keep the incident log current, especially once unexplained activity has been identified or ruled out
