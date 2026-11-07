# Event reference

This page lists every type of event that a webhook receives and that an audit entry causes. It is
for you when you need the exact name to put in an endpoint's event filter; the task pages
([Webhooks](../operations/webhooks.md), [Audit log](../operations/audit-log.md)) explain what to do
with them, and the envelope of an event is in [07](../../07-api.md#webhooks-phase-2).

<!-- Generated from the API services and the status events of internal/events by TestEventReference. Do not edit by hand. -->

## How to read this page

- Every change that the audit log records as a success is an event. Its type is
  `<resource>.<verb>`, made from the name of the API method: `UpdateRoute` of the route service is
  `route.update`, `CreateRouteTarget` is `route_target.create`, and a method that is a verb alone takes
  the name of its service. The audit log names the same change by the method, and the event's type is
  that name in this form.
- Status events report a state rather than a change you made, such as a route's status or an agent
  going offline. They are marked with a link to where they are described.
- Signing in and out, a step-up, asking for a reset link, the use of a token and the use of a
  system scope are not events. Neither is a read.
- Changes that the controller or the command line make outside the API are events too, under the
  name of their audit action; they are not generated here.
- An endpoint names the types it wants, or a prefix such as `route.*` for every type of one
  resource; naming none means all of them. A name that is not in the table is not
  refused when you save the endpoint, so check it against this page.
- Scope says whose endpoints can receive the event: `org` is the organisation's, `instance`
  the instance endpoints'. A scope of `varies` means that it depends on the request.

## access_policy

| Type | Meaning | Scope | See |
|---|---|---|---|
| `access_policy.create` | Access policy created. | org |  |
| `access_policy.delete` | Access policy deleted. | org |  |
| `access_policy.update` | Access policy updated. | org |  |

## agent

| Type | Meaning | Scope | See |
|---|---|---|---|
| `agent.connect` | An agent connected. | org or instance | [07](../../07-api.md#webhooks-phase-2) |
| `agent.disconnect` | An agent went offline. | org or instance | [07](../../07-api.md#webhooks-phase-2) |

## agents

| Type | Meaning | Scope | See |
|---|---|---|---|
| `agents.upgrade` | Agents upgraded. | instance |  |

## alert

| Type | Meaning | Scope | See |
|---|---|---|---|
| `alert.fire` | An alert fired. | org or instance | [10](../../10-operations.md#suggested-alerts) |
| `alert.resolve` | An alert resolved. | org or instance | [10](../../10-operations.md#suggested-alerts) |

## apply

| Type | Meaning | Scope | See |
|---|---|---|---|
| `apply.reject` | An agent rejected a configuration snapshot. | org or instance | [07](../../07-api.md#webhooks-phase-2) |

## audit

| Type | Meaning | Scope | See |
|---|---|---|---|
| `audit.export` | Audit exported. | varies |  |

## audit_sink

| Type | Meaning | Scope | See |
|---|---|---|---|
| `audit_sink.create` | Audit sink created. | instance |  |
| `audit_sink.delete` | Audit sink deleted. | instance |  |
| `audit_sink.test` | Audit sink tested. | instance |  |
| `audit_sink.update` | Audit sink updated. | instance |  |
| `audit_sink.verify` | Audit sink verified. | instance |  |

## ca_bundle

| Type | Meaning | Scope | See |
|---|---|---|---|
| `ca_bundle.create` | CA bundle created. | org |  |
| `ca_bundle.delete` | CA bundle deleted. | org |  |
| `ca_bundle.update` | CA bundle updated. | org |  |

## certificate

| Type | Meaning | Scope | See |
|---|---|---|---|
| `certificate.delete` | Certificate deleted. | org |  |
| `certificate.renew` | Certificate renewed. | org |  |
| `certificate.upload` | Certificate uploaded. | org |  |

## connector

| Type | Meaning | Scope | See |
|---|---|---|---|
| `connector.decommission` | Connector decommissioned. | org |  |
| `connector.update` | Connector updated. | org |  |

## connector_drain

| Type | Meaning | Scope | See |
|---|---|---|---|
| `connector_drain.end` | Connector drain ended. | org |  |

## controller

| Type | Meaning | Scope | See |
|---|---|---|---|
| `controller.update` | Controller updated. | instance |  |

## dns

| Type | Meaning | Scope | See |
|---|---|---|---|
| `dns.conflict` | A DNS name is in conflict with another record. | org | [07](../../07-api.md#webhooks-phase-2) |
| `dns.drifted` | A DNS record drifted from what rpmgr manages. | org | [07](../../07-api.md#webhooks-phase-2) |
| `dns.sync_failing` | A DNS zone's provider keeps failing. | org | [07](../../07-api.md#webhooks-phase-2) |
| `dns.token_expiring` | A DNS provider token is about to expire or no longer works. | org | [07](../../07-api.md#webhooks-phase-2) |
| `dns.zone_held` | A DNS zone is held. | org | [07](../../07-api.md#webhooks-phase-2) |

## dns_name

| Type | Meaning | Scope | See |
|---|---|---|---|
| `dns_name.create` | DNS name created. | org |  |
| `dns_name.delete` | DNS name deleted. | org |  |
| `dns_name.update` | DNS name updated. | org |  |

## dns_provider

| Type | Meaning | Scope | See |
|---|---|---|---|
| `dns_provider.connect` | DNS provider connected. | org |  |
| `dns_provider.delete` | DNS provider deleted. | org |  |
| `dns_provider.update` | DNS provider updated. | org |  |

## domain

| Type | Meaning | Scope | See |
|---|---|---|---|
| `domain.create` | Domain created. | org |  |
| `domain.delete` | Domain deleted. | org |  |
| `domain.verify` | Domain verified. | org |  |

## domain_claim

| Type | Meaning | Scope | See |
|---|---|---|---|
| `domain_claim.approve` | Domain claim approved. | instance |  |

## domain_trusted

| Type | Meaning | Scope | See |
|---|---|---|---|
| `domain_trusted.mark` | Domain trusted marked. | instance |  |

## enrollment_token

| Type | Meaning | Scope | See |
|---|---|---|---|
| `enrollment_token.create` | Enrollment token created. | org |  |
| `enrollment_token.revoke` | Enrollment token revoked. | org |  |

## gateway

| Type | Meaning | Scope | See |
|---|---|---|---|
| `gateway.create` | Gateway created. | org |  |
| `gateway.decommission` | Gateway decommissioned. | org |  |
| `gateway.update` | Gateway updated. | org |  |

## gateway_drain

| Type | Meaning | Scope | See |
|---|---|---|---|
| `gateway_drain.end` | Gateway drain ended. | org |  |

## gateway_enrollment_token

| Type | Meaning | Scope | See |
|---|---|---|---|
| `gateway_enrollment_token.create` | Gateway enrollment token created. | org |  |

## gateway_group

| Type | Meaning | Scope | See |
|---|---|---|---|
| `gateway_group.create` | Gateway group created. | org |  |
| `gateway_group.delete` | Gateway group deleted. | org |  |
| `gateway_group.update` | Gateway group updated. | org |  |

## gateway_page

| Type | Meaning | Scope | See |
|---|---|---|---|
| `gateway_page.delete` | Gateway page deleted. | org |  |
| `gateway_page.set` | Gateway page set. | org |  |

## instance_admin

| Type | Meaning | Scope | See |
|---|---|---|---|
| `instance_admin.set` | Instance admin set. | instance |  |

## instance_settings

| Type | Meaning | Scope | See |
|---|---|---|---|
| `instance_settings.update` | Instance settings updated. | instance |  |

## instance_webhook

| Type | Meaning | Scope | See |
|---|---|---|---|
| `instance_webhook.create` | Instance webhook created. | instance |  |
| `instance_webhook.delete` | Instance webhook deleted. | instance |  |
| `instance_webhook.update` | Instance webhook updated. | instance |  |

## instance_webhook_secret

| Type | Meaning | Scope | See |
|---|---|---|---|
| `instance_webhook_secret.rotate` | Instance webhook secret rotated. | instance |  |

## intermediate

| Type | Meaning | Scope | See |
|---|---|---|---|
| `intermediate.rotate` | Intermediate rotated. | instance |  |

## invitation

| Type | Meaning | Scope | See |
|---|---|---|---|
| `invitation.accept` | Invitation accepted. | varies |  |
| `invitation.create` | Invitation created. | org |  |

## member

| Type | Meaning | Scope | See |
|---|---|---|---|
| `member.remove` | Member removed. | org |  |
| `member.update` | Member updated. | org |  |

## org

| Type | Meaning | Scope | See |
|---|---|---|---|
| `org.update` | Org updated. | org |  |

## org_settings

| Type | Meaning | Scope | See |
|---|---|---|---|
| `org_settings.update` | Org settings updated. | org |  |

## password

| Type | Meaning | Scope | See |
|---|---|---|---|
| `password.change` | Password changed. | varies |  |

## password_reset_link

| Type | Meaning | Scope | See |
|---|---|---|---|
| `password_reset_link.create` | Password reset link created. | varies |  |

## port_pool

| Type | Meaning | Scope | See |
|---|---|---|---|
| `port_pool.create` | Port pool created. | org |  |
| `port_pool.delete` | Port pool deleted. | org |  |
| `port_pool.update` | Port pool updated. | org |  |

## port_quota

| Type | Meaning | Scope | See |
|---|---|---|---|
| `port_quota.delete` | Port quota deleted. | org |  |
| `port_quota.set` | Port quota set. | org |  |

## record

| Type | Meaning | Scope | See |
|---|---|---|---|
| `record.release` | Record released. | org |  |

## records

| Type | Meaning | Scope | See |
|---|---|---|---|
| `records.adopt` | Records adopted. | org |  |

## recovery_codes

| Type | Meaning | Scope | See |
|---|---|---|---|
| `recovery_codes.regenerate` | Recovery codes regenerated. | varies |  |

## release

| Type | Meaning | Scope | See |
|---|---|---|---|
| `release.upload` | Release uploaded. | instance |  |

## releases

| Type | Meaning | Scope | See |
|---|---|---|---|
| `releases.check` | Releases checked. | instance |  |

## restore_review

| Type | Meaning | Scope | See |
|---|---|---|---|
| `restore_review.confirm` | Restore review confirmed. | org |  |

## rollout

| Type | Meaning | Scope | See |
|---|---|---|---|
| `rollout.advance` | Rollout advanced. | instance |  |
| `rollout.cancel` | Rollout cancelled. | instance |  |
| `rollout.create` | Rollout created. | instance |  |
| `rollout.pause` | Rollout paused. | instance |  |
| `rollout.resume` | Rollout resumed. | instance |  |

## route

| Type | Meaning | Scope | See |
|---|---|---|---|
| `route.create` | Route created. | org |  |
| `route.delete` | Route deleted. | org |  |
| `route.status` | A route's status changed. | org | [07](../../07-api.md#webhooks-phase-2) |
| `route.update` | Route updated. | org |  |

## route_target

| Type | Meaning | Scope | See |
|---|---|---|---|
| `route_target.create` | Route target created. | org |  |
| `route_target.delete` | Route target deleted. | org |  |
| `route_target.update` | Route target updated. | org |  |

## session

| Type | Meaning | Scope | See |
|---|---|---|---|
| `session.revoke` | Session revoked. | varies |  |

## smtp_password

| Type | Meaning | Scope | See |
|---|---|---|---|
| `smtp_password.set` | SMTP password set. | instance |  |

## target_certificate

| Type | Meaning | Scope | See |
|---|---|---|---|
| `target_certificate.probe` | Target certificate probed. | org |  |

## token

| Type | Meaning | Scope | See |
|---|---|---|---|
| `token.create` | Token created. | org |  |
| `token.resume` | Token resumed. | org |  |
| `token.revoke` | Token revoked. | org |  |

## totp

| Type | Meaning | Scope | See |
|---|---|---|---|
| `totp.confirm` | TOTP confirmed. | varies |  |
| `totp.enroll` | TOTP enrolled. | varies |  |
| `totp.remove` | TOTP removed. | varies |  |

## user

| Type | Meaning | Scope | See |
|---|---|---|---|
| `user.password_reset` | User password_reseted. | varies |  |
| `user.update` | User updated. | varies |  |

## user_totp

| Type | Meaning | Scope | See |
|---|---|---|---|
| `user_totp.remove` | User TOTP removed. | varies |  |

## webhook

| Type | Meaning | Scope | See |
|---|---|---|---|
| `webhook.create` | Webhook created. | org |  |
| `webhook.delete` | Webhook deleted. | org |  |
| `webhook.disable` | A failing webhook endpoint was disabled. | org or instance | [07](../../07-api.md#webhooks-phase-2) |
| `webhook.test` | A test event, sent to one endpoint on request and to no other. | org or instance | [07](../../07-api.md#webhooks-phase-2) |
| `webhook.update` | Webhook updated. | org |  |

## webhook_secret

| Type | Meaning | Scope | See |
|---|---|---|---|
| `webhook_secret.rotate` | Webhook secret rotated. | org |  |

## zone

| Type | Meaning | Scope | See |
|---|---|---|---|
| `zone.enable` | Zone enabled. | org |  |
| `zone.import` | Zone imported. | org |  |
| `zone.remove` | Zone removed. | org |  |
| `zone.sync` | Zone synced. | org |  |
| `zone.update` | Zone updated. | org |  |

## zone_plan

| Type | Meaning | Scope | See |
|---|---|---|---|
| `zone_plan.approve` | Zone plan approved. | org |  |
