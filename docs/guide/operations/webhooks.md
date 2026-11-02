# Webhooks

A webhook sends the events of an organisation, such as a route created or a connector going
offline, to an HTTPS endpoint you run, so that other systems can react. rpmgr signs every request
with a secret that only the endpoint and rpmgr know. Managing endpoints needs the permission
`webhooks.write` (Owner and Admin); the page for it is [Webhooks](../web-ui/webhooks.md).

## Set up an endpoint

1. Open **Administration → Webhooks** and choose **New webhook…**.
2. Enter the endpoint's `https://` URL and the event types it wants, such as `route.*`; leave the
   types empty for all events.
3. Choose **Create the webhook**. The signing secret, `rpmgr_whs_…`, appears once. Store it where
   your receiver can read it, then choose **I have stored it**.
4. Choose **Send test event** on the new row. The receiver answers a `webhook.test` event, and the
   page shows its HTTP status, or why it was not delivered.

The format of the events, the headers, how to verify the signature and the age after which a
receiver must reject a request are in [07](../../07-api.md#webhooks-phase-2) and
[04](../../04-security.md#webhooks-and-the-egress-guard-phase-2). A receiver answers with a 2xx
status; anything else, or no answer, is a failure and is retried.

## Chat services

An endpoint can post to Discord, Slack or Microsoft Teams instead, so that people see an event
as a message: the event's summary as the title, and its type, organisation, actor, subject and
time as fields. An alert that fires is red and one that resolves is green. The event filter, the
retries, **Deliveries**, **Send test event** and the switching off of a failing endpoint work as
for any endpoint.

1. In the service, make an incoming webhook for the channel and copy its URL. Discord:
   channel settings, Integrations, Webhooks. Slack: an app with Incoming Webhooks. Teams: a
   workflow with the trigger "When a Teams webhook request is received" that posts the card.
2. Make the endpoint with the format `discord`, `slack` or `teams` and that URL (see below).
3. Send a test event and check the channel.

The URL holds the service's token, so rpmgr treats it as a secret: it is stored encrypted, never
shown again, and appears only as its scheme and host, such as `https://discord.com`, in the API,
the command line, logs and the audit log. To change it, enter it again; to move an endpoint to
another service, change the format and the URL together. A chat endpoint has no signing secret,
as the services check none, and cannot be rotated. An endpoint of a chat format does not become
an rpmgr one: make a new endpoint.

When a service answers that it is rate limiting, rpmgr waits as long as it asks, within the
limits in [03](../../03-connections.md#timeouts-keepalive-and-backoff), and does not count that
as a failure of the endpoint. Messages longer than a service allows are cut with an ellipsis.

## Rotate the secret

Choose **Rotate secret…** on the endpoint and confirm. The new secret is shown once. Both the old
and the new secret sign for the period in
[03](../../03-connections.md#timeouts-keepalive-and-backoff): configure the receiver with the new
one, and the old one stops signing by itself.

## When an endpoint fails

Open **Deliveries** on the row to see each attempt with its HTTP status or error and the next
retry. An endpoint that keeps failing is switched off after the period in
[03](../../03-connections.md#timeouts-keepalive-and-backoff); its row then says **Disabled:
failing since …**, and the web UI's overview announces it to Owners and Admins. Fix the
receiver, check it with **Send test event**, and choose **Enable again**.

## Private receivers

A receiver of an organisation's endpoint on a private network is refused unless the Instance Admin
lists its range in the instance setting `webhook_private_ranges`, on **Settings → Webhooks** or
with `rpmgr update settings --instance --set webhook_private_ranges=10.0.0.0/8`
([Settings](settings.md#webhooks-tab)). The refusal appears as the error of the test event and of
the delivery, and names the range to list. Loopback, link-local and cloud metadata addresses are
never admitted, whatever is listed ([04](../../04-security.md#webhooks-and-the-egress-guard-phase-2)).

## Instance webhooks

The Instance Admin's endpoints receive the instance's events, such as its audit entries, releases
and rollouts. They are managed on **Settings → Webhooks** exactly like an organisation's, and with
`--instance` on the command line. They may name a receiver on loopback or a private network
without a listed range.

## On the command line

The commands take the verb first and work on the organisation of the stored login, or with
`--instance` on the instance's endpoints, which needs the Instance Admin. A webhook has no name:
name it by its ID, `whk_…`, which `list webhook` shows.

```sh
rpmgr create webhook --url https://hooks.example.com/rpmgr --event 'route.*' --event 'connector.*'
rpmgr list webhook
rpmgr update webhook --url https://hooks.example.com/v2 whk_1
rpmgr test webhook whk_1
rpmgr update webhook --rotate-secret whk_1
rpmgr list webhook-delivery whk_1
rpmgr disable webhook whk_1
rpmgr enable webhook whk_1
rpmgr delete webhook whk_1
```

A chat endpoint takes `--format discord`, `slack` or `teams` and its URL from a file, or `-` for
standard input, never from an argument, which the shell history would keep:

```sh
rpmgr create webhook --format slack --url-file slack-url.txt --event 'alert.*'
rpmgr update webhook --url-file new-slack-url.txt whk_1
rpmgr update webhook --format discord --url-file discord-url.txt whk_1
```

`create webhook` and `update webhook --rotate-secret` print the signing secret once, on standard
output; nothing else shows it, and no command takes a secret as an argument. Capture it with a
redirect to a file that only the receiver's user can read. `--event` may be repeated; an empty list
means all events, and `update webhook --all-events` returns to that. `test webhook` exits with 1
and says why when the event was not delivered.
