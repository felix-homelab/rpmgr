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

## Rotate the secret

Choose **Rotate secret…** on the endpoint and confirm. The new secret is shown once. Both the old
and the new secret sign for the period in
[03](../../03-connections.md#timeouts-keepalive-and-backoff): configure the receiver with the new
one, and the old one stops signing by itself.

## When an endpoint fails

Open **Deliveries** on the row to see each attempt with its HTTP status or error and the next
retry. An endpoint that keeps failing is switched off after the period in
[03](../../03-connections.md#timeouts-keepalive-and-backoff); its row then says **Disabled:
failing since …**. Fix the receiver, check it with **Send test event**, and choose **Enable
again**.

A receiver on a private network is refused unless the Instance Admin lists its range
([04](../../04-security.md#webhooks-and-the-egress-guard-phase-2)). The refusal appears as the
error of the test event and of the delivery.
