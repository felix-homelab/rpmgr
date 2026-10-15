# rpmgr user guide

This guide is for the people who install, run and use rpmgr: whoever sets up the servers, enrolls
the connectors and publishes services, and everyone who signs in to the web UI or calls the API.
It shows every task in the web UI and on the command line. How rpmgr works inside, and why, is in
the [design documents](../README.md#design-documents), which this guide links to for exact
timeouts, sizes and limits ([D91](../14-open-decisions.md#project-and-process)).

New to rpmgr? Read [Concepts](concepts.md), then follow the [Quick start](quick-start.md).

## Start

| Page | Read it to |
|---|---|
| [Concepts](concepts.md) | Learn the parts of rpmgr, how traffic flows and who may do what |
| [Quick start](quick-start.md) | Go from a fresh server to a first published service, step by step |

## Install and run

| Page | Read it to |
|---|---|
| [Install script](install/install-script.md) | Install or upgrade rpmgr from a release, verified, with every option |
| [rpmgr setup](install/setup.md) | Set a host up for its role, in forms or with flags |
| [Manual installation](install/manual.md) | Install step by step without `rpmgr setup`, or run the container images |
| [Topologies](install/topologies.md) | Choose between an all-in-one, a separate controller, a private controller and several gateways |
| [Upgrades](install/upgrades.md) | Upgrade every host in the right order |
| [Air-gapped installations](install/air-gapped.md) | Give a controller without internet access its releases |
| [Backup and restore](operations/backup-and-restore.md) | Back up the controller, and restore it |

## Publish services

| Page | Read it to |
|---|---|
| [HTTP routes](routes/http.md) | Publish a website or an API by hostname, with HTTPS |
| [TCP and UDP routes](routes/tcp-and-udp.md) | Publish a port, for TCP, UDP or both |
| [TLS passthrough](routes/tls-passthrough.md) | Pass TLS through to a service that keeps its own certificate |
| [Targets](routes/targets.md) | Point a route at its services: addresses, HTTPS verification, PROXY protocol, weights, priorities and failover |
| [Maintenance and error pages](routes/maintenance-and-pages.md) | Take a service down for maintenance, and see what visitors get when a service is down |
| [Preview and apply](routes/preview-and-apply.md) | Preview a change, follow it to every gateway and connector, and read a route's state |
| [Domains and certificates](domains-and-certificates.md) | Prove your domains, get certificates from ACME or upload your own |
| [Access policies](access-policies.md) | Allow or deny clients by address, and require basic auth |

## Connectors and gateways

| Page | Read it to |
|---|---|
| [Enrolling connectors](connectors/enroll.md) | Add a connector to your network with an enrollment token |
| [The local policy](connectors/local-policy.md) | Decide on the connector's host what the connector may reach |
| [Connector networking](connectors/network.md) | Understand QUIC and TCP, proxies and restricted networks |
| [Status and diagnostics](connectors/status-and-diagnostics.md) | Check an agent on its host, and test its connections |
| [Connector lifecycle](connectors/lifecycle.md) | Switch a connector off, decommission it, and handle ephemeral connectors |
| [Gateways](gateways.md) | Manage gateway groups, gateways, port pools and quotas |

## Accounts and teams

| Page | Read it to |
|---|---|
| [Sign-in and two-factor authentication](accounts/sign-in-and-mfa.md) | Sign in, add an authenticator app, and reset a password |
| [Members and roles](accounts/members-and-roles.md) | Invite people and give them the right role |
| [API tokens and the command line](accounts/api-tokens-and-cli.md) | Make a personal API token and use the command line with it |

## Operate

| Page | Read it to |
|---|---|
| [Monitoring](operations/monitoring.md) | Watch health, metrics, traces and logs |
| [Audit log](operations/audit-log.md) | Read and verify who changed what |
| [PKI](operations/pki.md) | Understand rpmgr's certificate authority, its pin and its rotation |
| [Settings](operations/settings.md) | Configure the instance and your organisation |
| [Troubleshooting](operations/troubleshooting.md) | Find the cause of what you see, and fix it |

## Reference

| Page | Read it to |
|---|---|
| [Web UI](web-ui/README.md) | Find your way through every page of the web UI, with screenshots |
| [Command line](reference/cli.md) | Look up every command and its flags (generated from the binary) |
| [Boot files](reference/boot-files.md) | Look up every key of each role's configuration file |
| [Local policy file](reference/policy-file.md) | Look up the format of `/etc/rpmgr/policy.yaml` |
| [Environment variables](reference/environment.md) | Look up what rpmgr and its scripts read from the environment |
| [API](reference/api.md) | Automate rpmgr with its API: authentication, calls, errors and paging |
