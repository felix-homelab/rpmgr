# Updates

rpmgr updates **connectors and gateways** itself, in a rollout you start. Controllers and
all-in-ones are upgraded by hand ([Upgrades](../install/upgrades.md)). A rollout is **easy**, the
agents you choose one after another, or **staged**, test agents first and then stages you approve.
This page shows how to run both and what they tell you. The rules behind them are in
[04](../../04-security.md#over-the-air-updates),
[10](../../10-operations.md#upgrades-and-version-skew),
[D121](../../14-open-decisions.md#engineering) and [D129](../../14-open-decisions.md#engineering).

## What a rollout does

- **The target is the controller's version**, or an older release you uploaded on purpose. No agent
  runs ahead of its controller.
- **Easy or staged.** **Settings → Updates → Rollouts** says which kind **Roll out…** starts:
  **Easy** unless you change it. **Update** on a connector or gateway always joins or starts an
  easy rollout.
- **An easy rollout** takes the agents you chose one at a time, in your order. An agent that rolls
  back, refuses the release or stalls is marked and skipped, and the next one takes its turn; after
  a few failures in a row the rollout pauses, so that a broken release stops early
  ([04](../../04-security.md#easy-rollouts)).
- **A staged rollout has three stages:** the test agents you choose (the canary agents), then a percentage of the
  others, 25 % unless you choose another, then all agents. You continue every stage yourself; the
  other agents wait until you do. An agent's place in the percentages is fixed by its ID, so a
  later stage includes every agent of an earlier one.
- **Gateways go one at a time per group.** Each drains first, so that its connectors move to the
  other gateways, and is enabled again after the update.
- **In a staged rollout, a rollback or a silent agent pauses the rollout.** You then resume it, or
  cancel it. Agents
  that are offline, or whose policy says `auto_update: notify` or `off`, are listed and skipped;
  they never block a stage.
- Only one rollout runs or is paused at a time.

Hosts need the root updater and a policy that allows updates
([Install](../install/install-script.md)). A host in the container image, or on Windows or macOS,
is not updated over the air.

## Check for a new release now

The controller looks for new releases once a day. To see a release that was just published,
choose **Check now** above the list of releases on **Settings → Updates**, or run:

```sh
rpmgr check release
```

![The releases with Check now and the result of the last check](../images/web/release-check.png)

The page shows when the last check ended and whether it went well; a failed check names its error,
and the controller keeps the releases it had. The release check must be on (**Check for releases
once a day**). A check shortly after the last one, or while the release source limits requests,
is refused with the time to wait ([03](../../03-connections.md#timeouts-keepalive-and-backoff)).

## Run an easy rollout

1. Open **Settings → Updates**, where **Rollouts** says **Easy**, and choose **Roll out…** on a
   release.
2. Tick the agents that get the release; **Select all** ticks every agent the search shows. The
   ones that cannot take it are listed below with the reason: built in, not enrolled, never
   connected, no over-the-air updater on its host, or already on the release.
3. **Order** shows the queue: connectors first, then gateways, each by name. **Move up** and
   **Move down** change it. An agent that is offline when its turn comes is skipped.

   ![The start dialog of an easy rollout, four agents queued](../images/web/rollout-easy-start.png)

4. Choose **Start: update … agents** and confirm your identity.
5. Watch the rollout: **Now** is the agent whose turn it is, with its step; **Next** the queue to
   come; **Updated**, **Failed** and **Skipped** the agents done, each with its reason. A count
   next to the state says how many failed.

   ![An easy rollout, one agent failed and the queue going on](../images/web/rollout-easy.png)

6. After a few failures in a row the rollout is **paused** and says why. Find out what goes wrong
   on those hosts, then **Resume** to go on with the next agent, or **Cancel**. Agents already
   updated keep the release.

   ![An easy rollout paused after failures in a row](../images/web/rollout-easy-paused.png)

## Update one agent

As an Instance Admin, each connector and gateway has **Update to …** with the controller's version,
in the list (for gateways, on their group's page) and on a connector's page. After a step-up it adds
the agent to the end of the easy rollout of that version, or starts one with it alone; the button
then says the agent's place in the queue. Next to a disabled button you see why: up to date, built
in, no over-the-air updater, offline, already in the queue, or another rollout running.

![The connectors list with Update buttons](../images/web/connectors-update.png)

## Run a staged rollout

With **Rollouts** set to **Advanced**:

1. Open **Settings → Updates**. **Releases** lists what the controller verified, with its channel,
   where it came from and whether the mirror holds it. Every release that is no newer than the
   controller has a **Roll out…** button. A rollout of a release the mirror does not hold yet
   starts at once; the controller fetches the release and offers it once the mirror holds it.
2. Choose **Roll out…**. The first step asks for the **test agents**, which update first; the
   connectors and gateways of your org are listed with their version and whether they are online,
   and one online connector and one online gateway are already ticked. Change the choice if you
   like, then choose **Next**. An offline test agent is skipped, so it tests nothing.

   ![The first step: the test agents, one connector and one gateway ticked](../images/web/rollout-start.png)

3. The second step shows the plan: the test agents, then about a quarter of the other agents, then
   the rest. Choose **Start the rollout** and confirm your identity.

   ![The second step: the plan of the rollout](../images/web/rollout-plan.png)

4. Watch the rollout. The stages show which are done, the current one and the ones to come, each
   with its agents; a bar shows how many agents updated. The agents are grouped: **Need attention**
   (rolled back, refused or stalled, with the reason), **Updating now**, **Waiting for a later
   stage**, **Updated** and **Skipped**.

   ![A rollout at 25 %, two agents of the stage still updating](../images/web/rollout.png)

5. Once the agents of the current stage are done, choose **Continue to 25 %**, and later
   **Continue to all agents**, and confirm. The button says how many more agents the next stage
   takes. **Choose another stage** offers other percentages, or all agents at once.
6. At the end the rollout is **completed**. A rollback or a stalled agent shows **paused** with the
   agent and its reason; fix it, then **Resume**, or **Cancel** to end the rollout for good.

   ![A rollout paused because an agent rolled back](../images/web/rollout-paused.png)

**Pause** needs no confirmation; **Resume**, **Continue** and **Cancel** ask for a step-up
([The step-up dialog](../web-ui/README.md#the-step-up-dialog)).

## Upload a release

On an air-gapped installation, or to offer a signed downgrade, choose **Upload release…** and give
the four signed files of a GitHub release: `signing-key.json`, `manifest.json` and their
`.minisig` files. **Choose files…**, or dropping them on the dialog, takes all four at once and
sorts them by name; other files are left out. A file your browser saved under another name, such
as `manifest (1).json`, goes in with the **Choose…** button of its row. **Upload** waits until all
four are there and lists the ones still missing. The controller verifies them as the release check
does. The artifacts then come from the release source, or from `rpmgr release import <dir>` on the
controller host.

![The upload dialog with three of the four files chosen](../images/web/release-upload.png)

## From the command line

```
rpmgr list release
rpmgr create rollout --release 1.5.0 --canary db-host-1
rpmgr get rollout rol_…
rpmgr list rollout-target rol_…
rpmgr advance rollout --percent 25 rol_…
rpmgr advance rollout --all rol_…
rpmgr pause rollout rol_…
rpmgr resume rollout rol_…
rpmgr cancel rollout rol_…
```

Each change but a pause is audited and asks for the step-up
([04](../../04-security.md#over-the-air-updates)).

An **easy rollout** updates the agents you name one after another, in the order you give, with no
stages to approve. An agent that rolls back, refuses the release or stalls is marked and skipped,
and the next one takes its turn; after a few failures in a row the rollout pauses, so that a
broken release stops early. `rpmgr upgrade connector` and `rpmgr upgrade gateway` add agents to the
end of the easy rollout of the controller's version, or start one, and say each agent's place in
the queue. They are refused while a staged rollout, or a rollout of another release, runs
([04](../../04-security.md#easy-rollouts)).

```
rpmgr create rollout --easy --release 1.5.0 --agent db-host-1 --agent nas --agent edge
rpmgr upgrade connector db-host-2
rpmgr upgrade gateway edge-2
rpmgr list rollout-target rol_…
```

## Choose what a host takes

Each connector and gateway host decides for itself, in its local policy, whether it takes updates
and which releases. Change it on the host, as root:

```
sudo rpmgr policy set-update-channel prerelease   # betas and release candidates too
sudo rpmgr policy set-update-channel stable       # stable releases only, the default
sudo rpmgr policy set-auto-update notify          # only report an update as available
sudo rpmgr policy set-auto-update off             # never update this host over the air
sudo rpmgr policy set-auto-update auto            # take updates again, the default
```

Each command prints both settings afterwards:

```text
/etc/rpmgr/policy.yaml: updated; running agents and the updater take it up without a restart
auto_update: auto
update_channel: prerelease
```

Nothing needs restarting: the agent checks its policy again by itself
([03](../../03-connections.md#timeouts-keepalive-and-backoff)), and the updater reads it before
every install. A host only gets a pre-release if the controller lists pre-releases too: set
**Release channel** to **Pre-releases too** in **Settings → Updates**
([Settings](settings.md)). The commands refuse a policy file the updater would not trust, such as
one that other users may write; fix its owner or mode first
([Local policy file](../reference/policy-file.md)).

## When something goes wrong

- **A connector or gateway is skipped.** Its policy says `auto_update: off` or `notify`, it is
  offline, or its channel does not take the release. Update it by hand, or change its policy
  ([Choose what a host takes](#choose-what-a-host-takes)).
- **An agent rolled back.** Its updater installed the release, the role did not become ready, and
  the previous binary is back. The rollout is paused; read the agent's log, then resume or cancel.
- **An agent is stalled.** It reported nothing for long enough that the rollout stopped waiting.
  Check that it is connected and that its updater runs, then resume.
- **An agent has no over-the-air updater.** Its host has no root updater, or the updater's units
  are not enabled, as on a host installed with v0.1.0 and upgraded by replacing the binary. Run
  the install script with `--upgrade --restart` on that host once: it installs and enables the
  updater, and the restarted agent then announces over-the-air updates
  ([Upgrades](../install/upgrades.md)).
- **The rollout's agents stay pending.** The mirror does not hold the release yet: the controller
  could not fetch it from the release source. Import the release on the controller host, or cancel
  the rollout.
