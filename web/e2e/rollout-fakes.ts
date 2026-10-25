// SPDX-License-Identifier: Apache-2.0

import type { Page } from "@playwright/test";

// The API answers of a made-up fleet of Example Lab for Settings → Updates: a release to roll out
// and a rollout in progress. The browser tests and the screenshots run against an instance without
// a signed release, so these answers stand in for ReleaseService and for the agent lists the start
// dialog reads; everything else of the page comes from the instance.

const connector = (id: string, name: string, connected: boolean, builtIn = false) =>
  ({ id, name, enabled: true, builtIn, session: { connected, version: "0.1.0", overTheAir: !builtIn } });
const gateway = (id: string, name: string, connected: boolean, enrolled = true) =>
  ({ id, name, gatewayGroupId: "ggr_eu", enabled: true, status: { enrolled, connected, version: enrolled ? "0.1.0" : "", overTheAir: enrolled } });

const connectors = [
  connector("con_nas", "nas-01", true), connector("con_db", "db-host-1", true), connector("con_office", "office-pc", false),
  connector("con_cam", "cam-01", true), connector("con_backup", "backup-nas", true), connector("con_media", "media-01", true),
  connector("con_printer", "printer-01", false), connector("con_local", "local", true, true),
];
const gateways = [gateway("gw_eu1", "gw-eu-1", true), gateway("gw_eu2", "gw-eu-2", true), gateway("gw_us1", "gw-us-1", false, false)];

const releases = [
  { id: "rel_020", version: "0.2.0", channel: "UPDATE_CHANNEL_STABLE", manifestSeq: "12", source: "RELEASE_SOURCE_CHECK", mirrored: true,
    createTime: "2026-10-23T09:00:00Z", controllerVersion: true },
  { id: "rel_010", version: "0.1.0", channel: "UPDATE_CHANNEL_STABLE", manifestSeq: "9", source: "RELEASE_SOURCE_CHECK", mirrored: true,
    createTime: "2026-10-19T06:27:00Z" },
];

// releaseCheck is the controller's last release check, which "Check now" asks for again.
const releaseCheck = { checkTime: "2026-10-24T08:00:00Z", outcome: "RELEASE_CHECK_OUTCOME_OK" };

const target = (name: string, kind: "CONNECTOR" | "GATEWAY", bucket: number, state: string, canary = false, reason = "") =>
  ({ id: `rlt_${name}`, rolloutId: "rol_1", agentId: name, agentKind: `AGENT_KIND_${kind}`, agentName: name, orgId: "org_lab",
    canary, bucket, state: `ROLLOUT_TARGET_STATE_${state}`, reason, versionBefore: "0.1.0" });

// rolloutTargets are the agents of a rollout at 25 %: the two test agents updated, two agents of the
// stage updating (or one of them rolled back), one skipped and four waiting for later stages.
function rolloutTargets(paused: boolean) {
  return [
    target("db-host-1", "CONNECTOR", 64, "UPDATED", true), target("gw-eu-1", "GATEWAY", 33, "UPDATED", true),
    paused ? target("nas-01", "CONNECTOR", 7, "ROLLED_BACK", false, "the new version did not become ready; the old one runs again")
      : target("nas-01", "CONNECTOR", 7, "STAGED"),
    target("cam-01", "CONNECTOR", 18, "OFFERED"), target("printer-01", "CONNECTOR", 22, "SKIPPED", false, "offline"),
    target("office-pc", "CONNECTOR", 41, "PENDING"), target("backup-nas", "CONNECTOR", 58, "PENDING"),
    target("media-01", "CONNECTOR", 77, "PENDING"), target("gw-eu-2", "GATEWAY", 91, "PENDING"),
  ];
}

// easyTargets are an easy rollout's queue of nine: three updated, one rolled back that the queue
// went past, one skipped, one installing now and three to come; after three failures in a row the
// rollout is paused instead.
function easyTargets(paused: boolean) {
  const at = (name: string, kind: "CONNECTOR" | "GATEWAY", position: number, state: string, reason = "") =>
    ({ ...target(name, kind, 0, state, false, reason), position });
  const failed = "the new version did not become ready; the old one runs again";
  return [
    at("db-host-1", "CONNECTOR", 1, "UPDATED"), at("nas-01", "CONNECTOR", 2, "ROLLED_BACK", failed),
    at("cam-01", "CONNECTOR", 3, "UPDATED"), at("printer-01", "CONNECTOR", 4, "SKIPPED", "offline"),
    paused ? at("backup-nas", "CONNECTOR", 5, "REFUSED", "the host's policy takes stable releases only") : at("backup-nas", "CONNECTOR", 5, "UPDATED"),
    paused ? at("media-01", "CONNECTOR", 6, "STALLED", "the agent reported nothing in time") : at("media-01", "CONNECTOR", 6, "STAGED"),
    at("office-pc", "CONNECTOR", 7, "PENDING"), at("gw-eu-1", "GATEWAY", 8, "PENDING"), at("gw-eu-2", "GATEWAY", 9, "PENDING"),
  ];
}

function easyRollout(paused: boolean) {
  return { id: "rol_2", releaseId: "rel_020", version: "0.2.0", mode: "ROLLOUT_MODE_EASY", stage: "ROLLOUT_STAGE_CANARY",
    state: paused ? "ROLLOUT_STATE_PAUSED" : "ROLLOUT_STATE_RUNNING",
    pauseReason: paused ? "3 agents in a row failed to take the release; the last: media-01 reported nothing for 30m0s" : "",
    counts: paused ? { pending: 3, updated: 2, rolledBack: 1, refused: 1, stalled: 1, skipped: 1 }
      : { pending: 3, staged: 1, updated: 3, rolledBack: 1, skipped: 1 }, etag: "r2" };
}

function rollout(paused: boolean) {
  return { id: "rol_1", releaseId: "rel_020", version: "0.2.0", stage: "ROLLOUT_STAGE_PERCENTAGE", percentage: 25,
    state: paused ? "ROLLOUT_STATE_PAUSED" : "ROLLOUT_STATE_RUNNING",
    pauseReason: paused ? "nas-01 rolled back: the new version did not become ready" : "",
    counts: { pending: 4, offered: 1, staged: paused ? 0 : 1, updated: 2, rolledBack: paused ? 1 : 0, skipped: 1 }, etag: "r1" };
}

// The rollouts fakeUpdates can show: none, a staged one running or paused, an easy one running or
// paused.
export type FakeRollout = "none" | "running" | "paused" | "easy" | "easy-paused";

// fakeUpdates answers the page's release, release check, rollout and agent calls; rolloutState says
// which rollout is there, and is read at every call. With mode, the instance's settings are made
// up too, with that kind of rollout, so that no test has to save them.
export async function fakeUpdates(page: Page, rolloutState: () => FakeRollout, mode?: () => "easy" | "advanced") {
  const answer = (method: string, body: () => object) =>
    page.route(`**/rpmgr.v1.${method}`, (route) => route.fulfill({ json: body() }));
  await answer("ReleaseService/ListReleases", () => ({ releases, controllerVersion: "0.2.0", releaseCheck }));
  await answer("ReleaseService/CheckReleases", () => ({ releaseCheck: { running: true } }));
  const easy = () => rolloutState().startsWith("easy");
  await answer("ReleaseService/ListRollouts", () => ({ rollouts: rolloutState() === "none" ? []
    : [easy() ? easyRollout(rolloutState() === "easy-paused") : rollout(rolloutState() === "paused")] }));
  await answer("ReleaseService/ListRolloutTargets", () => ({ rolloutTargets: easy()
    ? easyTargets(rolloutState() === "easy-paused") : rolloutTargets(rolloutState() === "paused") }));
  await answer("ConnectorService/ListConnectors", () => ({ connectors }));
  await answer("GatewayService/ListGateways", () => ({ gateways }));
  if (mode) {
    await answer("SettingsService/GetInstanceSettings", () => ({ etag: "1", settings: { releaseCheck: true,
      updateChannel: "UPDATE_CHANNEL_STABLE", rolloutMode: mode() === "easy" ? "ROLLOUT_MODE_EASY" : "ROLLOUT_MODE_ADVANCED" } }));
  }
}
