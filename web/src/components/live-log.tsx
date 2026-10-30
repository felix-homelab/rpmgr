// SPDX-License-Identifier: Apache-2.0

import { timestampDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { useTransport } from "@connectrpc/connect-query";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { LogService, type LogLine } from "@/gen/rpmgr/v1/log_pb";

// canStreamLogs: Owners and Admins hold agents.logs (docs/04-security.md, "Roles").
export const canStreamLogs = (role?: string) => role === "owner" || role === "admin";

// keptLines is how many lines the panel keeps; older ones scroll away for good.
const keptLines = 2000;

type Shown = { key: number; text: string; level?: string; earlier?: boolean };

// LiveLog streams a connector's or gateway's live log, redacted on the agent (docs/09-web-ui.md,
// "Live logs, webhooks and audit sinks (Phase 2)"): a level and a text filter, Raise to debug, and
// Pause, which stops the panel scrolling while lines keep arriving. A marker shows where the agent
// dropped or cut lines; the lines the agent kept from before the log opened come first, marked as
// earlier ones (D154), and while no new line has arrived the panel says it is connected, with the
// level it follows. When the stream ends at its deadline the panel says so and offers to go on.
export function LiveLog({ agentId }: { agentId: string }) {
  const { t } = useTranslation();
  const transport = useTransport();
  const id = useId();
  const [level, setLevel] = useState("info");
  const [filter, setFilter] = useState("");
  const [debug, setDebug] = useState(false);
  const [running, setRunning] = useState(false);
  const [paused, setPaused] = useState(false);
  const [lines, setLines] = useState<Shown[]>([]);
  const [ended, setEnded] = useState("");
  const [fresh, setFresh] = useState(false); // a new line, not an earlier one, has arrived
  const [followed, setFollowed] = useState("info"); // the level the running log follows
  const abort = useRef<AbortController>(undefined);
  const counter = useRef(0);
  const panel = useRef<HTMLPreElement>(null);

  useEffect(() => () => abort.current?.abort(), []);
  useEffect(() => {
    if (!paused && panel.current) {
      panel.current.scrollTop = panel.current.scrollHeight;
    }
  }, [lines, paused]);

  const shown = (l: LogLine): Shown[] => {
    const out: Shown[] = [];
    if (l.droppedBefore > 0) {
      out.push({ key: counter.current++, text: t(l.backlog ? "liveLog.goneEarlier" : "liveLog.dropped", { count: l.droppedBefore }) });
    }
    const at = l.time ? timestampDate(l.time).toISOString() : "";
    out.push({ key: counter.current++, level: l.level, earlier: l.backlog, text: `${at} ${l.level.toUpperCase().padEnd(5)} ${l.text}${l.truncated ? ` ${t("liveLog.cut")}` : ""}` });
    return out;
  };

  async function start() {
    abort.current?.abort();
    const a = new AbortController();
    abort.current = a;
    setEnded("");
    setFresh(false);
    setFollowed(debug ? "debug" : level);
    setRunning(true);
    try {
      const stream = createClient(LogService, transport).streamLogs({ agentId, level, filter, raiseToDebug: debug }, { signal: a.signal });
      for await (const m of stream) {
        if (m.line) {
          const add = shown(m.line);
          if (!m.line.backlog) {
            setFresh(true);
          }
          setLines((ls) => [...ls, ...add].slice(-keptLines));
        }
      }
      setEnded(t("liveLog.deadline"));
    } catch (err) {
      if (!a.signal.aborted) {
        const e = ConnectError.from(err);
        setEnded(e.code === Code.Unavailable ? t("liveLog.unavailable") : e.code === Code.ResourceExhausted ? t("liveLog.limit")
          : t("link.failed", { message: e.rawMessage }));
      }
    } finally {
      if (abort.current === a) {
        setRunning(false);
      }
    }
  }

  function stop() {
    abort.current?.abort();
    setRunning(false);
  }

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="grid gap-1.5 text-sm">
          {t("liveLog.level")}
          <Select value={level} disabled={running} onChange={(e) => setLevel(e.target.value)}>
            {["debug", "info", "warn", "error"].map((l) => <option key={l} value={l}>{t(`liveLog.levels.${l}`)}</option>)}
          </Select>
        </label>
        <label className="grid gap-1.5 text-sm">
          {t("liveLog.filter")}
          <Input value={filter} disabled={running} maxLength={200} onChange={(e) => setFilter(e.target.value)} />
        </label>
        <label className="flex items-center gap-2 pb-2 text-sm">
          <input type="checkbox" checked={debug} disabled={running} onChange={(e) => setDebug(e.target.checked)} />
          {t("liveLog.debug")}
        </label>
        {running ? (
          <>
            <Button size="sm" variant="outline" onClick={stop}>{t("liveLog.stop")}</Button>
            <Button size="sm" variant="outline" aria-pressed={paused} onClick={() => setPaused((p) => !p)}>
              {paused ? t("liveLog.resume") : t("liveLog.pause")}
            </Button>
          </>
        ) : (
          <Button size="sm" onClick={() => void start()}>{lines.length > 0 ? t("liveLog.continue") : t("liveLog.start")}</Button>
        )}
      </div>
      <p className="text-xs text-muted-foreground">{t("liveLog.hint")}</p>
      {ended && <Alert>{ended}</Alert>}
      <pre ref={panel} id={id} role="log" aria-label={t("liveLog.panel")} tabIndex={0}
        className="h-80 overflow-auto rounded-lg border border-border bg-muted/40 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
        {lines.length === 0 ? <span className="text-muted-foreground">{running ? t("liveLog.connecting") : t("liveLog.empty")}</span>
          : lines.map((l) => <div key={l.key} className={l.level && !l.earlier ? undefined : "text-muted-foreground italic"}
            title={l.earlier ? t("liveLog.earlier") : undefined}>{l.text}</div>)}
      </pre>
      {running && !fresh && <p role="status" className="text-xs text-muted-foreground">{t("liveLog.connected", { level: t(`liveLog.levels.${followed}`) })}</p>}
    </div>
  );
}

// LiveLogButton opens an agent's live log in a dialog, for a row of a table such as a gateway
// group's gateways.
export function LiveLogButton({ agentId, name }: { agentId: string; name: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}>{t("liveLog.open")}</Button>
      {open && <LiveLogDialog agentId={agentId} name={name} onClose={() => setOpen(false)} />}
    </>
  );
}

function LiveLogDialog({ agentId, name, onClose }: { agentId: string; name: string; onClose: () => void }) {
  const { t } = useTranslation();
  const id = useId();
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => dialog.current?.showModal(), []);
  return (
    <dialog ref={dialog} aria-labelledby={id} onCancel={onClose}
      className="m-auto w-[calc(100%-2rem)] max-w-5xl rounded-xl border border-border bg-card p-6 shadow-2xl">
      <div className="grid gap-3">
        <h2 id={id} className="text-lg font-semibold">{t("liveLog.of", { name })}</h2>
        <LiveLog agentId={agentId} />
        <Button size="sm" className="justify-self-start" onClick={onClose}>{t("manifest.close")}</Button>
      </div>
    </dialog>
  );
}
