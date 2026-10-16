// SPDX-License-Identifier: Apache-2.0

import { Check, Copy } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

// mask hides a token but its kind and its checksum (docs/09-web-ui.md, "Enroll connector dialog").
export function mask(token: string): string {
  const kind = token.indexOf("_", "rpmgr_".length) + 1;
  return `${token.slice(0, kind)}${"•".repeat(12)}${token.slice(token.lastIndexOf("_"))}`;
}

// useCopy copies text to the clipboard and says how it went: "copied" for a moment, or "failed"
// where the browser has no clipboard for the page or refuses it, so that the text is copied by hand.
function useCopy(text: string) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state !== "copied") {
      return;
    }
    const timer = setTimeout(() => setState("idle"), 2000);
    return () => clearTimeout(timer);
  }, [state]);
  async function copy(): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
      return true;
    } catch {
      setState("failed");
      return false;
    }
  }
  return { state, copy };
}

// CopyNote says that the browser did not copy the text.
function CopyNote({ failed }: { failed: boolean }) {
  const { t } = useTranslation();
  return failed && <p role="status" className="text-xs text-muted-foreground">{t("copy.failed")}</p>;
}

// The boxes wrap their text and never widen their container, so a dialog or table that holds them
// never scrolls sideways (docs/09-web-ui.md, "Enroll connector dialog").

// OneTimeToken shows a token the server returns only once: masked until shown, with a copy button.
// If the browser does not copy it, it is shown, to be copied by hand.
export function OneTimeToken({ token, label }: { token: string; label: string }) {
  const { t } = useTranslation();
  const [show, setShow] = useState(false);
  const { state, copy } = useCopy(token);
  return (
    <div className="grid min-w-0 gap-1">
      <div className="flex min-w-0 items-center gap-2">
        <code aria-label={label} className="min-w-0 grow break-all rounded bg-muted p-2 font-mono text-xs">{show ? token : mask(token)}</code>
        <Button size="sm" variant="outline" onClick={() => void copy().then((copied) => copied || setShow(true))}>
          {t(state === "copied" ? "copy.copied" : "mfa.copy")}
        </Button>
        <Button size="sm" variant="outline" aria-pressed={show} onClick={() => setShow(!show)}>{t(show ? "enroll.hide" : "enroll.show")}</Button>
      </div>
      <CopyNote failed={state === "failed"} />
    </div>
  );
}

// Command shows a command to run on a host, with a copy button.
export function Command({ command, label }: { command: string; label: string }) {
  const { t } = useTranslation();
  const { state, copy } = useCopy(command);
  return (
    <div className="grid min-w-0 gap-1">
      <div className="flex min-w-0 items-start gap-2">
        <pre aria-label={label} className="min-w-0 grow rounded bg-muted p-2 font-mono text-xs whitespace-pre-wrap wrap-anywhere">{command}</pre>
        <Button size="sm" variant="outline" onClick={() => void copy()}>{t(state === "copied" ? "copy.copied" : "mfa.copy")}</Button>
      </div>
      <CopyNote failed={state === "failed"} />
    </div>
  );
}

// ResourceID shows a resource's ID, by which the command line and the API name it, with a button
// that copies it; screen readers hear the ID with the button. The ID wraps rather than widen its
// row.
export function ResourceID({ id }: { id: string }) {
  const { t } = useTranslation();
  const { state, copy } = useCopy(id);
  const code = useId();
  return (
    <div className="grid min-w-0 gap-1">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 text-muted-foreground">
        <span>{t("copy.idLabel")}</span>
        <code id={code} className="min-w-0 font-mono text-xs break-all text-foreground">{id}</code>
        <Button size="sm" variant="ghost" className="h-7 px-2" aria-describedby={code} onClick={() => void copy()}>
          {state === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}{t(state === "copied" ? "copy.copied" : "mfa.copy")}
        </Button>
      </div>
      <CopyNote failed={state === "failed"} />
    </div>
  );
}
