// SPDX-License-Identifier: Apache-2.0

import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { EditorState } from "@codemirror/state";
import { EditorView, lineNumbers } from "@codemirror/view";
import { tags } from "@lezer/highlight";
import { useEffect, useRef } from "react";
import { cspNonce } from "@/lib/csp";

// The colours of the theme (src/index.css), so the view follows light and dark.
const theme = EditorView.theme({
  "&": { color: "var(--color-foreground)", backgroundColor: "var(--color-muted)", fontSize: "0.8125rem", maxHeight: "60vh" },
  ".cm-scroller": { fontFamily: "ui-monospace, monospace", overflow: "auto" },
  ".cm-gutters": { color: "var(--color-muted-foreground)", backgroundColor: "var(--color-muted)", border: "none" },
  "&.cm-focused": { outline: "2px solid var(--color-ring)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "var(--color-border)" },
});

const highlight = HighlightStyle.define([
  { tag: [tags.propertyName, tags.definition(tags.propertyName)], color: "var(--color-code-key)" },
  { tag: [tags.string, tags.content], color: "var(--color-code-string)" },
  { tag: [tags.number, tags.bool, tags.null, tags.atom], color: "var(--color-code-atom)" },
  { tag: [tags.comment, tags.meta, tags.punctuation, tags.separator], color: "var(--color-muted-foreground)" },
]);

// YamlView shows YAML read-only with CodeMirror. Its styles go into style elements that carry the
// page's nonce (VB-07). The text can be selected and copied with the keyboard.
export default function YamlView({ text, label }: { text: string; label: string }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const nonce = cspNonce();
    const view = new EditorView({
      parent: host.current!,
      state: EditorState.create({
        doc: text,
        extensions: [
          ...(nonce ? [EditorView.cspNonce.of(nonce)] : []),
          EditorState.readOnly.of(true),
          EditorView.contentAttributes.of({ "aria-label": label, "aria-readonly": "true" }),
          lineNumbers(),
          yaml(),
          syntaxHighlighting(highlight),
          theme,
        ],
      }),
    });
    return () => view.destroy();
  }, [text, label]);
  return <div ref={host} className="overflow-hidden rounded-md border border-border" />;
}
