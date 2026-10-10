// SPDX-License-Identifier: Apache-2.0

import { useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useState } from "react";

// useLinkToken returns the token of a one-time link, which sits in the URL's fragment so that no
// server or Referer header sees it (docs/10-operations.md, "Install"), and then removes it from the
// address bar and the browser history.
export function useLinkToken(): string {
  const hash = useRouterState({ select: (s) => s.location.hash });
  const [token] = useState(hash);
  const navigate = useNavigate();
  useEffect(() => {
    if (hash) {
      void navigate({ to: ".", hash: "", replace: true });
    }
  }, [hash, navigate]);
  return token;
}

// serverMessage is the text of an API error for the user: the message without its package prefix.
export function serverMessage(raw: string): string {
  const text = raw.replace(/^[a-z]+: /, "");
  return text.charAt(0).toUpperCase() + text.slice(1) + (text.endsWith(".") ? "" : ".");
}
