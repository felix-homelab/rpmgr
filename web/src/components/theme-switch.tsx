// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { createConnectQueryKey, useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Monitor, Moon, Sun } from "lucide-react";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { applyTheme } from "@/theme";

const choices = [[Theme.SYSTEM, "system", Monitor], [Theme.LIGHT, "light", Sun], [Theme.DARK, "dark", Moon]] as const;

// ThemeSwitch chooses the light, the dark or the system's theme (docs/09-web-ui.md, U10). The
// choice applies at once and is saved to the user's profile, so that it follows them to every
// browser; if it cannot be saved, the stored theme comes back and the switch says why. It is a group
// of radio buttons, so the arrow keys move through the themes.
export function ThemeSwitch() {
  const { t } = useTranslation();
  const user = useQuery(UserService.method.getMe, {}).data?.user;
  const update = useMutation(UserService.method.updateMe);
  const queryClient = useQueryClient();
  const [chosen, setChosen] = useState<Theme>();
  const [error, setError] = useState("");
  const name = useId();
  const latest = useRef(0); // the last choice, whose answer alone counts
  const stored = user?.theme || Theme.SYSTEM;
  const shown = chosen ?? stored;

  async function choose(theme: Theme) {
    if (!user) {
      return;
    }
    const n = ++latest.current;
    setChosen(theme);
    setError("");
    applyTheme(theme);
    try {
      // UpdateMe takes the display name with the theme; the name stays as it is.
      await update.mutateAsync({ displayName: user.displayName, theme });
      await queryClient.invalidateQueries({ queryKey: createConnectQueryKey({ schema: UserService.method.getMe, cardinality: "finite" }) });
    } catch (err) {
      if (n === latest.current) {
        applyTheme(stored);
        setError(t("theme.failed", { message: ConnectError.from(err).rawMessage }));
      }
    } finally {
      if (n === latest.current) {
        setChosen(undefined);
      }
    }
  }

  return (
    <div className="relative">
      <fieldset className="flex items-center gap-0.5 rounded-lg border border-border bg-card p-0.5" disabled={!user}>
        <legend className="sr-only">{t("account.theme")}</legend>
        {choices.map(([value, key, Icon]) => (
          <label key={key} title={t(`account.themes.${key}`)}
            className="grid size-7 cursor-pointer place-items-center rounded-md text-muted-foreground transition-colors hover:text-foreground has-checked:bg-muted has-checked:text-foreground has-focus-visible:outline-2 has-focus-visible:outline-ring">
            <input type="radio" name={name} className="sr-only" checked={shown === value} onChange={() => void choose(value)} />
            <Icon aria-hidden="true" className="size-4" />
            <span className="sr-only">{t(`account.themes.${key}`)}</span>
          </label>
        ))}
      </fieldset>
      {error && (
        <p role="alert" className="absolute top-full right-0 z-40 mt-2 w-64 rounded-lg border border-border bg-card p-3 text-sm text-destructive shadow-lg">
          {error}
        </p>
      )}
    </div>
  );
}
