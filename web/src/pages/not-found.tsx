// SPDX-License-Identifier: Apache-2.0

import { Link } from "@tanstack/react-router";
import { MapPinOff } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

export function NotFound() {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="not-found-title" className="grid justify-items-center gap-3 px-4 py-24 text-center">
      <MapPinOff aria-hidden="true" className="size-8 text-muted-foreground" />
      <h1 id="not-found-title" className="text-2xl font-semibold tracking-tight">
        {t("notFound.title")}
      </h1>
      <p className="text-sm text-muted-foreground">{t("notFound.text")}</p>
      <Button asChild className="mt-3">
        <Link to="/">{t("notFound.back")}</Link>
      </Button>
    </section>
  );
}
