// SPDX-License-Identifier: Apache-2.0

import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

export function NotFound() {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="not-found-title">
      <h1 id="not-found-title" className="text-2xl font-semibold">
        {t("notFound.title")}
      </h1>
      <Button asChild className="mt-4">
        <Link to="/">{t("notFound.back")}</Link>
      </Button>
    </section>
  );
}
