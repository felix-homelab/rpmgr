// SPDX-License-Identifier: Apache-2.0

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Field } from "@/components/field";
import { LinesField } from "@/components/lines-field";
import { PemField } from "@/components/pem-field";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

const none = () => {};

describe("required fields", () => {
  it("end the label of a required field in the asterisk and mark its control required", () => {
    render(
      <form>
        <Field label="Name" required value="" onChange={none} />
        <LinesField label="Tunnel endpoints" required value={[]} onChange={none} />
        <PemField label="Private key (PEM)" required value="" onChange={none} secret />
      </form>,
    );
    expect(marked()).toEqual(["Name", "Tunnel endpoints", "Private key (PEM)"]);
    expect(unmatched()).toEqual([]);
    expect((screen.getByLabelText("Tunnel endpoints") as HTMLTextAreaElement).required).toBe(true);
    // The asterisk is CSS, so neither the label's text nor the field's name changes.
    expect(screen.getByRole("textbox", { name: "Name" })).toBeDefined();
  });

  it("leave an optional field without asterisk and not required", () => {
    render(
      <form>
        <Field label="Region" value="" onChange={none} />
        <LinesField label="Public hostnames" value={[]} onChange={none} />
        <PemField label="Certificate chain" value="" onChange={none} />
      </form>,
    );
    expect(marked()).toEqual([]);
    expect(unmatched()).toEqual([]);
    expect((screen.getByLabelText("Region") as HTMLInputElement).required).toBe(false);
  });

  it("finds a label and its control that disagree", () => {
    render(
      <form>
        <label htmlFor="a" className="required-mark">Marked</label>
        <input id="a" />
        <label htmlFor="b">Plain</label>
        <input id="b" required />
      </form>,
    );
    expect(unmatched()).toEqual(["Marked: asterisk, not required", "Plain: required, no asterisk"]);
  });
});
