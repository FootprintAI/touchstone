"use client";

import { type FormEvent, useState } from "react";
import type { ScanReport } from "../gen/touchstone/v1/scan_pb";
import { scan, ScanError, validateUrl } from "../lib/scan";
import { ReportView } from "./ReportView";

type State =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "error"; message: string }
  | { kind: "report"; report: ScanReport };

export function ScanPage() {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<State>({ kind: "idle" });

  async function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    const invalid = validateUrl(url);
    if (invalid) {
      setState({ kind: "error", message: invalid });
      return;
    }
    setState({ kind: "scanning" });
    try {
      setState({ kind: "report", report: await scan(url) });
    } catch (err) {
      setState({ kind: "error", message: err instanceof ScanError ? err.message : "The scan failed unexpectedly." });
    }
  }

  return (
    <main className="mx-auto max-w-4xl p-6">
      <h1 className="text-3xl font-bold">Touchstone</h1>
      <p className="text-slate-700">
        Paste a vendor URL for a CVE report graded by evidence quality. Touchstone only makes requests a
        browser loading the page would make.
      </p>
      <form onSubmit={onSubmit} className="mt-4 flex gap-2">
        <label htmlFor="url" className="sr-only">
          Vendor URL
        </label>
        <input
          id="url"
          type="text"
          inputMode="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://vendor.example"
          className="flex-1 rounded border border-slate-300 bg-white px-3 py-2"
        />
        <button
          type="submit"
          disabled={state.kind === "scanning"}
          className="rounded bg-slate-900 px-4 py-2 text-white disabled:opacity-50"
        >
          Scan
        </button>
      </form>

      {state.kind === "scanning" ? (
        <p role="status" className="mt-6">
          Scanning… this can take up to a minute.
        </p>
      ) : null}
      {state.kind === "error" ? (
        <div role="alert" className="mt-6 rounded border border-red-300 bg-red-50 p-4 text-red-900">
          <strong>Scan failed.</strong> {state.message}
        </div>
      ) : null}
      {state.kind === "report" ? <ReportView report={state.report} /> : null}
    </main>
  );
}
