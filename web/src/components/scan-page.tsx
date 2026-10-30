"use client";

import { useState } from "react";
import { ScanStatus, type ScanReport } from "../gen/touchstone/v1/scan_pb";
import { requestScan, ScanError } from "../lib/api";
import { ReportView } from "./report-view";
import { ScanForm } from "./scan-form";

type View =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "error"; message: string }
  | { kind: "report"; report: ScanReport };

/** The whole page: the URL form, then either the report or an error. */
export function ScanPage() {
  const [view, setView] = useState<View>({ kind: "idle" });

  async function scan(url: string) {
    setView({ kind: "scanning" });
    try {
      const report = await requestScan(url);
      // An unreachable target returns a report with no components, which
      // would look like a clean result. Show it as an error instead.
      if (report.scanStatus !== ScanStatus.OK) {
        setView({ kind: "error", message: scanStatusMessage(report.scanStatus) });
        return;
      }
      setView({ kind: "report", report });
    } catch (err) {
      setView({ kind: "error", message: err instanceof ScanError ? err.message : "The scan failed unexpectedly." });
    }
  }

  return (
    <div className="space-y-8">
      <ScanForm onScan={scan} busy={view.kind === "scanning"} />
      {view.kind === "scanning" && <p role="status" className="text-sm text-slate-600">Scanning…</p>}
      {view.kind === "error" && (
        <div role="alert" className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-900">
          {view.message}
        </div>
      )}
      {view.kind === "report" && <ReportView report={view.report} />}
    </div>
  );
}

function scanStatusMessage(status: ScanStatus): string {
  if (status === ScanStatus.TARGET_UNREACHABLE) {
    return "The target could not be reached, so there is no report. Check the URL and try again.";
  }
  return "The scan did not complete, so there is no report.";
}
