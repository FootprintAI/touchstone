import { timestampDate } from "@bufbuild/protobuf/wkt";
import {
  type CheckedLocation,
  CheckedLocation_Result,
  type Component,
  type Evidence,
  EvidenceKind,
  LookupStatus,
  type ScanReport,
  ScanStatus,
  type Vulnerability,
  VexStatus,
} from "../gen/touchstone/v1/scan_pb";
import { groupByTier } from "../lib/group";

const evidenceLabel: Record<EvidenceKind, string> = {
  [EvidenceKind.UNSPECIFIED]: "Unknown evidence",
  [EvidenceKind.SBOM_PUBLISHED]: "Published SBOM",
  [EvidenceKind.SBOM_SUPPLIED]: "Supplied SBOM",
  [EvidenceKind.VEX]: "VEX",
  [EvidenceKind.REPO_LOCKFILE]: "Repo lockfile",
  [EvidenceKind.FINGERPRINT_ASSET]: "Fingerprint: asset",
  [EvidenceKind.FINGERPRINT_HEADER]: "Fingerprint: header",
};

const resultLabel: Record<CheckedLocation_Result, string> = {
  [CheckedLocation_Result.UNSPECIFIED]: "unknown",
  [CheckedLocation_Result.FOUND]: "found",
  [CheckedLocation_Result.NOT_FOUND]: "not found",
  [CheckedLocation_Result.ERROR]: "error",
  [CheckedLocation_Result.REFUSED]: "refused",
};

const vexLabel: Partial<Record<VexStatus, string>> = {
  [VexStatus.AFFECTED]: "VEX: affected",
  [VexStatus.NOT_AFFECTED]: "VEX: not affected",
  [VexStatus.FIXED]: "VEX: fixed",
  [VexStatus.UNDER_INVESTIGATION]: "VEX: under investigation",
};

function time(ts: Parameters<typeof timestampDate>[0] | undefined): string {
  return ts ? timestampDate(ts).toISOString() : "unknown";
}

function EvidenceItem({ e }: { e: Evidence }) {
  return (
    <li className="break-all">
      <span className="font-medium">{evidenceLabel[e.kind]}</span> at <code>{e.location}</code>
      {e.detail ? (
        <>
          {" "}
          matched <code>{e.detail}</code>
        </>
      ) : null}
    </li>
  );
}

function VulnItem({ v }: { v: Vulnerability }) {
  const badge = "rounded px-1.5 py-0.5 text-xs font-medium";
  const vex = vexLabel[v.vexStatus];
  return (
    <li className={v.suppressed ? "opacity-60" : ""}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-semibold">{v.id}</span>
        {v.kev ? <span className={`${badge} bg-red-100 text-red-800`}>Known exploited (KEV)</span> : null}
        {v.cvssBase !== undefined ? (
          <span className={`${badge} bg-slate-200`}>CVSS {v.cvssBase.toFixed(1)}</span>
        ) : null}
        {v.epss !== undefined ? (
          <span className={`${badge} bg-slate-200`}>EPSS {(v.epss * 100).toFixed(2)}%</span>
        ) : null}
        {vex ? <span className={`${badge} bg-blue-100 text-blue-800`}>{vex}</span> : null}
        {v.suppressed ? <span className={`${badge} bg-slate-200`}>Suppressed</span> : null}
      </div>
      {v.summary ? <p className="text-sm">{v.summary}</p> : null}
      {v.aliases.length > 0 ? <p className="text-xs text-slate-600">Also: {v.aliases.join(", ")}</p> : null}
      {v.vexJustification ? <p className="text-xs text-slate-600">{v.vexJustification}</p> : null}
    </li>
  );
}

function ComponentCard({ c, lookupComplete }: { c: Component; lookupComplete: boolean }) {
  return (
    <li className="rounded border border-slate-200 bg-white p-4">
      <h4 className="text-lg font-semibold">
        {c.name} {c.version}
      </h4>
      {c.purl ? <p className="break-all font-mono text-xs text-slate-600">{c.purl}</p> : null}
      {c.caveats.length > 0 ? (
        <p className="mt-1 text-xs text-amber-800">Caveats: {c.caveats.join(", ")}</p>
      ) : null}

      <h5 className="mt-3 text-sm font-semibold">Vulnerabilities (ranked)</h5>
      {c.vulnerabilities.length > 0 ? (
        <ol className="mt-1 list-decimal space-y-2 pl-5">
          {c.vulnerabilities.map((v) => (
            <VulnItem key={v.id} v={v} />
          ))}
        </ol>
      ) : (
        // An empty list is only "none known" when every lookup succeeded.
        <p className="text-sm text-slate-600">
          {lookupComplete ? "No known vulnerabilities." : "Unknown: the vulnerability lookup was incomplete."}
        </p>
      )}

      <details className="mt-3">
        <summary className="cursor-pointer text-sm font-semibold">Evidence ({c.evidence.length})</summary>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">
          {c.evidence.map((e, i) => (
            <EvidenceItem key={`${e.kind}-${e.location}-${i}`} e={e} />
          ))}
        </ul>
      </details>
    </li>
  );
}

function CheckedList({ checked }: { checked: readonly CheckedLocation[] }) {
  return (
    <section aria-labelledby="checked-heading" className="mt-8">
      <h3 id="checked-heading" className="text-xl font-semibold">
        Checked locations ({checked.length})
      </h3>
      <p className="text-sm text-slate-600">Every request Touchstone made, and why.</p>
      <ul className="mt-2 space-y-1 text-sm">
        {checked.map((l, i) => (
          <li key={`${l.url}-${i}`} className="break-all">
            <code>{l.url}</code> — {l.reason.toLowerCase().replaceAll("_", " ")}: {resultLabel[l.result]}
            {l.error ? ` (${l.error})` : ""}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ReportView({ report }: { report: ScanReport }) {
  const unreachable = report.scanStatus !== ScanStatus.OK;
  const lookupComplete = report.lookupStatus === LookupStatus.COMPLETE;
  const tiers = groupByTier(report.components);

  return (
    <article aria-label="Scan report" className="mt-6">
      <h2 className="text-2xl font-bold">Report for {report.targetUrl}</h2>
      <p className="text-sm text-slate-600">
        Scanned {time(report.startedAt)} · tool {report.toolVersion} · {report.requestsUsed} of{" "}
        {report.requestBudget} requests used · vulnerability data as of {time(report.vulnDataAsOf)}
      </p>

      {unreachable ? (
        <div role="alert" className="mt-4 rounded border border-red-300 bg-red-50 p-4 text-red-900">
          <strong>Target unreachable.</strong> Touchstone could not fetch {report.targetUrl}, so nothing was
          scanned. This is not an empty report: no components were checked. See the checked locations below.
        </div>
      ) : (
        <>
          {!lookupComplete ? (
            <div role="alert" className="mt-4 rounded border border-amber-300 bg-amber-50 p-4 text-amber-900">
              <strong>Lookup incomplete.</strong> Some vulnerability lookups failed (
              {report.lookupStatus === LookupStatus.FAILED ? "all of them" : "some of them"}), so a missing
              CVE below does not mean none exist.
            </div>
          ) : null}

          {tiers.length === 0 ? (
            <p className="mt-6">No components were detected from the page's public assets.</p>
          ) : (
            tiers.map((t) => (
              <section key={t.confidence} aria-label={t.label} className="mt-6">
                <h3 className="text-xl font-semibold">
                  {t.label} ({t.components.length})
                </h3>
                <ul className="mt-2 space-y-3">
                  {t.components.map((c) => (
                    <ComponentCard key={`${c.purl || c.name}@${c.version}`} c={c} lookupComplete={lookupComplete} />
                  ))}
                </ul>
              </section>
            ))
          )}
        </>
      )}

      <CheckedList checked={report.checked} />

      {report.sources.some((s) => !s.ok) ? (
        <ul className="mt-4 text-sm text-amber-900">
          {report.sources
            .filter((s) => !s.ok)
            .map((s) => (
              <li key={s.source}>
                Source {s.source} failed: {s.error}
              </li>
            ))}
        </ul>
      ) : null}

      <p className="mt-8 text-xs text-slate-600">{report.disclaimer}</p>
    </article>
  );
}
