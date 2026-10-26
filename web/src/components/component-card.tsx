import {
  EvidenceKind,
  VexStatus,
  type Component,
  type Vulnerability,
} from "../gen/touchstone/v1/scan_pb";

/** Lowercase words for an enum name, e.g. FINGERPRINT_ASSET → "fingerprint asset". */
function words(enumName: string): string {
  return enumName.toLowerCase().replaceAll("_", " ");
}

/**
 * One component: its name and version, the evidence behind it, and its
 * vulnerabilities in the order the server ranked them. The count is withheld
 * when the lookup is incomplete, to match the banner.
 */
export function ComponentCard({ component, showCount }: { component: Component; showCount: boolean }) {
  const count = component.vulnerabilities.length;
  return (
    <article className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <h3 className="text-lg font-semibold">
        {component.name} <span className="font-mono text-base font-normal">{component.version}</span>
      </h3>
      {component.purl && <p className="font-mono text-xs text-slate-500">{component.purl}</p>}
      {component.caveats.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-2 text-xs">
          {component.caveats.map((caveat) => (
            <li key={caveat} className="rounded bg-amber-100 px-2 py-0.5 text-amber-900">
              {caveat}
            </li>
          ))}
        </ul>
      )}

      <details className="mt-3 text-sm">
        <summary className="cursor-pointer text-slate-700">Evidence ({component.evidence.length})</summary>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          {component.evidence.map((ev, i) => (
            <li key={i}>
              <span className="font-medium">{words(EvidenceKind[ev.kind] ?? "UNSPECIFIED")}</span>
              {": "}
              <span className="break-all font-mono text-xs">{ev.location}</span>
              {ev.detail && <span className="text-slate-600"> ({ev.detail})</span>}
            </li>
          ))}
        </ul>
      </details>

      <h4 className="mt-4 text-sm font-semibold">
        Vulnerabilities{showCount ? ` (${count})` : ""}
      </h4>
      {count === 0 ? (
        <p className="text-sm text-slate-600">None listed for this component.</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {component.vulnerabilities.map((vuln) => (
            <VulnerabilityItem key={vuln.id} vuln={vuln} />
          ))}
        </ul>
      )}
    </article>
  );
}

function VulnerabilityItem({ vuln }: { vuln: Vulnerability }) {
  return (
    <li className="rounded border border-slate-100 p-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-semibold">{vuln.id}</span>
        {vuln.kev && <span className="rounded bg-red-100 px-1.5 text-xs text-red-800">Known exploited (KEV)</span>}
        {vuln.cvssBase !== undefined && <span className="text-xs text-slate-600">CVSS {vuln.cvssBase}</span>}
        {vuln.epss !== undefined && <span className="text-xs text-slate-600">EPSS {(vuln.epss * 100).toFixed(1)}%</span>}
        {vuln.suppressed && (
          <span className="rounded bg-slate-200 px-1.5 text-xs text-slate-700">
            Suppressed by VEX: {words(VexStatus[vuln.vexStatus] ?? "UNSPECIFIED")}
            {vuln.vexJustification && ` (${vuln.vexJustification})`}
          </span>
        )}
      </div>
      {vuln.summary && <p className="mt-1 text-slate-700">{vuln.summary}</p>}
      {vuln.aliases.length > 0 && (
        <p className="mt-1 text-xs text-slate-500">Also known as {vuln.aliases.join(", ")}</p>
      )}
    </li>
  );
}
