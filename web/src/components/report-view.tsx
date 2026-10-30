import { timestampDate } from "@bufbuild/protobuf/wkt";
import {
  CheckedLocation_Result,
  type CheckedLocation,
  type Component,
  type ScanReport,
} from "../gen/touchstone/v1/scan_pb";
import { groupByTier, lookupIncomplete } from "../lib/report";
import { ComponentCard } from "./component-card";

/**
 * The report for one scan: a banner when the lookup is incomplete, the
 * components grouped by confidence tier, the checked locations, and the
 * disclaimer.
 */
export function ReportView({ report }: { report: ScanReport }) {
  const incomplete = lookupIncomplete(report);
  const { tiers, unclassified } = groupByTier(report);
  return (
    <section aria-label="Scan report" className="space-y-8">
      <div className="text-sm text-slate-600">
        <p>
          Target <span className="font-mono text-slate-900">{report.targetUrl}</span>
        </p>
        {report.vulnDataAsOf && <p>Vulnerability data as of {timestampDate(report.vulnDataAsOf).toISOString()}</p>}
      </div>

      {incomplete && (
        <div role="alert" className="rounded-lg border border-amber-300 bg-amber-50 p-4 text-amber-900">
          <p className="font-semibold">Lookup incomplete</p>
          <p className="text-sm">
            Not every vulnerability source answered, so the results below may be missing CVEs. No vulnerability count
            is shown.
          </p>
        </div>
      )}

      {tiers.map(({ tier, components }) => (
        <TierSection
          key={tier.label}
          label={tier.label}
          description={tier.description}
          components={components}
          showCount={!incomplete}
        />
      ))}
      {unclassified.length > 0 && (
        <TierSection
          label="Unclassified"
          description="Components with no confidence tier."
          components={unclassified}
          showCount={!incomplete}
        />
      )}

      <CheckedLocations locations={report.checked} requestsUsed={report.requestsUsed} budget={report.requestBudget} />

      <p className="border-t border-slate-200 pt-4 text-xs text-slate-500">{report.disclaimer}</p>
    </section>
  );
}

function TierSection({
  label,
  description,
  components,
  showCount,
}: {
  label: string;
  description: string;
  components: Component[];
  showCount: boolean;
}) {
  const headingId = `tier-${label.toLowerCase().replaceAll(" ", "-")}`;
  return (
    <section aria-labelledby={headingId} className="space-y-3">
      <div>
        <h2 id={headingId} className="text-xl font-semibold">
          {label}
        </h2>
        <p className="text-sm text-slate-600">{description}</p>
      </div>
      {components.length === 0 ? (
        <p className="text-sm text-slate-500">No components at this tier.</p>
      ) : (
        components.map((component, i) => (
          <ComponentCard
            key={`${component.name}@${component.version}#${i}`}
            component={component}
            showCount={showCount}
          />
        ))
      )}
    </section>
  );
}

function CheckedLocations({
  locations,
  requestsUsed,
  budget,
}: {
  locations: CheckedLocation[];
  requestsUsed: number;
  budget: number;
}) {
  return (
    <section aria-labelledby="checked-locations" className="space-y-2">
      <h2 id="checked-locations" className="text-xl font-semibold">
        Checked locations
      </h2>
      <p className="text-sm text-slate-600">
        {requestsUsed} of {budget} requests used.
      </p>
      {locations.length === 0 ? (
        <p className="text-sm text-slate-500">No locations were requested.</p>
      ) : (
        <ul className="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white text-sm">
          {locations.map((loc, i) => (
            <li key={`${loc.url}#${i}`} className="flex flex-wrap gap-x-4 gap-y-1 p-3">
              <span className="break-all font-mono text-xs">{loc.url}</span>
              <span className="text-slate-600">{loc.reason}</span>
              <span className="font-medium">{resultLabel(loc.result)}</span>
              {loc.error && <span className="text-red-700">{loc.error}</span>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function resultLabel(result: CheckedLocation_Result): string {
  switch (result) {
    case CheckedLocation_Result.FOUND:
      return "found";
    case CheckedLocation_Result.NOT_FOUND:
      return "not found";
    case CheckedLocation_Result.ERROR:
      return "error";
    case CheckedLocation_Result.REFUSED:
      return "refused";
    default:
      return "unknown";
  }
}
