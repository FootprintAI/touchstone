import {
  Confidence,
  LookupStatus,
  type Component,
  type ScanReport,
} from "../gen/touchstone/v1/scan_pb";

export interface Tier {
  confidence: Confidence;
  label: string;
  description: string;
}

/** Tiers in display order, highest confidence first. */
export const TIERS: readonly Tier[] = [
  { confidence: Confidence.HIGH, label: "High confidence", description: "Published by the vendor as an SBOM or VEX." },
  {
    confidence: Confidence.MEDIUM,
    label: "Medium confidence",
    description: "From the vendor's public source repository, at its latest release.",
  },
  {
    confidence: Confidence.LOW,
    label: "Low confidence",
    description: "Inferred from a passive fingerprint of the page and the assets it loads.",
  },
];

export interface TierGroup {
  tier: Tier;
  components: Component[];
}

/**
 * Splits components into the tiers above. A component with no known tier goes
 * to unclassified rather than being dropped.
 */
export function groupByTier(report: ScanReport): { tiers: TierGroup[]; unclassified: Component[] } {
  const known = new Set(TIERS.map((tier) => tier.confidence));
  return {
    tiers: TIERS.map((tier) => ({
      tier,
      components: report.components.filter((c) => c.confidence === tier.confidence),
    })),
    unclassified: report.components.filter((c) => !known.has(c.confidence)),
  };
}

/** True unless the lookup completed, so a partial lookup never looks clean. */
export function lookupIncomplete(report: ScanReport): boolean {
  return report.lookupStatus !== LookupStatus.COMPLETE;
}
