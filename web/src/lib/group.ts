import { type Component, Confidence } from "../gen/touchstone/v1/scan_pb";

export interface Tier {
  confidence: Confidence;
  label: string;
  components: Component[];
}

const order: { confidence: Confidence; label: string }[] = [
  { confidence: Confidence.HIGH, label: "High confidence" },
  { confidence: Confidence.MEDIUM, label: "Medium confidence" },
  { confidence: Confidence.LOW, label: "Low confidence" },
  { confidence: Confidence.UNSPECIFIED, label: "Unrated" },
];

/** Groups components by confidence tier, best evidence first; empty tiers are dropped. */
export function groupByTier(components: readonly Component[]): Tier[] {
  return order
    .map((t) => ({ ...t, components: components.filter((c) => c.confidence === t.confidence) }))
    .filter((t) => t.components.length > 0);
}
