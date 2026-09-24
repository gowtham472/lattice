import type { AssetReport, Finding, Location, Threat, Tier } from './types';

export const TIERS: Tier[] = ['critical', 'high', 'medium', 'low', 'info'];

export const THREAT_LABEL: Record<Threat, string> = {
  harvest: 'Harvest now, decrypt later',
  forge: 'Trust forged later',
  integrity: 'Integrity',
};

export const THREAT_SHORT: Record<Threat, string> = {
  harvest: 'HNDL',
  forge: 'Forgery',
  integrity: 'Integrity',
};

export function assetTypeLabel(finding: Finding): string {
  return {
    algorithm: 'Algorithm',
    certificate: 'Certificate',
    protocol: 'Protocol',
    'related-crypto-material': 'Key material',
  }[finding.assetType];
}

export function where(location: Location): string {
  if (location.line) return `${location.path}:${location.line}`;
  if (location.byteOffset !== undefined) return `${location.path}@0x${location.byteOffset.toString(16)}`;
  return location.path;
}

export function primaryLocation(report: AssetReport): string {
  const first = report.asset.occurrences[0];
  return first ? where(first.location) : '';
}

export function componentName(component: string, subject: string): string {
  return component === '.' ? subject : component;
}

export function years(value: number): string {
  return `${Number.isInteger(value) ? value : value.toFixed(1)} y`;
}

export function weeks(value: number): string {
  return `${value.toFixed(1)} person-week${value === 1 ? '' : 's'}`;
}

export function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

export function when(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function titleCase(value: string): string {
  return value.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, (c) => c.toUpperCase());
}
