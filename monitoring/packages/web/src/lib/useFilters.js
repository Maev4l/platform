import { useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import dayjs from 'dayjs';

// Preset date ranges → number of days back from today (90 = log retention max).
export const RANGES = { 'Last 7 days': 7, 'Last 14 days': 14, 'Last 30 days': 30, 'Last 90 days': 90 };

const today = () => dayjs().format('YYYY-MM-DD');
const daysAgo = (n) => dayjs().subtract(n, 'day').format('YYYY-MM-DD');

// Reverse the from/to span back to a preset label for the Select; falls back to
// the 14-day default label when the span doesn't match a preset.
const rangeLabel = (from, to) => {
  if (to === today()) {
    const days = dayjs(to).diff(dayjs(from), 'day');
    const match = Object.keys(RANGES).find((k) => RANGES[k] === days);
    if (match) return match;
  }
  return 'Last 14 days';
};

// Shared dashboard filters, backed by URL search params so refresh / browser
// Back / deep-link preserve them and the /callers route inherits the same
// selection. `sources` is used only for the first-source default and to gate
// canonicalization until the source list has loaded.
export const useFilters = (sources) => {
  const [params, setParams] = useSearchParams();

  const source = params.get('source') || sources?.[0] || '';
  const from = params.get('from') || daysAgo(14);
  const to = params.get('to') || today();
  const groupBy = params.get('groupBy') || 'day';

  // Write the effective defaults into the URL once the source list is known, so
  // the URL is always canonical (a bare refresh on /callers keeps the filters).
  // Guarded on `missing`, so it no-ops after the first write — no render loop.
  useEffect(() => {
    if (!sources || sources.length === 0) return;
    const missing = !params.get('source') || !params.get('from') || !params.get('to') || !params.get('groupBy');
    if (!missing) return;
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (!p.get('source')) p.set('source', sources[0]);
      if (!p.get('from')) p.set('from', daysAgo(14));
      if (!p.get('to')) p.set('to', today());
      if (!p.get('groupBy')) p.set('groupBy', 'day');
      return p;
    }, { replace: true });
  }, [sources, params, setParams]);

  const patch = useCallback((next) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      Object.entries(next).forEach(([k, v]) => p.set(k, v));
      return p;
    }, { replace: true });
  }, [setParams]);

  const setSource = useCallback((v) => patch({ source: v }), [patch]);
  const setGroupBy = useCallback((v) => patch({ groupBy: v }), [patch]);
  const setRange = useCallback((label) => {
    const days = RANGES[label] ?? 14;
    patch({ from: daysAgo(days), to: today() });
  }, [patch]);

  return { source, from, to, groupBy, range: rangeLabel(from, to), setSource, setRange, setGroupBy };
};
