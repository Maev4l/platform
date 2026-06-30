import { Link, useLocation } from 'react-router-dom';
import { Card } from '@/components/ui/Card';

const Kpi = ({ label, value, unit, accent }) => (
  <Card className="relative h-full overflow-hidden p-4">
    <span className={`absolute left-0 top-0 h-full w-[3px] ${accent ? 'bg-signal shadow-[0_0_10px_rgba(200,241,53,.5)]' : 'bg-border'}`} />
    <div className="font-mono text-[9.5px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
    <div className={`mt-2 font-mono text-3xl font-semibold tabular-nums ${accent ? 'text-signal' : ''}`}>
      {value}{unit && <span className="ml-1 text-sm text-muted-foreground">{unit}</span>}
    </div>
  </Card>
);

export const Kpis = ({ summary, countries }) => {
  const { search } = useLocation();
  return (
    <div className="grid grid-cols-4 gap-3.5">
      <Kpi label="Total Requests" value={(summary?.total ?? 0).toLocaleString()} accent />
      {/* Clickable → Callers view; preserve the current filters via the search string. */}
      <Link
        to={{ pathname: '/callers', search }}
        aria-label="View unique callers by country"
        className="block transition-transform hover:-translate-y-0.5 [&>div]:hover:border-signal/60"
      >
        <Kpi label="Unique Callers ▸" value={(summary?.uniqueIps ?? 0).toLocaleString()} unit="ip" />
      </Link>
      <Kpi label="Error Rate · 4xx+5xx" value={(summary?.errorRate ?? 0).toFixed(2)} unit="%" />
      {/* Derived from the IP-resolved world geo (matches the map), not c-country. */}
      <Kpi label="Countries" value={countries ?? 0} />
    </div>
  );
};
