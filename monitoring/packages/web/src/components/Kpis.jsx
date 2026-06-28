import { Card } from '@/components/ui/Card';

const Kpi = ({ label, value, unit, accent }) => (
  <Card className="relative overflow-hidden p-4">
    <span className={`absolute left-0 top-0 h-full w-[3px] ${accent ? 'bg-signal shadow-[0_0_10px_rgba(200,241,53,.5)]' : 'bg-border'}`} />
    <div className="font-mono text-[9.5px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
    <div className={`mt-2 font-mono text-3xl font-semibold tabular-nums ${accent ? 'text-signal' : ''}`}>
      {value}{unit && <span className="ml-1 text-sm text-muted-foreground">{unit}</span>}
    </div>
  </Card>
);

export const Kpis = ({ summary }) => (
  <div className="grid grid-cols-4 gap-3.5">
    <Kpi label="Total Requests" value={(summary?.total ?? 0).toLocaleString()} accent />
    <Kpi label="Unique Callers" value={(summary?.uniqueIps ?? 0).toLocaleString()} unit="ip" />
    <Kpi label="Error Rate · 4xx+5xx" value={(summary?.errorRate ?? 0).toFixed(2)} unit="%" />
    <Kpi label="Countries" value={summary?.countries ?? 0} />
  </div>
);
