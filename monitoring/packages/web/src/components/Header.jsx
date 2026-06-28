import dayjs from 'dayjs';
import { Loader2 } from 'lucide-react';
import { Select } from '@/components/ui/Select';
import { ToggleGroup } from '@/components/ui/ToggleGroup';
import { useApiLoading } from '@/lib/api';

// Preset date ranges → number of days back from today (90 = log retention max).
const RANGES = { 'Last 7 days': 7, 'Last 14 days': 14, 'Last 30 days': 30, 'Last 90 days': 90 };

export const Header = ({ sources, state, setState }) => {
  const loading = useApiLoading();
  return (
  <header className="flex h-[58px] items-center gap-6 border-b border-border px-5">
    <div className="flex items-center gap-2">
      <span className="text-signal text-lg drop-shadow-[0_0_6px_rgba(200,241,53,.6)]">◢</span>
      <div>
        <div className="font-display text-base font-extrabold">EDGE<span className="text-signal">//</span>WATCH</div>
        <div className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">cloudfront access telemetry</div>
      </div>
    </div>
    <div className="ml-auto flex items-center gap-3">
      <Select
        value={state.source}
        onChange={(v) => setState((s) => ({ ...s, source: v, country: '' }))}
        options={sources}
        className="w-[230px]"
      />
      <Select
        value={state.range}
        onChange={(label) => {
          const days = RANGES[label] ?? 14;
          setState((s) => ({
            ...s,
            range: label,
            from: dayjs().subtract(days, 'day').format('YYYY-MM-DD'),
            to: dayjs().format('YYYY-MM-DD'),
          }));
        }}
        options={Object.keys(RANGES)}
        className="w-[150px]"
      />
      <ToggleGroup
        value={state.groupBy}
        onChange={(v) => setState((s) => ({ ...s, groupBy: v }))}
        items={[{ value: 'day', label: 'Day' }, { value: 'week', label: 'Week' }, { value: 'month', label: 'Month' }]}
      />
      {/* In-flight indicator: spinner while any /api request runs, else a live dot. */}
      <span className="flex w-[88px] items-center justify-end gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
        {loading ? (
          <><Loader2 className="h-3.5 w-3.5 animate-spin text-signal" />querying</>
        ) : (
          <><span className="h-[7px] w-[7px] rounded-full bg-signal" />live</>
        )}
      </span>
    </div>
  </header>
  );
};
