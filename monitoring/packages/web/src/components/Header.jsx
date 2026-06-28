import { Select } from '@/components/ui/Select';
import { ToggleGroup } from '@/components/ui/ToggleGroup';

export const Header = ({ sources, state, setState }) => (
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
      <ToggleGroup
        value={state.groupBy}
        onChange={(v) => setState((s) => ({ ...s, groupBy: v }))}
        items={[{ value: 'day', label: 'Day' }, { value: 'week', label: 'Week' }, { value: 'month', label: 'Month' }]}
      />
    </div>
  </header>
);
