import { cn } from '@/lib/utils';

export const ToggleGroup = ({ value, onChange, items }) => (
  <div className="flex h-9 overflow-hidden rounded-[4px] border border-border bg-card">
    {items.map((it, i) => (
      <button
        key={it.value}
        onClick={() => onChange(it.value)}
        className={cn(
          'border-border px-3.5 font-mono text-[11px] uppercase tracking-[0.08em] transition-colors',
          i > 0 && 'border-l',
          value === it.value ? 'bg-signal font-semibold text-[#0b0d07]' : 'text-muted-foreground hover:text-foreground'
        )}
      >
        {it.label}
      </button>
    ))}
  </div>
);
