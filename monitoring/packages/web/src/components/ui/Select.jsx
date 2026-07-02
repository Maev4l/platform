import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

export const Select = ({ value, onChange, options, className }) => (
  <div className={cn('relative inline-flex items-center', className)}>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 w-full appearance-none rounded-[4px] border border-border bg-card pl-3 pr-8 font-mono text-sm text-foreground outline-none hover:border-signal/60"
    >
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
    <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
  </div>
);
