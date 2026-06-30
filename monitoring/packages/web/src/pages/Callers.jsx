import { useEffect, useState } from 'react';
import { Link, useLocation, useOutletContext } from 'react-router-dom';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { api } from '@/lib/api';
import { useFilters } from '@/lib/useFilters';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';

// Unique client IPs grouped by country (alphabetical, "Unknown" last), reached
// from the "Unique Callers" KPI. Honors the same source/date filters as the
// dashboard (URL search params), so the Back link round-trips cleanly.
export default function Callers() {
  const sources = useOutletContext();
  const { source, from, to } = useFilters(sources);
  const { search } = useLocation();
  const [groups, setGroups] = useState([]);
  const [collapsed, setCollapsed] = useState(() => new Set());

  useEffect(() => {
    if (!source) return;
    api('/api/callers', { source, from, to })
      // Guard against a missing/malformed groups array.
      .then((d) => setGroups(Array.isArray(d?.groups) ? d.groups : []))
      .catch((err) => console.error('callers fetch failed', err));
  }, [source, from, to]);

  const total = groups.reduce((n, g) => n + (g.count ?? 0), 0);
  const toggle = (country) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(country)) next.delete(country);
      else next.add(country);
      return next;
    });

  return (
    <main className="flex flex-1 flex-col gap-3.5 p-4 min-h-0">
      <div className="flex items-center gap-3 font-mono text-[11px]">
        <Link to={{ pathname: '/', search }}><Button variant="outline" size="sm">◀ Back</Button></Link>
        <span className="text-signal uppercase tracking-[0.1em]">Unique Callers</span>
        <span className="text-muted-foreground">
          {total.toLocaleString()} ip across {groups.length} {groups.length === 1 ? 'country' : 'countries'}
        </span>
      </div>

      <div className="flex flex-1 flex-col gap-3.5 overflow-auto min-h-0">
        {groups.length === 0 && (
          <div className="font-mono text-[11px] text-muted-foreground">No callers in range</div>
        )}
        {groups.map((g) => {
          const isCollapsed = collapsed.has(g.country);
          return (
            <Card key={g.country}>
              <button
                type="button"
                onClick={() => toggle(g.country)}
                className="flex w-full items-center justify-between border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em]"
              >
                <span className="flex items-center gap-2 text-foreground">
                  {isCollapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                  {g.country}
                </span>
                <span className="text-muted-foreground">{g.count} {g.count === 1 ? 'ip' : 'ips'}</span>
              </button>
              {!isCollapsed && (
                <div className="py-1.5">
                  {g.ips.map((ip) => (
                    <div key={ip.ip} className="flex items-baseline justify-between gap-3 px-3.5 py-1.5 font-mono text-[11.5px]">
                      <span className="truncate text-foreground">{ip.ip}</span>
                      {ip.city && <span className="flex-1 truncate text-[10px] text-muted-foreground">{ip.city}</span>}
                      <span className="tabular-nums text-muted-foreground">{ip.requests.toLocaleString()} req</span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </main>
  );
}
