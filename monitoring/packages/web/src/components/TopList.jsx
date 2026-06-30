import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Card } from '@/components/ui/Card';

export const TopList = ({ source, from, to, country, summary }) => {
  const [items, setItems] = useState([]);
  const [title, setTitle] = useState('Top URIs');

  useEffect(() => {
    if (country) {
      setTitle(`Top Callers · ${country}`);
      api('/api/geo', { source, from, to, country })
        // Guard against missing points array (e.g. empty/malformed API response)
        .then((d) => setItems((d?.points ?? []).slice(0, 12).map((p) => ({ label: p.ip, sub: p.city, n: p.requests }))))
        .catch((err) => console.error('geo drill fetch failed', err));
    } else {
      setTitle('Top URIs');
      setItems((summary?.topUris ?? []).map((u) => ({ label: u.uri, sub: '', n: u.hits })));
    }
  }, [country, source, from, to, summary]);

  const max = Math.max(1, ...items.map((i) => i.n));
  return (
    <Card className="flex-1 flex flex-col min-h-0">
      <div className="border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">{title}</div>
      <div className="flex-1 overflow-auto py-1.5">
        {items.map((i, idx) => (
          <div key={idx} className="px-3.5 py-2">
            <div className="flex justify-between font-mono text-[11.5px]"><span className="truncate">{i.label}</span><span className="tabular-nums text-muted-foreground">{i.n.toLocaleString()}</span></div>
            <div className="mt-1 h-[3px] rounded bg-border overflow-hidden"><i className="block h-full rounded" style={{ width: `${(i.n / max * 100).toFixed(1)}%`, background: 'linear-gradient(90deg,#8ba31f,#c8f135)' }} /></div>
            {i.sub && <div className="font-mono text-[9.5px] text-muted-foreground">{i.sub}</div>}
          </div>
        ))}
      </div>
    </Card>
  );
};
