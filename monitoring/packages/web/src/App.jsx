import { useEffect, useState } from 'react';
import dayjs from 'dayjs';
import { api } from '@/lib/api';
import { Header } from '@/components/Header';
import { Kpis } from '@/components/Kpis';
import { GeoMap } from '@/components/GeoMap';
import { Histogram } from '@/components/Histogram';
import { StatusDonut } from '@/components/StatusDonut';
import { TopList } from '@/components/TopList';

const today = dayjs().format('YYYY-MM-DD');
const twoWeeksAgo = dayjs().subtract(14, 'day').format('YYYY-MM-DD');

export default function App() {
  const [sources, setSources] = useState([]);
  const [state, setState] = useState({ source: '', from: twoWeeksAgo, to: today, groupBy: 'day', country: '', range: 'Last 14 days' });
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    api('/api/sources')
      .then((s) => {
        // Guard against non-array responses (e.g. unexpected API shape on error)
        const arr = Array.isArray(s) ? s : [];
        setSources(arr);
        setState((st) => ({ ...st, source: st.source || arr[0] || '' }));
      })
      .catch((err) => console.error('sources fetch failed', err));
  }, []);

  useEffect(() => {
    if (!state.source) return;
    api('/api/summary', { source: state.source, from: state.from, to: state.to })
      .then(setSummary)
      .catch((err) => console.error('summary fetch failed', err));
  }, [state.source, state.from, state.to]);

  return (
    <div className="flex h-screen flex-col">
      <Header sources={sources} state={state} setState={setState} />
      <main className="grid flex-1 grid-cols-[1fr_340px] grid-rows-[auto_1fr_auto] gap-3.5 p-4 min-h-0">
        <div className="col-span-2"><Kpis summary={summary} /></div>
        <GeoMap state={state} setState={setState} />
        <aside className="flex flex-col gap-3.5 min-h-0">
          <StatusDonut summary={summary} />
          <TopList state={state} summary={summary} />
        </aside>
        <div className="col-span-2"><Histogram state={state} /></div>
      </main>
    </div>
  );
}
