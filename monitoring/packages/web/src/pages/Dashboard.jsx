import { useEffect, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { api } from '@/lib/api';
import { useFilters } from '@/lib/useFilters';
import { Kpis } from '@/components/Kpis';
import { GeoMap } from '@/components/GeoMap';
import { Histogram } from '@/components/Histogram';
import { StatusDonut } from '@/components/StatusDonut';
import { TopList } from '@/components/TopList';

export default function Dashboard() {
  const sources = useOutletContext();
  const { source, from, to, groupBy } = useFilters(sources);
  const [country, setCountry] = useState(''); // map drill-down (view-only, dashboard-local)
  const [summary, setSummary] = useState(null);
  const [countryCount, setCountryCount] = useState(0);

  // Reset the drill-down when the source changes (old Header did this inline).
  useEffect(() => { setCountry(''); }, [source]);

  useEffect(() => {
    if (!source) return;
    api('/api/summary', { source, from, to })
      .then(setSummary)
      .catch((err) => console.error('summary fetch failed', err));
  }, [source, from, to]);

  // "Countries" KPI = count of countries in the IP-resolved world geo (matches
  // the map's dots); the summary query no longer counts c_country.
  useEffect(() => {
    if (!source) return;
    api('/api/geo', { source, from, to })
      .then((d) => setCountryCount(d?.countries?.length ?? 0))
      .catch((err) => console.error('country count fetch failed', err));
  }, [source, from, to]);

  return (
    <main className="grid flex-1 grid-cols-[1fr_340px] grid-rows-[auto_1fr_auto] gap-3.5 p-4 min-h-0">
      <div className="col-span-2"><Kpis summary={summary} countries={countryCount} /></div>
      <GeoMap source={source} from={from} to={to} country={country} setCountry={setCountry} />
      <aside className="flex flex-col gap-3.5 min-h-0">
        <StatusDonut summary={summary} />
        <TopList source={source} from={from} to={to} country={country} summary={summary} />
      </aside>
      <div className="col-span-2"><Histogram source={source} from={from} to={to} groupBy={groupBy} /></div>
    </main>
  );
}
