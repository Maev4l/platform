import { useEffect, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { api } from '@/lib/api';
import { Header } from '@/components/Header';

// App shell: fetches the source list once and renders the shared Header plus
// the active route. `sources` is passed to routed pages via Outlet context so
// they (and Header) can resolve the first-source default for useFilters.
export const Layout = () => {
  const [sources, setSources] = useState([]);

  useEffect(() => {
    api('/api/sources')
      // Guard against a non-array response (unexpected API shape on error).
      .then((s) => setSources(Array.isArray(s) ? s : []))
      .catch((err) => console.error('sources fetch failed', err));
  }, []);

  return (
    <div className="flex h-screen flex-col">
      <Header sources={sources} />
      <Outlet context={sources} />
    </div>
  );
};
