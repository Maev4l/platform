import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import Dashboard from '@/pages/Dashboard';
import Callers from '@/pages/Callers';

// BrowserRouter (clean URLs): the Go embed handler falls back to index.html for
// unknown paths (internal/web/embed.go) and Vite dev serves the SPA entry, so
// refresh / deep-link work in both dev and prod without a hash.
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="callers" element={<Callers />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
