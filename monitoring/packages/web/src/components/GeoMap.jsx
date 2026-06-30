import { useEffect, useRef, useState } from 'react';
import * as echarts from '@/lib/echarts';
import { api } from '@/lib/api';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { ensureWorld, CENTROIDS } from '@/lib/world';

const SIGNAL = '#c8f135';
const CYAN = '#39d9c8';
const tip = {
  backgroundColor: '#0c0e12', borderColor: '#1c2129', borderWidth: 1,
  textStyle: { color: '#e7ebef', fontFamily: '"IBM Plex Mono", monospace', fontSize: 11 },
};

const worldOption = (data) => ({
  tooltip: { ...tip, formatter: (p) => (p.value ? `${p.name}<br/><b style="color:${SIGNAL}">${p.value[2].toLocaleString()}</b> callers` : p.name) },
  geo: { map: 'world', roam: true, zoom: 1.2, center: [12, 28], itemStyle: { areaColor: '#13161c', borderColor: '#262c36', borderWidth: 0.6 }, emphasis: { itemStyle: { areaColor: '#1a1f27' }, label: { show: false } }, scaleLimit: { min: 1, max: 8 } },
  series: [{ type: 'effectScatter', coordinateSystem: 'geo', data, zlevel: 2, symbolSize: (v) => Math.max(9, Math.sqrt(v[2]) / 2.4), showEffectOn: 'render', rippleEffect: { brushType: 'stroke', scale: 2.6, period: 4 }, itemStyle: { color: SIGNAL, shadowBlur: 14, shadowColor: 'rgba(200,241,53,.75)' }, emphasis: { scale: 1.5 } }],
});

const countryOption = (data, center) => ({
  tooltip: { ...tip, formatter: (p) => (p.value ? `${p.name}<br/><b style="color:${CYAN}">${p.value[2].toLocaleString()}</b> requests` : p.name) },
  geo: { map: 'world', roam: true, zoom: 11, center, itemStyle: { areaColor: '#13161c', borderColor: '#2a313c', borderWidth: 0.8 }, emphasis: { itemStyle: { areaColor: '#1a1f27' }, label: { show: false } }, scaleLimit: { min: 4, max: 40 } },
  series: [{ type: 'effectScatter', coordinateSystem: 'geo', data, zlevel: 2, symbolSize: (v) => Math.max(5, Math.sqrt(v[2])), showEffectOn: 'render', rippleEffect: { brushType: 'stroke', scale: 2.2, period: 3.5 }, itemStyle: { color: CYAN, shadowBlur: 10, shadowColor: 'rgba(57,217,200,.7)' } }],
});

export const GeoMap = ({ source, from, to, country, setCountry }) => {
  const ref = useRef(null);
  const chart = useRef(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      await ensureWorld();
      if (!alive) return;
      chart.current = echarts.init(ref.current);
      chart.current.on('click', (p) => {
        if (p.seriesType === 'effectScatter' && p.data?.code) {
          setCountry(p.data.code);
        }
      });
      setLoading(false);
    })();
    const onResize = () => chart.current?.resize();
    window.addEventListener('resize', onResize);
    // Cleanup: remove resize listener and dispose chart on unmount
    return () => { alive = false; window.removeEventListener('resize', onResize); chart.current?.dispose(); };
  }, [setCountry]);

  useEffect(() => {
    if (loading || !source) return;
    const c = chart.current;
    if (!country) {
      api('/api/geo', { source, from, to })
        .then((d) => {
          if (!c || c.isDisposed()) return;
          const data = (d?.countries ?? []).filter((x) => CENTROIDS[x.country]).map((x) => ({ name: CENTROIDS[x.country].name, code: x.country, value: [...CENTROIDS[x.country].coord, x.callers] }));
          c.setOption(worldOption(data), true);
        })
        .catch((err) => console.error('geo world fetch failed', err));
    } else {
      api('/api/geo', { source, from, to, country })
        .then((d) => {
          if (!c || c.isDisposed()) return;
          const data = (d?.points ?? []).map((p) => ({ name: `${p.city} · ${p.ip}`, value: [p.lng, p.lat, p.requests] }));
          c.setOption(countryOption(data, CENTROIDS[country]?.coord || [0, 20]), true);
        })
        .catch((err) => console.error('geo drill fetch failed', err));
    }
  }, [loading, source, from, to, country]);

  return (
    <Card className="relative flex flex-col min-h-0">
      <div className="flex items-center gap-3 border-b border-border px-3.5 py-2.5 font-mono text-[11px]">
        {country && <Button variant="outline" size="sm" onClick={() => setCountry('')}>◀ Back</Button>}
        <span className={country ? 'text-muted-foreground' : 'text-signal uppercase tracking-[0.1em]'}>Global View</span>
        {country && <><span className="text-muted-foreground">▸</span><span className="text-signal uppercase tracking-[0.1em]">{country}</span></>}
      </div>
      <div ref={ref} className="flex-1 min-h-0" />
    </Card>
  );
};
