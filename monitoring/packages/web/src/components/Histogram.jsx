import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import { api } from '@/lib/api';
import { Card } from '@/components/ui/Card';

const COLORS = { s2: '#c8f135', s3: '#5b9bff', s4: '#ffb020', s5: '#ff5a5a' };

export const Histogram = ({ state }) => {
  const ref = useRef(null);
  const chart = useRef(null);

  useEffect(() => {
    chart.current = echarts.init(ref.current);
    const r = () => chart.current?.resize();
    window.addEventListener('resize', r);
    // Cleanup: remove resize listener and dispose chart to avoid memory leaks on unmount
    return () => { window.removeEventListener('resize', r); chart.current?.dispose(); };
  }, []);

  useEffect(() => {
    if (!state.source) return;
    api('/api/access', { source: state.source, from: state.from, to: state.to, groupBy: state.groupBy })
      .then((d) => {
        // Guard against missing buckets (e.g. partial API response or network error shape)
        if (!d?.buckets) return;
        // Guard against a disposed chart if the component unmounted while the request was in-flight
        if (!chart.current || chart.current.isDisposed()) return;
        const x = d.buckets.map((b) => b.t);
        const series = ['s2', 's3', 's4', 's5'].map((k) => ({ name: k, type: 'bar', stack: 't', barWidth: '58%', data: d.buckets.map((b) => b[k]), itemStyle: { color: COLORS[k] } }));
        chart.current.setOption({
          tooltip: { trigger: 'axis', backgroundColor: '#0c0e12', borderColor: '#1c2129', textStyle: { color: '#e7ebef', fontFamily: '"IBM Plex Mono", monospace', fontSize: 11 } },
          grid: { left: 54, right: 18, top: 14, bottom: 24 },
          xAxis: { type: 'category', data: x, axisLine: { lineStyle: { color: '#1c2129' } }, axisTick: { show: false }, axisLabel: { color: '#5c6470', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10 } },
          yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255,255,255,.04)' } }, axisLabel: { color: '#5c6470', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, formatter: (v) => (v >= 1000 ? v / 1000 + 'k' : v) } },
          series,
        }, true);
      })
      .catch((err) => console.error('access fetch failed', err));
  }, [state.source, state.from, state.to, state.groupBy]);

  return (
    <Card className="h-[188px] flex flex-col">
      <div className="border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">Requests Over Time</div>
      <div ref={ref} className="flex-1 min-h-0" />
    </Card>
  );
};
