import { useEffect, useRef } from 'react';
import * as echarts from '@/lib/echarts';
import { Card } from '@/components/ui/Card';

export const StatusDonut = ({ summary }) => {
  const ref = useRef(null);
  const chart = useRef(null);

  useEffect(() => {
    chart.current = echarts.init(ref.current);
    // Cleanup: dispose chart on unmount to avoid memory leaks (no resize listener needed for fixed-size donut)
    return () => { chart.current?.dispose(); };
  }, []);

  useEffect(() => {
    if (!summary) return;
    // Guard against a disposed chart if the component unmounted while summary was being set
    if (!chart.current || chart.current.isDisposed()) return;
    const errors = summary.errors ?? 0;
    const redirects = summary.redirects ?? 0;
    // Green absorbs any stray non-3xx/non-error status (1xx/unknown) so the
    // three slices always sum to total; in practice this is just the 2xx count.
    const ok = Math.max(0, (summary.total ?? 0) - errors - redirects);
    chart.current.setOption({
      series: [{ type: 'pie', radius: ['62%', '92%'], label: { show: false }, labelLine: { show: false }, itemStyle: { borderColor: '#0f1217', borderWidth: 2 },
        data: [
          { value: ok, name: '2xx', itemStyle: { color: '#c8f135' } },
          { value: redirects, name: '3xx', itemStyle: { color: '#e8a13a' } },
          { value: errors, name: '4xx/5xx', itemStyle: { color: '#ff5a5a' } },
        ] }],
    });
  }, [summary]);

  return (
    <Card className="flex flex-col">
      <div className="border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">Status Mix</div>
      <div ref={ref} className="h-[150px]" />
    </Card>
  );
};
