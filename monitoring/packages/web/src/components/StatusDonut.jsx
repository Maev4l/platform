import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
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
    const errors = summary.errors ?? 0;
    const ok = (summary.total ?? 0) - errors;
    chart.current.setOption({
      series: [{ type: 'pie', radius: ['62%', '92%'], label: { show: false }, labelLine: { show: false }, itemStyle: { borderColor: '#0f1217', borderWidth: 2 },
        data: [{ value: ok, name: '2xx/3xx', itemStyle: { color: '#c8f135' } }, { value: errors, name: '4xx/5xx', itemStyle: { color: '#ff5a5a' } }] }],
    });
  }, [summary]);

  return (
    <Card className="flex flex-col">
      <div className="border-b border-border px-3.5 py-2.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">Status Mix</div>
      <div ref={ref} className="h-[150px]" />
    </Card>
  );
};
