// Tree-shaken ECharts: import only the charts/components the app uses and
// register them, instead of pulling in the full `echarts` bundle (~1 MB).
// Consumers do `import * as echarts from '@/lib/echarts'` and get init /
// registerMap / etc. from echarts/core with the pieces below already enabled.
import { BarChart, EffectScatterChart, PieChart } from 'echarts/charts';
import { GeoComponent, GridComponent, TooltipComponent } from 'echarts/components';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';

use([
  BarChart, // Histogram
  PieChart, // StatusDonut
  EffectScatterChart, // GeoMap blips
  GeoComponent, // GeoMap world map
  GridComponent, // Histogram axes
  TooltipComponent, // all charts
  CanvasRenderer,
]);

export * from 'echarts/core';
