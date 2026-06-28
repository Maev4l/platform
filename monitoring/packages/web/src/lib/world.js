import * as echarts from 'echarts';

let registered = false;
export const ensureWorld = async () => {
  if (registered) return;
  const res = await fetch('https://cdn.jsdelivr.net/gh/johan/world.geo.json@master/countries.geo.json');
  echarts.registerMap('world', await res.json());
  registered = true;
};

// ISO-A2 → [lng,lat] centroid + display name (extend as needed).
export const CENTROIDS = {
  US: { name: 'United States', coord: [-98, 39] },
  FR: { name: 'France', coord: [2.4, 46.6] },
  DE: { name: 'Germany', coord: [10.4, 51.1] },
  GB: { name: 'United Kingdom', coord: [-1.5, 52.6] },
  ES: { name: 'Spain', coord: [-3.7, 40.2] },
  BR: { name: 'Brazil', coord: [-51, -10] },
  IN: { name: 'India', coord: [79, 22] },
  JP: { name: 'Japan', coord: [138, 36.5] },
  CA: { name: 'Canada', coord: [-106, 56] },
  AU: { name: 'Australia', coord: [134, -25] },
  SG: { name: 'Singapore', coord: [103.8, 1.35] },
  ZA: { name: 'South Africa', coord: [24.5, -29] },
};
