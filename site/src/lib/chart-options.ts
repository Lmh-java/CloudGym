import type { EChartsCoreOption } from 'echarts/core';
import type { Condition } from './results';
import {
  panelModels,
  panelSeries,
  formatValue,
  metricMax,
  type Metric,
} from './panels';
import { modelIcon } from './site';

export function chartOptions(
  kind: Metric,
  condition: Condition,
  width: number,
  reducedMotion: boolean,
): EChartsCoreOption {
  const horizontal = width < 650;
  const single = kind !== 'categories';
  const categoryAxis = {
    type: 'category',
    data: panelModels.map((model) => model.name),
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: {
      color: '#bcc9df',
      margin: horizontal ? 10 : 18,
      interval: 0,
      formatter: (name: string, index: number) =>
        `{${panelModels[index].provider === 'Anthropic' ? 'claude' : 'chatgpt'}|}  {model|${name}}`,
      rich: {
        claude: {
          width: 16,
          height: 16,
          align: 'center',
          verticalAlign: 'middle',
          backgroundColor: { image: modelIcon('Anthropic') },
        },
        chatgpt: {
          width: 16,
          height: 16,
          align: 'center',
          verticalAlign: 'middle',
          backgroundColor: { image: modelIcon('OpenAI') },
        },
        model: {
          color: '#bcc9df',
          fontSize: horizontal ? 10 : 11,
          fontFamily: 'Inter',
          verticalAlign: 'middle',
        },
      },
    },
  };
  const valueAxis = {
    type: 'value',
    min: 0,
    max: metricMax(kind),
    interval: metricMax(kind) / 4,
    axisLabel: {
      color: '#99a8be',
      fontSize: 9,
      formatter: (value: number) => formatValue(kind, value),
    },
    splitLine: {
      lineStyle: { color: '#30405c', type: 'dashed', opacity: 0.65 },
    },
  };
  return {
    animation: !reducedMotion,
    animationDuration: 1000,
    animationEasing: 'cubicOut',
    animationDurationUpdate: 700,
    animationEasingUpdate: 'cubicInOut',
    grid: horizontal
      ? { left: 112, right: single ? 52 : 35, top: 15, bottom: 32 }
      : { left: 42, right: 16, top: 27, bottom: 49 },
    textStyle: { fontFamily: 'Inter' },
    tooltip: {
      trigger: 'axis',
      confine: true,
      backgroundColor: '#162239',
      borderColor: '#3b4e70',
      borderWidth: 1,
      padding: 13,
      textStyle: { color: '#e8edf5', fontSize: 11 },
      axisPointer: { type: 'shadow', shadowStyle: { color: '#8daaff09' } },
      valueFormatter: (value: number) => formatValue(kind, Number(value)),
    },
    xAxis: horizontal ? valueAxis : categoryAxis,
    yAxis: horizontal ? { ...categoryAxis, inverse: true } : valueAxis,
    series: panelSeries(kind, condition).map((series, index) => ({
      id: series.id,
      name: series.name,
      type: 'bar',
      data: panelModels.map((model, i) => ({
        name: model.name,
        value: series.values[i],
      })),
      barMaxWidth: horizontal ? (single ? 20 : 11) : 28,
      barGap: '25%',
      itemStyle: {
        color: series.color,
        borderRadius: horizontal ? [0, 2, 2, 0] : [2, 2, 0, 0],
      },
      emphasis: {
        focus: 'series',
        itemStyle: { shadowBlur: 16, shadowColor: `${series.color}55` },
      },
      label: {
        show: true,
        position: horizontal ? 'right' : 'top',
        color: series.color,
        fontSize: horizontal ? 9 : 10,
        distance: horizontal ? 4 : 8,
        formatter: (params: { value: number }) =>
          kind === 'categories'
            ? Number(params.value).toFixed(1)
            : formatValue(kind, Number(params.value)),
        valueAnimation: true,
      },
      animationDelay: (dataIndex: number) =>
        reducedMotion ? 0 : dataIndex * 65 + index * 45,
    })),
  };
}
