import {
  results,
  DEFAULT_CONDITION,
  sortedModels,
  type Category,
  type Condition,
} from './results';

export type PanelKind = 'categories' | 'cost';
export type Metric = PanelKind | 'tokens';
export const panelModels = sortedModels(DEFAULT_CONDITION);
export function panelSeries(kind: Metric, condition: Condition) {
  if (kind === 'categories')
    return results.categories.map((category) => ({
      id: category.key,
      name: category.name,
      color: category.color,
      values: panelModels.map(
        (model) => model.scores[condition][category.key as Category],
      ),
    }));
  if (kind === 'tokens')
    return [
      {
        id: 'tokens',
        name: 'Tokens consumed',
        color: '#b1a2ef',
        values: panelModels.map((model) => model.scores[condition].tokensK),
      },
    ];
  return [
    {
      id: 'cost',
      name: 'Inference cost',
      color: '#8daaff',
      values: panelModels.map((model) => model.scores[condition].cost),
    },
  ];
}
// Units and scales are shared by the static fallback and interactive charts.
export const metrics = {
  categories: { max: 100, label: 'PASS RATE (%)' },
  cost: { max: 1, label: 'USD PER CASE' },
  tokens: { max: 800, label: 'TOKENS PER CASE (THOUSANDS)' },
} satisfies Record<Metric, { max: number; label: string }>;
export const metricMax = (kind: Metric) => metrics[kind].max;
export function formatValue(kind: Metric, value: number) {
  if (kind === 'cost') return `$${value.toFixed(2)}`;
  if (kind === 'tokens') return `${value.toFixed(1)}K`;
  return `${value.toFixed(1)}%`;
}
