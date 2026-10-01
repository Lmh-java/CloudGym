import data from '../data/results.json';
export type Condition = 'consulted' | 'prompted' | 'control';
export type Category = 'sc' | 'ia' | 'ec';
export const DEFAULT_CONDITION: Condition = 'consulted';
export const results = data;
export const sortedModels = (condition: Condition) =>
  [...data.models].sort(
    (a, b) =>
      b.scores[condition].overall - a.scores[condition].overall ||
      a.name.localeCompare(b.name),
  );
export function rankOf(condition: Condition, score: number) {
  return (
    1 +
    data.models.filter((model) => model.scores[condition].overall > score)
      .length
  );
}
export const percent = (value: number) => value.toFixed(1) + '%';
