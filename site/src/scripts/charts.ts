import { DEFAULT_CONDITION, type Condition } from '../lib/results';
import { type Metric } from '../lib/panels';
import { chartOptions } from '../lib/chart-options';
import type { EChartsType } from 'echarts/core';

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const controllers: {
  chart?: EChartsType;
  render: (resize?: boolean) => void;
}[] = [];

let condition: Condition = DEFAULT_CONDITION;
for (const viewport of document.querySelectorAll<HTMLElement>(
  '.chart-viewport',
)) {
  const kind = viewport.dataset.metric as Metric;
  const host = viewport.querySelector<HTMLElement>('.interactive-chart')!;
  let loading: Promise<void> | undefined;

  const controller = {
    chart: undefined as EChartsType | undefined,
    render(resize = false) {
      if (!this.chart) return;
      if (resize) this.chart.resize();
      this.chart.setOption(
        chartOptions(
          kind,
          condition,
          viewport.clientWidth,
          reducedMotion.matches,
        ),
        { notMerge: resize },
      );
    },
  };
  controllers.push(controller);

  async function ensureChart() {
    if (controller.chart) return;
    if (!loading)
      loading = (async () => {
        const { init } = await import('../lib/chart');
        controller.chart = init(host, undefined, { renderer: 'svg' });
        controller.render();
        viewport.classList.add('chart-ready');
      })().catch((error) => {
        loading = undefined;
        console.error('Chart enhancement unavailable', error);
      });
    await loading;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      if (entries.some((entry) => entry.isIntersecting)) {
        void ensureChart();
        observer.disconnect();
      }
    },
    { rootMargin: '100px' },
  );
  observer.observe(viewport);
  let frame = 0;
  const resizeObserver = new ResizeObserver(() => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => controller.render(true));
  });
  resizeObserver.observe(viewport);
}
reducedMotion.addEventListener('change', () =>
  controllers.forEach((controller) => controller.render()),
);
document.addEventListener('visibilitychange', () =>
  controllers.forEach(({ chart }) => {
    if (document.hidden) chart?.getZr().animation.stop();
    else chart?.getZr().animation.start();
  }),
);

const buttons = [
  ...document.querySelectorAll<HTMLButtonElement>('[data-tabs] [role="tab"]'),
];
const tabpanel = document.getElementById('condition-results');
if (tabpanel) {
  tabpanel.setAttribute('role', 'tabpanel');
  tabpanel.setAttribute('aria-labelledby', `results-${DEFAULT_CONDITION}-tab`);
  tabpanel.tabIndex = 0;
}
function selectCondition(next: Condition) {
  if (next === condition) return;
  condition = next;
  tabpanel
    ?.querySelectorAll<HTMLElement>('.detail-panel')
    .forEach((panel) => (panel.dataset.condition = next));
  buttons.forEach((button) => {
    const selected = button.dataset.condition === next;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  tabpanel?.setAttribute('aria-labelledby', `results-${next}-tab`);
  tabpanel
    ?.querySelectorAll<HTMLElement>('.static-condition')
    .forEach((el) => (el.hidden = el.dataset.condition !== next));
  tabpanel
    ?.querySelectorAll<HTMLElement>('[data-table-condition]')
    .forEach((el) => (el.hidden = el.dataset.tableCondition !== next));
  controllers.forEach((controller) => controller.render());
}
document.querySelector<HTMLElement>('[data-tabs]')?.removeAttribute('hidden');
buttons.forEach((button, index) => {
  button.addEventListener('click', () =>
    selectCondition(button.dataset.condition as Condition),
  );
  button.addEventListener('keydown', (event) => {
    let target = index;
    if (event.key === 'ArrowRight') target = (index + 1) % buttons.length;
    else if (event.key === 'ArrowLeft')
      target = (index - 1 + buttons.length) % buttons.length;
    else if (event.key === 'Home') target = 0;
    else if (event.key === 'End') target = buttons.length - 1;
    else return;
    event.preventDefault();
    buttons[target].focus();
    selectCondition(buttons[target].dataset.condition as Condition);
  });
});
