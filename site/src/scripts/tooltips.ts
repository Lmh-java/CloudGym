let trigger: HTMLElement | undefined;
let tooltip: HTMLElement | undefined;
let timer: ReturnType<typeof setTimeout> | undefined;

function position() {
  if (!trigger || !tooltip) return;
  const rect = trigger.getBoundingClientRect();
  const box = tooltip.getBoundingClientRect();
  const left = Math.max(
    12,
    Math.min(
      rect.left + rect.width / 2 - box.width / 2,
      innerWidth - box.width - 12,
    ),
  );
  const above = rect.top - box.height - 9;
  const top =
    above >= 12
      ? above
      : Math.min(rect.bottom + 9, innerHeight - box.height - 12);
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${Math.max(12, top)}px`;
}
function hide() {
  clearTimeout(timer);
  if (tooltip) tooltip.hidden = true;
  trigger = undefined;
  tooltip = undefined;
}
function show(target: HTMLElement) {
  clearTimeout(timer);
  if (target !== trigger) hide();
  trigger = target;
  tooltip = document.getElementById(`help-${target.dataset.help}`)!;
  tooltip.hidden = false;
  position();
}
function scheduleHide() {
  clearTimeout(timer);
  timer = setTimeout(() => {
    if (!trigger?.matches(':hover, :focus') && !tooltip?.matches(':hover'))
      hide();
  }, 120);
}
document.querySelectorAll<HTMLElement>('[data-help]').forEach((target) => {
  target.removeAttribute('title'); // Avoid a second, browser-native tooltip.
  target.addEventListener('pointerenter', () => show(target));
  target.addEventListener('focus', () => show(target));
  target.addEventListener('pointerleave', scheduleHide);
  target.addEventListener('blur', scheduleHide);
});
document.querySelectorAll<HTMLElement>('.help-tooltip').forEach((element) => {
  element.addEventListener('pointerenter', () => clearTimeout(timer));
  element.addEventListener('pointerleave', scheduleHide);
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') hide();
});
window.addEventListener('resize', position);
window.addEventListener('scroll', position, { passive: true, capture: true });
