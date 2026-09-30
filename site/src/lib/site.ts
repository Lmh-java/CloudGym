export const site = {
  title: 'CloudGym',
  github: 'https://github.com/Lmh-java/CloudGym',
};

// Keep local assets and navigation working under a GitHub Pages subdirectory.
export const base = import.meta.env.BASE_URL.replace(/\/$/, '');
export const assetPath = (path: string) => `${base}/${path}`;
export const modelIcon = (provider: string) =>
  assetPath(`icons/${provider === 'Anthropic' ? 'claude' : 'chatgpt'}.svg`);
