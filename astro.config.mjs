// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import cloudflare from '@astrojs/cloudflare';

const isDev = process.argv.includes('dev');

// https://astro.build/config
export default defineConfig({
  site: 'https://jmcenvironmental.ie',
  vite: {
    plugins: [tailwindcss()],
  },
  // Skip Cloudflare adapter in dev (miniflare incompatible with Node v25)
  ...(isDev ? {} : { adapter: cloudflare() }),
});