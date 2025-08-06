// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
  integrations: [
    starlight({
      title: 'Spotter - Universal Kubernetes Security Engine',
      description: 'Spotter is a comprehensive Kubernetes security scanner that uses CEL-based rules to identify security vulnerabilities, misconfigurations, and compliance violations across your Kubernetes clusters, manifests, and CI/CD pipelines.',
      logo: {
        src: './src/assets/logo-horizontal.svg',
        replacesTitle: true,
      },
      social: [
          {
            icon: 'github',
            label: 'GitHub',
            href: 'https://github.com/madhuakula/spotter',
          },
        ],
      customCss: [
        './src/styles/custom.css',
      ],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Introduction', slug: 'introduction' },
            { label: 'Installation', slug: 'installation' },
            { label: 'Quick Start', slug: 'quick-start' },
          ],
        },
        {
          label: 'CLI Reference',
          items: [
            { label: 'Command Line Interface', slug: 'cli' },
          ],
        },
        {
          label: 'Security Rules',
          items: [
            { label: 'Built-in Rules', slug: 'rules/builtin' },
            { label: 'Custom Rules', slug: 'rules/custom' },
          ],
        },
        {
          label: 'Deployment',
          items: [
            { label: 'Admission Controller', slug: 'deployment/admission-controller' },
            { label: 'CI/CD Integration', slug: 'deployment/ci-cd' },
            { label: 'Cluster Scanning', slug: 'deployment/cluster' },
          ],
        },
        {
          label: 'Development',
          items: [
            { label: 'Contributing', slug: 'development/contributing' },
          ],
        },
        {
          label: 'Miscellaneous',
          items: [
            { label: 'FAQ', slug: 'faq' },
          ],
        },
      ],
      favicon: '/favicon.svg',
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});