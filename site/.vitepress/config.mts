import { defineConfig } from 'vitepress';
import { withMermaid } from 'vitepress-plugin-mermaid';

export default withMermaid(
  defineConfig({
    title: 'Synapse Fleet',
    description:
      'Administration, deployment, and development documentation for Synapse Fleet (formerly Signal Horizon) — the fleet intelligence platform for Synapse edge sensors.',
    base: '/',
    appearance: 'dark',
    head: [
      ['link', { rel: 'icon', href: '/images/brand/horizon-icon-dark.svg' }],
      [
        'link',
        {
          rel: 'preconnect',
          href: 'https://fonts.googleapis.com',
        },
      ],
      [
        'link',
        {
          rel: 'preconnect',
          href: 'https://fonts.gstatic.com',
          crossorigin: '',
        },
      ],
      [
        'link',
        {
          href: 'https://fonts.googleapis.com/css2?family=Recursive:slnt,wght,CASL,CRSV,MONO@-15..0,300..1000,0..1,0..1,0..1&display=swap',
          rel: 'stylesheet',
        },
      ],
    ],

    themeConfig: {
      logo: '/images/brand/horizon-icon-dark.svg',
      siteTitle: 'Synapse Fleet',

      nav: [
        { text: 'Getting Started', link: '/getting-started/' },
        { text: 'Deployment', link: '/deployment/' },
        { text: 'Architecture', link: '/architecture/' },
        {
          text: 'Reference',
          items: [
            { text: 'Configuration', link: '/configuration/' },
            { text: 'Synapse Fleet Features', link: '/reference/synapse-fleet-features' },
            { text: 'Synapse Features', link: '/reference/synapse-features' },
            { text: 'Synapse Fleet API', link: '/reference/synapse-fleet-api' },
            { text: 'Synapse API', link: '/reference/synapse-api' },
            { text: 'Synapse CLI', link: '/reference/synapse-cli' },
          ],
        },
        {
          text: 'Brand',
          items: [
            { text: 'Brand Overview', link: '/brand/' },
            { text: 'Color Reference', link: '/brand/color/color-reference.html', target: '_blank' },
            { text: 'Typography Reference', link: '/brand/typography/typography-reference.html', target: '_blank' },
            { text: 'Usage Guide', link: '/brand/guides/usage-guide.html', target: '_blank' },
            { text: 'Brand Lockups', link: '/brand/lockups/lockup-sheet-v1.html', target: '_blank' },
            { text: 'Reference Card', link: '/brand/reference/edge-protection-reference-card.html', target: '_blank' },
          ],
        },
      ],

      sidebar: {
        '/getting-started/': [
          {
            text: 'Getting Started',
            items: [
              { text: 'Overview', link: '/getting-started/' },
              { text: 'Installation', link: '/getting-started/installation' },
              { text: 'Requirements', link: '/getting-started/requirements' },
              { text: 'Quick Start', link: '/getting-started/quickstart' },
              { text: 'Demo Mode', link: '/getting-started/demo-mode' },
            ],
          },
        ],
        '/deployment/': [
          {
            text: 'Deployment',
            items: [
              { text: 'Overview', link: '/deployment/' },
              { text: 'Deploy Synapse Fleet', link: '/deployment/synapse-fleet' },
              {
                text: 'Deploy Synapse Standalone',
                link: '/deployment/synapse-standalone',
              },
              { text: 'Docker', link: '/deployment/docker' },
              { text: 'Kubernetes', link: '/deployment/kubernetes' },
              {
                text: 'Production Checklist',
                link: '/deployment/production',
              },
            ],
          },
        ],
        '/development/': [
          {
            text: 'Development',
            items: [
              { text: 'Overview', link: '/development/' },
              {
                text: 'Local Environment',
                link: '/development/local-setup',
              },
              { text: 'Building', link: '/development/building' },
              { text: 'Testing', link: '/development/testing' },
              { text: 'Benchmarks', link: '/development/benchmarks' },
            ],
          },
        ],
        '/architecture/': [
          {
            text: 'Architecture',
            items: [
              { text: 'Overview', link: '/architecture/' },
              { text: 'Synapse Fleet Hub', link: '/architecture/synapse-fleet' },
              { text: 'Synapse WAF Engine', link: '/architecture/synapse' },
              { text: 'Data Flow & Telemetry', link: '/architecture/data-flow' },
            ],
          },
        ],
        '/configuration/': [
          {
            text: 'Configuration',
            items: [
              { text: 'Overview', link: '/configuration/' },
              { text: 'Synapse Fleet', link: '/configuration/synapse-fleet' },
              { text: 'Synapse', link: '/configuration/synapse' },
              {
                text: 'Feature Toggles',
                link: '/configuration/features',
              },
            ],
          },
        ],
        '/reference/': [
          {
            text: 'Feature Reference',
            items: [
              { text: 'Synapse Fleet Features', link: '/reference/synapse-fleet-features' },
              { text: 'Synapse Features', link: '/reference/synapse-features' },
            ],
          },
          {
            text: 'API Reference',
            items: [
              { text: 'Synapse Fleet REST & WebSocket', link: '/reference/synapse-fleet-api' },
              { text: 'Synapse Admin API', link: '/reference/synapse-api' },
              { text: 'Synapse CLI', link: '/reference/synapse-cli' },
            ],
          },
        ],
        '/brand/': [
          {
            text: 'Brand Guidelines',
            items: [
              { text: 'Overview', link: '/brand/' },
            ],
          },
        ],
      },

      socialLinks: [
        {
          icon: 'github',
          link: 'https://github.com/atlas-crew/edge-protection',
        },
      ],

      search: {
        provider: 'local',
      },

      editLink: {
        pattern:
          'https://github.com/atlas-crew/edge-protection/edit/main/site/:path',
        text: 'Edit this page on GitHub',
      },

      footer: {
        message: 'Licensed under AGPL-3.0 · <a href="https://atlascrew.dev">atlascrew.dev</a>',
        copyright: 'Copyright 2026 Atlas Crew',
      },
    },

    mermaid: {
      theme: 'dark',
      themeVariables: {
        primaryColor: '#1E90FF',
        primaryTextColor: '#E8ECF4',
        primaryBorderColor: '#2A3F5C',
        secondaryColor: '#8B5CF6',
        secondaryTextColor: '#E8ECF4',
        secondaryBorderColor: '#4C1D95',
        tertiaryColor: '#101828',
        tertiaryTextColor: '#E8ECF4',
        tertiaryBorderColor: '#1E2D44',
        lineColor: '#5A6F8A',
        textColor: '#E8ECF4',
        mainBkg: '#101828',
        nodeBorder: '#2A3F5C',
        clusterBkg: '#131C2E',
        clusterBorder: '#1E2D44',
        titleColor: '#E8ECF4',
        edgeLabelBackground: '#0C1220',
        nodeTextColor: '#E8ECF4',
      },
    },

    mermaidPlugin: {
      class: 'mermaid',
    },
  }),
);
