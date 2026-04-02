import { defineConfig } from 'vitepress';
import { withMermaid } from 'vitepress-plugin-mermaid';

export default withMermaid(
  defineConfig({
    title: 'Horizon',
    description:
      'Administration, deployment, and development documentation for the Horizon edge protection platform.',
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
      siteTitle: 'Horizon',

      nav: [
        { text: 'Getting Started', link: '/getting-started/' },
        { text: 'Deployment', link: '/deployment/' },
        { text: 'Architecture', link: '/architecture/' },
        {
          text: 'Reference',
          items: [
            { text: 'Configuration', link: '/configuration/' },
            { text: 'Horizon Features', link: '/reference/horizon-features' },
            { text: 'Synapse Features', link: '/reference/synapse-features' },
            { text: 'Horizon API', link: '/reference/horizon-api' },
            { text: 'Synapse API', link: '/reference/synapse-api' },
            { text: 'Synapse CLI', link: '/reference/synapse-cli' },
          ],
        },
        {
          text: 'Brand',
          items: [
            { text: 'Brand Overview', link: '/brand/' },
            { text: 'Color Reference', link: '/brand/color-reference.html', target: '_blank' },
            { text: 'Typography Reference', link: '/brand/typography-reference.html', target: '_blank' },
            { text: 'Usage Guide', link: '/brand/usage-guide.html', target: '_blank' },
            { text: 'Lockups', link: '/brand/edge-protection-lockups.html', target: '_blank' },
            { text: 'Reference Card', link: '/brand/edge-protection-reference-card.html', target: '_blank' },
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
            ],
          },
        ],
        '/deployment/': [
          {
            text: 'Deployment',
            items: [
              { text: 'Overview', link: '/deployment/' },
              { text: 'Deploy Horizon', link: '/deployment/horizon' },
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
              { text: 'Horizon Hub', link: '/architecture/horizon' },
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
              { text: 'Horizon', link: '/configuration/horizon' },
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
              { text: 'Horizon Features', link: '/reference/horizon-features' },
              { text: 'Synapse Features', link: '/reference/synapse-features' },
            ],
          },
          {
            text: 'API Reference',
            items: [
              { text: 'Horizon REST & WebSocket', link: '/reference/horizon-api' },
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
