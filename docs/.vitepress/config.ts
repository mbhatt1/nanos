import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(
  defineConfig({
    title: 'Authority Nanos',
    description: 'Fork of Nanos with Authority Kernel for AI Agents',

    head: [
      ['link', { rel: 'icon', href: '/favicon.ico' }]
    ],

    themeConfig: {
      logo: '/logo.svg',

      nav: [
        { text: 'Home', link: '/' },
        { text: 'Getting Started', link: '/getting-started/' },
        { text: 'Architecture', link: '/architecture/' },
        { text: 'Security', link: '/security/' },
        { text: 'Policy', link: '/policy/' },
        { text: 'API', link: '/api/' },
        { text: 'FAQ', link: '/faq' }
      ],

      sidebar: {
        '/getting-started/': [
          {
            text: 'Getting Started',
            items: [
              { text: 'Quick Start', link: '/getting-started/' },
              { text: 'Installation', link: '/getting-started/installation' },
              { text: 'First Agent', link: '/getting-started/first-agent' }
            ]
          }
        ],
        '/architecture/': [
          {
            text: 'Architecture',
            items: [
              { text: 'Overview', link: '/architecture/' },
              { text: 'Fork Relationship', link: '/architecture/nanos-fork' },
              { text: 'Authority Kernel', link: '/architecture/authority-kernel' }
            ]
          }
        ],
        '/security/': [
          {
            text: 'Security',
            items: [
              { text: 'Overview', link: '/security/' },
              { text: 'Security Invariants', link: '/security/invariants' },
              { text: 'Threat Model', link: '/security/threat-model' }
            ]
          }
        ],
        '/policy/': [
          {
            text: 'Policy',
            items: [
              { text: 'Overview', link: '/policy/' },
              { text: 'JSON Format', link: '/policy/json-format' },
              { text: 'TOML Format', link: '/policy/toml-format' }
            ]
          }
        ],
        '/api/': [
          {
            text: 'API Reference',
            items: [
              { text: 'Overview', link: '/api/' },
              { text: 'Syscalls', link: '/api/syscalls' },
              { text: 'Effects', link: '/api/effects' }
            ]
          }
        ]
      },

      socialLinks: [
        { icon: 'github', link: 'https://github.com/nanovms/authority-nanos' }
      ],

      footer: {
        message: 'Released under the Apache 2.0 License.',
        copyright: 'Copyright © 2024-present NanoVMs, Inc.'
      },

      search: {
        provider: 'local'
      },

      editLink: {
        pattern: 'https://github.com/nanovms/authority-nanos/edit/main/docs/:path',
        text: 'Edit this page on GitHub'
      }
    },

    mermaid: {
      theme: 'default'
    },

    mermaidPlugin: {
      class: 'mermaid'
    }
  })
)
