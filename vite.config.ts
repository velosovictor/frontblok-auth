import { defineConfig } from 'vite';
import { resolve } from 'path';
import dts from 'vite-plugin-dts';

export default defineConfig({
  // CRITICAL: Prevent Vite from statically replacing import.meta.env.*
  // during the LIBRARY build. These must be preserved as runtime expressions
  // so the CONSUMING APP's Vite build resolves them with correct values.
  define: {
    'import.meta.env.VITE_DATABASE_API_URL': 'import.meta.env.VITE_DATABASE_API_URL',
    'import.meta.env.VITE_API_URL': 'import.meta.env.VITE_API_URL',
    'import.meta.env.DEV': 'import.meta.env.DEV',
  },
  plugins: [
    dts({
      include: ['src'],
      outDir: 'dist',
      rollupTypes: true,
      bundledPackages: [],
      insertTypesEntry: true,
    }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'FrontblokAuth',
      formats: ['es', 'cjs'],
      fileName: (format) => `index.${format === 'es' ? 'js' : 'cjs'}`,
    },
    rollupOptions: {
      external: [
        'react',
        'react-dom',
        'react-dom/client',
        'react-router-dom',
        'react/jsx-runtime',
        '@react-oauth/google',
      ],
      output: {
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          'react-dom/client': 'ReactDOMClient',
          'react-router-dom': 'ReactRouterDOM',
          '@react-oauth/google': 'ReactOAuthGoogle',
        },
      },
    },
    sourcemap: true,
    minify: false,
  },
});
