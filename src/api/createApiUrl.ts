// ========================================================================
// API URL FACTORY
// ========================================================================
// Universal API URL resolution for RationalBloks apps.
//
// In production, the URL is injected via Docker build args (VITE_DATABASE_API_URL).
// In development, falls back to localhost:8000.
//
// This function lives in the package so URL resolution logic is consistent
// across ALL customer apps and can be updated via npm — eliminating the
// entire class of "localhost baked into production" bugs.
//
// Usage:
//   import { createApiUrl } from '@rationalbloks/frontblok-auth';
//   const authApi = createAuthApi(createApiUrl());
// ========================================================================

/**
 * Options for createApiUrl.
 */
export interface CreateApiUrlOptions {
  /** 
   * Override the env variable name. Default: 'VITE_DATABASE_API_URL'.
   * This is read from import.meta.env at call time.
   */
  envVar?: string;
  
  /**
   * Fallback URL for local development (only used when import.meta.env.DEV is true).
   * Default: 'http://localhost:8000'
   */
  devFallback?: string;
}

/**
 * Resolves the backend API URL for the current environment.
 * 
 * Resolution order:
 * 1. `import.meta.env.VITE_DATABASE_API_URL` (injected at build time)
 * 2. `import.meta.env.VITE_API_URL` (alternative env var name)
 * 3. In development mode only: devFallback (default: 'http://localhost:8000')
 * 4. In production: empty string (will cause API calls to fail loudly)
 * 
 * @param options - Configuration options
 * @returns The resolved API base URL
 * 
 * @example
 * ```typescript
 * import { createApiUrl, createAuthApi } from '@rationalbloks/frontblok-auth';
 * 
 * // Simple usage
 * const authApi = createAuthApi(createApiUrl());
 * 
 * // Custom dev fallback
 * const authApi = createAuthApi(createApiUrl({ devFallback: 'http://localhost:3000' }));
 * ```
 */
export function createApiUrl(options: CreateApiUrlOptions = {}): string {
  const { devFallback = 'http://localhost:8000' } = options;
  
  // CRITICAL: Access env vars via bracket notation so Vite does NOT statically
  // replace them during the LIBRARY build. They must survive as-is so the
  // CONSUMING APP's Vite build resolves them with the correct values.
  // Direct property access (import.meta.env.VITE_X) gets replaced at lib build
  // time when the var is unset → undefined → dead-code-eliminated → 405 errors.
  const env = import.meta.env;
  const fromEnv = env['VITE_DATABASE_API_URL'] || env['VITE_API_URL'];
  
  if (fromEnv) {
    return fromEnv;
  }
  
  // In development, use the fallback
  if (env['DEV']) {
    console.log(`[RationalBloks] Using dev fallback API URL: ${devFallback}`);
    return devFallback;
  }
  
  // In production without env var — this is a build config error
  console.error(
    '[RationalBloks] VITE_DATABASE_API_URL is not set in production. ' +
    'API calls will fail. Ensure the Docker build passes --build-arg VITE_DATABASE_API_URL.'
  );
  return '';
}
