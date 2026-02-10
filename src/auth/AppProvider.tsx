// ========================================================================
// CORE AUTH - App Provider Factory
// ========================================================================
// Creates a wrapped app component with OAuth providers configured.
// This is the universal entry point for React apps with authentication.
//
// Usage:
//   import { createAppRoot } from './core/auth';
//   import App from './App';
//   createAppRoot(App, { googleClientId: '...' });
// ========================================================================

import React, { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { GoogleOAuthProvider } from '@react-oauth/google';

export interface AuthConfig {
  // Google OAuth Client ID (optional - only needed if using Google Sign-In)
  googleClientId?: string;
}

// Creates and renders the app root with authentication providers.
// This is the universal way to bootstrap a React app with auth.
export function createAppRoot(
  App: React.ComponentType,
  config: AuthConfig = {}
): void {
  const { googleClientId = '' } = config;

  const root = createRoot(document.getElementById('root')!);

  // Build the component tree with OAuth provider
  // Always wrap with GoogleOAuthProvider to prevent crashes in AuthView
  // When clientId is empty, Google Sign-In just won't work (graceful degradation)
  const appElement = (
    <GoogleOAuthProvider clientId={googleClientId}>
      <App />
    </GoogleOAuthProvider>
  );

  // Render with StrictMode
  root.render(
    <StrictMode>
      {appElement}
    </StrictMode>
  );
}
