// ========================================================================
// CORE AUTH EXPORTS
// ========================================================================

export { useAuth, createAuthProvider } from './AuthContext';
export type { AuthState, AuthActions, AuthContextType } from './AuthContext';

// App bootstrap
export { createAppRoot } from './AppProvider';
export type { AuthConfig } from './AppProvider';
