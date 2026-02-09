// ========================================================================
// CORE AUTH EXPORTS
// ========================================================================

export { useAuth, createAuthProvider } from './AuthContext';
export type { AuthState, AuthActions, AuthContextType } from './AuthContext';

// App bootstrap
export { createAppRoot } from './AppProvider';
export type { AuthConfig } from './AppProvider';

// Protected Route
export { ProtectedRoute } from './ProtectedRoute';
export type { ProtectedRouteProps } from './ProtectedRoute';
