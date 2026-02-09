// ========================================================================
// PROTECTED ROUTE
// ========================================================================
// Universal auth-guarded route wrapper for React Router.
//
// This component is identical in every RationalBloks app, so it lives
// in the auth package to be updated via npm.
//
// Usage:
//   import { ProtectedRoute } from '@rationalbloks/frontblok-auth';
//   
//   <Route path="/dashboard" element={
//     <ProtectedRoute useAuth={useClientAuth}>
//       <DashboardView />
//     </ProtectedRoute>
//   } />
//
//   // Or with a custom redirect:
//   <ProtectedRoute useAuth={useClientAuth} redirectTo="/login">
// ========================================================================

import React from 'react';
import { Navigate } from 'react-router-dom';

export interface ProtectedRouteProps {
  children: React.ReactNode;
  /** 
   * The useAuth hook from your app's datablokApi.ts (useClientAuth).
   * We accept this as a prop instead of importing it directly to avoid
   * circular dependencies and keep the package decoupled.
   */
  useAuth: () => { isAuthenticated: boolean };
  /**
   * Where to redirect unauthenticated users. Default: '/auth'
   */
  redirectTo?: string;
}

/**
 * Route wrapper that redirects to the auth page if the user is not authenticated.
 */
export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  useAuth,
  redirectTo = '/auth' 
}) => {
  const { isAuthenticated } = useAuth();
  
  if (!isAuthenticated) {
    return <Navigate to={redirectTo} replace />;
  }
  
  return <>{children}</>;
};
