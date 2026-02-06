// ========================================================================
// AUTH CONTEXT
// Universal authentication state management
// ========================================================================
// It provides:
//   - Authentication state (user, isLoading, isAuthenticated, error)
//   - Authentication actions (login, register, logout, clearError, refreshUser)
//   - React Context pattern for app-wide auth state
//   - Token expiration handling via 'auth:cleared' event
// ========================================================================

import React, { createContext, useContext, useState, useEffect } from 'react';
import { getStoredUser, getStoredToken } from '../api';
import type { User } from '../api';
import type { BaseApi } from '../api/client';

// ========================================================================
// TYPES
// ========================================================================

export interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
}

export interface AuthActions {
  login: (email: string, password: string) => Promise<boolean>;
  register: (email: string, password: string, firstName: string, lastName: string) => Promise<boolean>;
  logout: () => void;
  clearError: () => void;
  refreshUser: () => Promise<void>;
}

export type AuthContextType = AuthState & AuthActions;

// ========================================================================
// CONTEXT
// ========================================================================

const AuthContext = createContext<AuthContextType | undefined>(undefined);

/**
 * Hook to access authentication state and actions.
 * Must be used within an AuthProvider.
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// ========================================================================
// PROVIDER FACTORY
// ========================================================================

/**
 * Creates an AuthProvider component that uses the specified API instance.
 * This allows the universal auth context to work with any API that extends BaseApi.
 * 
 * @example
 * ```typescript
 * // In your app's auth setup:
 * import { createAuthProvider } from '@/core/auth';
 * import { myAppApi } from '@/services/myAppApi';
 * 
 * export const MyAppAuthProvider = createAuthProvider(myAppApi);
 * ```
 */
export function createAuthProvider(api: BaseApi) {
  const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [state, setState] = useState<AuthState>({
      user: getStoredUser(),
      isLoading: false,
      isAuthenticated: !!getStoredToken(),
      error: null,
    });

    // Listen for auth:cleared event (token expiration, session invalidation)
    useEffect(() => {
      const handleAuthCleared = () => {
        console.log('[Auth] Session expired or invalidated - clearing auth state');
        setState({
          user: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        });
      };

      window.addEventListener('auth:cleared', handleAuthCleared);
      return () => window.removeEventListener('auth:cleared', handleAuthCleared);
    }, []);

    // Refresh user data from backend on mount if authenticated
    useEffect(() => {
      const refreshUserData = async () => {
        const token = getStoredToken();
        if (token) {
          try {
            const currentUser = await api.getCurrentUser();
            setState(prev => ({
              ...prev,
              user: currentUser,
              isAuthenticated: true,
            }));
          } catch (error: unknown) {
            console.error('[Auth] Failed to refresh user data:', error);
            const httpError = error as { status?: number };
            if (httpError?.status === 401 || httpError?.status === 403) {
              console.warn('[Auth] Auth failed - clearing local state only');
              localStorage.removeItem('auth_token');
              localStorage.removeItem('user_data');
              setState({
                user: null,
                isAuthenticated: false,
                isLoading: false,
                error: null,
              });
            } else {
              console.warn('[Auth] Keeping user logged in with cached data');
            }
          }
        }
      };

      refreshUserData();
    }, []);

    const login = async (email: string, password: string): Promise<boolean> => {
      setState(prev => ({ ...prev, isLoading: true, error: null }));
      
      try {
        const result = await api.login(email, password);
        setState(prev => ({
          ...prev,
          user: result.user,
          isAuthenticated: true,
          isLoading: false,
        }));
        return true;
      } catch (error) {
        setState(prev => ({
          ...prev,
          error: error instanceof Error ? error.message : 'Login failed',
          isLoading: false,
        }));
        return false;
      }
    };

    const register = async (email: string, password: string, firstName: string, lastName: string): Promise<boolean> => {
      setState(prev => ({ ...prev, isLoading: true, error: null }));
      
      try {
        const result = await api.register(email, password, firstName, lastName);
        setState(prev => ({
          ...prev,
          user: result.user,
          isAuthenticated: true,
          isLoading: false,
        }));
        return true;
      } catch (error) {
        setState(prev => ({
          ...prev,
          error: error instanceof Error ? error.message : 'Registration failed',
          isLoading: false,
        }));
        return false;
      }
    };

    const logout = () => {
      api.logout();
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      });
    };

    const clearError = () => {
      setState(prev => ({ ...prev, error: null }));
    };

    const refreshUser = async () => {
      try {
        const currentUser = await api.getCurrentUser();
        setState(prev => ({
          ...prev,
          user: currentUser,
        }));
      } catch (error) {
        console.error('[Auth] Failed to refresh user:', error);
      }
    };

    return (
      <AuthContext.Provider
        value={{
          ...state,
          login,
          register,
          logout,
          clearError,
          refreshUser,
        }}
      >
        {children}
      </AuthContext.Provider>
    );
  };

  return AuthProvider;
}
