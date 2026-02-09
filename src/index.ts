// ============================================================================
// FRONTBLOK-AUTH - CORE MECHANICS EXPORTS
// ============================================================================
// This is the main entry point for the frontblok-auth package.
//
// This package contains ONLY core mechanics:
// - Authentication (JWT tokens, refresh, cross-tab sync)
// - API client (BaseApi with automatic token management)
// - Auth context (React context for auth state)
// - Google OAuth (with CSRF nonce protection)
// - Password reset flow
// - Email verification flow
//
// NO UI COMPONENTS - each app provides its own ErrorBoundary, Navbar, etc.
//
// USAGE:
//   import { createAuthApi, createAuthProvider, useAuth } from '@rationalbloks/frontblok-auth';
//
//   export const authApi = createAuthApi(API_URL);
//   export const AuthProvider = createAuthProvider(authApi);
//
// GOOGLE OAUTH (THE ONE WAY):
//   import { generateOAuthNonce } from '@rationalbloks/frontblok-auth';
//   
//   // 1. Generate nonce once on component mount
//   const [nonce] = useState(() => generateOAuthNonce());
//   
//   // 2. Pass to GoogleLogin
//   <GoogleLogin nonce={nonce} onSuccess={handleSuccess} />
//   
//   // 3. On success, ONE call handles everything
//   const handleSuccess = async (response) => {
//     await authApi.googleLogin(response.credential);  // THE ONE WAY
//     // Done! Tokens stored, nonce cleared, user authenticated.
//   };
// ============================================================================

// API - Auth client factory + utilities
export { 
  BaseApi, 
  createAuthApi, 
  createApiUrl,
  getStoredUser, 
  getStoredToken, 
  isAuthenticated,
  // OAuth: Only generateOAuthNonce is public (THE ONE WAY)
  generateOAuthNonce
} from './api';

export type { CreateApiUrlOptions } from './api';

export type { 
  User, 
  ApiKey, 
  ApiKeyCreateResponse, 
  AuthResponse,
  // Extended auth types
  GoogleOAuthResponse,
  PasswordResetRequestResponse,
  PasswordResetResponse,
  EmailVerificationResponse,
  SetPasswordResponse
} from './api';

// Auth - Authentication context and providers
export { useAuth, createAuthProvider, createAppRoot, ProtectedRoute } from './auth';
export type { AuthState, AuthActions, AuthContextType, AuthConfig, ProtectedRouteProps } from './auth';
