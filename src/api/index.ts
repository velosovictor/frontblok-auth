// ========================================================================
// CORE API EXPORTS
// ========================================================================
// 
// RECOMMENDED: Use createAuthApi() factory (no inheritance needed)
//   import { createAuthApi } from '@rationalbloks/frontblok-auth';
//   export const authApi = createAuthApi(API_URL);
//
// ALTERNATIVE: Extend BaseApi if you need custom methods (not recommended)
//   class MyApi extends BaseApi { ... }
//
// ========================================================================

export { 
  BaseApi, 
  createAuthApi, 
  getStoredUser, 
  getStoredToken, 
  isAuthenticated,
  // OAuth nonce generator
  generateOAuthNonce
} from './client';

export type { 
  User, 
  ApiKey, 
  ApiKeyCreateResponse, 
  AuthResponse,
  // New types for extended auth features
  GoogleOAuthResponse,
  PasswordResetRequestResponse,
  PasswordResetResponse,
  EmailVerificationResponse,
  SetPasswordResponse
} from './types';
