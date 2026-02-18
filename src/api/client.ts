// ========================================================================
// BASE API CLIENT
// Universal HTTP client with JWT token management
// ========================================================================
//
// Features:
//   - JWT token storage and automatic refresh
//   - Cross-tab synchronization via localStorage events
//   - Proactive token refresh before expiration
//   - Automatic 401 retry with token refresh
//   - Rate limiting (429) retry with exponential backoff
//   - Authentication methods (login, register, logout)
//   - API key management for external integrations
//
// Usage:
//   1. Extend this class for your application's API
//   2. Add your domain-specific CRUD methods in the subclass
//   3. Call super() in constructor with your API base URL
//
// ========================================================================

import type { 
  User, 
  ApiKey, 
  ApiKeyCreateResponse, 
  AuthResponse,
  GoogleOAuthResponse,
  PasswordResetRequestResponse,
  PasswordResetResponse,
  EmailVerificationResponse,
  SetPasswordResponse
} from './types';

// ========================================================================
// OAUTH UTILITIES (defined before class so they can be used within it)
// ========================================================================

// Generate a cryptographically secure nonce for OAuth CSRF protection.
//
// USAGE:
// 1. Call generateOAuthNonce() in component useState (runs once on mount)
// 2. Pass the nonce to GoogleLogin component via the 'nonce' prop
// 3. On success, call authApi.googleLogin(credential) - it handles the rest
//
// Example:
//   const [nonce] = useState(() => generateOAuthNonce());
//   // Pass to GoogleLogin: <GoogleLogin nonce={nonce} onSuccess={...} />
//   // On success: await authApi.googleLogin(credential);
export const generateOAuthNonce = (): string => {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const nonce = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  sessionStorage.setItem('google_oauth_nonce', nonce);
  console.log('[OAuth] Generated nonce for CSRF protection');
  return nonce;
};

// Retrieve the stored OAuth nonce.
// Returns the stored nonce or null if not found.
export const getOAuthNonce = (): string | null => {
  return sessionStorage.getItem('google_oauth_nonce');
};

// Clear the stored OAuth nonce (call after successful login).
export const clearOAuthNonce = (): void => {
  sessionStorage.removeItem('google_oauth_nonce');
  console.log('[OAuth] Cleared nonce');
};

// ========================================================================
// BASE API CLASS
// ========================================================================

// BaseApi - Universal HTTP client with authentication.
//
// Extend this class to add your application-specific API methods.
//
// Example:
//   class MyAppApi extends BaseApi {
//     constructor() {
//       super(import.meta.env.VITE_API_URL || 'https://api.myapp.com');
//     }
//
//     async getProducts() {
//       return this.request<Product[]>('/api/products/');
//     }
//   }
export class BaseApi {
  protected token: string | null = null;
  protected refreshToken: string | null = null;
  protected isRefreshing: boolean = false;
  protected refreshPromise: Promise<boolean> | null = null;
  protected proactiveRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  protected refreshCheckInterval: ReturnType<typeof setInterval> | null = null;
  protected tokenRefreshPromise: Promise<void> | null = null;
  protected readonly apiBaseUrl: string;

  constructor(apiBaseUrl: string) {
    this.apiBaseUrl = apiBaseUrl;
    this.loadTokens();
    this.setupVisibilityHandler();
    this.setupStorageListener();
    this.startRefreshCheckInterval();
    
    console.log(`[API] Base URL: ${this.apiBaseUrl}`);
    console.log(`[API] Environment: ${import.meta.env.DEV ? 'Development' : 'Production'}`);
  }

  // ========================================================================
  // TOKEN MANAGEMENT
  // ========================================================================

  // Sync tokens across browser tabs when localStorage changes.
  // Prevents "stale refresh token" issue where Tab A rotates the token
  // but Tab B still has the old (now invalid) refresh token in memory.
  private setupStorageListener(): void {
    if (typeof window !== 'undefined') {
      window.addEventListener('storage', (event) => {
        if (event.key === 'auth_token') {
          console.log('[API] Token updated in another tab, syncing...');
          this.token = event.newValue;
        } else if (event.key === 'refresh_token') {
          console.log('[API] Refresh token updated in another tab, syncing...');
          this.refreshToken = event.newValue;
        } else if (event.key === null) {
          // Storage was cleared (logout in another tab)
          console.log('[API] Storage cleared in another tab, syncing logout...');
          this.token = null;
          this.refreshToken = null;
          window.dispatchEvent(new CustomEvent('auth:cleared'));
        }
      });
    }
  }

  // Start interval-based token check (runs every 60 seconds).
  // More reliable than setTimeout which browsers throttle in background tabs.
  private startRefreshCheckInterval(): void {
    if (this.refreshCheckInterval) {
      clearInterval(this.refreshCheckInterval);
    }
    
    this.refreshCheckInterval = setInterval(() => {
      if (this.token) {
        this.checkAndRefreshToken();
      }
    }, 60 * 1000);
  }

  // Handle tab visibility changes - check token when user returns to tab.
  private setupVisibilityHandler(): void {
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' && this.token) {
          console.log('[API] Tab became visible, checking token validity...');
          this.checkAndRefreshToken();
        }
      });
      
      window.addEventListener('focus', () => {
        if (this.token) {
          console.log('[API] Window focused, checking token validity...');
          this.checkAndRefreshToken();
        }
      });
    }
  }

  // Check token expiry and refresh if needed.
  protected async checkAndRefreshToken(): Promise<void> {
    if (!this.token) return;

    const expiry = this.getTokenExpiry(this.token);
    if (!expiry) return;

    const now = Date.now();
    const timeUntilExpiry = expiry - now;
    const refreshBuffer = 3 * 60 * 1000; // 3 minutes buffer

    if (timeUntilExpiry <= 0) {
      console.log('[API] Token expired, refreshing immediately...');
      await this.refreshAccessToken();
    } else if (timeUntilExpiry <= refreshBuffer) {
      console.log(`[API] Token expires in ${Math.round(timeUntilExpiry / 1000)}s, refreshing proactively...`);
      await this.refreshAccessToken();
    }
  }

  // Parse JWT to get expiration time.
  protected getTokenExpiry(token: string): number | null {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp ? payload.exp * 1000 : null;
    } catch {
      return null;
    }
  }

  // Schedule proactive refresh 5 minutes before token expires.
  protected scheduleProactiveRefresh(): void {
    if (this.proactiveRefreshTimer) {
      clearTimeout(this.proactiveRefreshTimer);
      this.proactiveRefreshTimer = null;
    }

    if (!this.token) return;

    const expiry = this.getTokenExpiry(this.token);
    if (!expiry) return;

    const now = Date.now();
    const timeUntilExpiry = expiry - now;
    const refreshBuffer = 5 * 60 * 1000;

    if (timeUntilExpiry <= 0) {
      console.log('[API] Token already expired, refreshing immediately...');
      this.refreshAccessToken();
      return;
    }

    if (timeUntilExpiry <= refreshBuffer) {
      console.log('[API] Token expiring soon, refreshing immediately...');
      this.refreshAccessToken();
      return;
    }

    const refreshIn = timeUntilExpiry - refreshBuffer;
    console.log(`[API] Scheduling proactive token refresh in ${Math.round(refreshIn / 60000)} minutes`);
    
    this.proactiveRefreshTimer = setTimeout(async () => {
      console.log('[API] Proactive token refresh triggered');
      await this.refreshAccessToken();
    }, refreshIn);
  }

  // Load tokens from localStorage on initialization.
  protected loadTokens(): void {
    const storedToken = localStorage.getItem('auth_token');
    const storedRefreshToken = localStorage.getItem('refresh_token');
    
    if (storedToken) {
      this.token = storedToken;
      console.log('[API] Access token loaded from localStorage');
    }
    if (storedRefreshToken) {
      this.refreshToken = storedRefreshToken;
      console.log('[API] Refresh token loaded from localStorage');
    }
    
    if (this.token) {
      this.tokenRefreshPromise = this.checkAndRefreshToken();
      this.scheduleProactiveRefresh();
    }
  }

  // Wait for any pending token refresh to complete before making API calls.
  async ensureTokenReady(): Promise<void> {
    if (this.tokenRefreshPromise) {
      await this.tokenRefreshPromise;
      this.tokenRefreshPromise = null;
    }
  }

  // Refresh the access token using the refresh token.
  async refreshAccessToken(): Promise<boolean> {
    if (this.isRefreshing) {
      return this.refreshPromise || Promise.resolve(false);
    }

    // Sync from localStorage before refresh (another tab may have rotated)
    const latestRefreshToken = localStorage.getItem('refresh_token');
    if (latestRefreshToken && latestRefreshToken !== this.refreshToken) {
      console.log('[API] Syncing refresh token from localStorage');
      this.refreshToken = latestRefreshToken;
    }

    if (!this.refreshToken) {
      console.warn('[API] No refresh token available');
      return false;
    }

    this.isRefreshing = true;
    this.refreshPromise = (async () => {
      try {
        console.log('[API] Refreshing access token...');
        const response = await fetch(`${this.apiBaseUrl}/api/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: this.refreshToken }),
        });

        if (!response.ok) {
          console.error('[API] Token refresh failed:', response.status);
          if (response.status === 401 || response.status === 403) {
            console.log('[API] Refresh token is invalid, logging out...');
            this.clearAuth();
          } else {
            console.warn(`[API] Refresh failed with ${response.status}, will retry on next interval`);
          }
          return false;
        }

        const data = await response.json();
        
        this.token = data.access_token;
        localStorage.setItem('auth_token', data.access_token);
        
        if (data.refresh_token) {
          this.refreshToken = data.refresh_token;
          localStorage.setItem('refresh_token', data.refresh_token);
          console.log('[API] Refresh token rotated');
        }
        
        this.scheduleProactiveRefresh();
        console.log('[API] Access token refreshed successfully');
        return true;
      } catch (error) {
        console.error('[API] Token refresh network error:', error);
        console.warn('[API] Will retry refresh on next interval');
        return false;
      } finally {
        this.isRefreshing = false;
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  // ========================================================================
  // HTTP REQUEST METHOD
  // ========================================================================

  // Make an authenticated HTTP request.
  // Handles token refresh, 401 retry, and rate limiting automatically.
  //
  // This method is public so apps can make custom API calls without extending BaseApi.
  //
  // Example:
  //   const authApi = createAuthApi(API_URL);
  //   const data = await authApi.request<MyType>('/api/my-endpoint/', { method: 'POST', body: JSON.stringify(payload) });
  async request<T>(endpoint: string, options: RequestInit = {}, isRetry = false, retryCount = 0): Promise<T> {
    await this.ensureTokenReady();
    
    // Proactive token refresh before request
    if (this.token && !isRetry && !endpoint.includes('/auth/')) {
      const expiry = this.getTokenExpiry(this.token);
      if (expiry) {
        const now = Date.now();
        const timeUntilExpiry = expiry - now;
        if (timeUntilExpiry < 2 * 60 * 1000) {
          console.log(`[API] Token expires in ${Math.round(timeUntilExpiry/1000)}s, refreshing before request...`);
          await this.refreshAccessToken();
        }
      }
    }
    
    const url = `${this.apiBaseUrl}${endpoint}`;
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    console.log(`[API Request] ${options.method || 'GET'} ${url}`);
    
    try {
      const response = await fetch(url, { ...options, headers });
      
      console.log(`[API Response] ${response.status} ${response.statusText}`);
      
      if (!response.ok) {
        const error = await response.text();
        console.error(`[API Error] ${response.status}: ${error}`);
        
        // Rate limiting retry
        if (response.status === 429 && retryCount < 3) {
          const backoffMs = Math.pow(2, retryCount) * 1000;
          console.log(`[API] Rate limited (429), retrying in ${backoffMs}ms (attempt ${retryCount + 1}/3)...`);
          await new Promise(resolve => setTimeout(resolve, backoffMs));
          return this.request<T>(endpoint, options, isRetry, retryCount + 1);
        }
        
        // 401 retry with token refresh
        if (response.status === 401 && !isRetry && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/register') && !endpoint.includes('/auth/refresh')) {
          console.log('[API] Attempting token refresh...');
          const refreshed = await this.refreshAccessToken();
          if (refreshed) {
            return this.request<T>(endpoint, options, true, retryCount);
          }
          console.warn('[API] Token refresh failed, returning error to caller');
        }
        
        const apiError = new Error(`API Error: ${response.status} - ${error}`) as Error & { status: number };
        apiError.status = response.status;
        throw apiError;
      }

      return response.json();
    } catch (error) {
      console.error('[API Connection Error]:', error);
      if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
        throw new Error(`Cannot connect to API: ${this.apiBaseUrl}`);
      }
      throw error;
    }
  }

  // ========================================================================
  // AUTHENTICATION METHODS
  // ========================================================================

  async login(email: string, password: string): Promise<AuthResponse> {
    console.log('[API] Login attempt:', email);
    
    const data = await this.request<AuthResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    this.token = data.access_token;
    this.refreshToken = data.refresh_token || null;
    localStorage.setItem('auth_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
    localStorage.setItem('user_data', JSON.stringify(data.user));
    
    this.scheduleProactiveRefresh();
    console.log('[API] Login successful');
    return data;
  }

  async register(email: string, password: string, firstName: string, lastName: string): Promise<AuthResponse> {
    console.log('[API] Registration attempt:', email);
    
    const data = await this.request<AuthResponse>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ 
        email, 
        password, 
        first_name: firstName, 
        last_name: lastName 
      }),
    });

    this.token = data.access_token;
    this.refreshToken = data.refresh_token || null;
    localStorage.setItem('auth_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
    localStorage.setItem('user_data', JSON.stringify(data.user));
    
    this.scheduleProactiveRefresh();
    console.log('[API] Registration successful');
    return data;
  }

  async getMe(): Promise<{ user: User }> {
    console.log('[API] Fetching current user');
    return this.request<{ user: User }>('/api/auth/me');
  }

  async getCurrentUser(): Promise<User> {
    console.log('[API] Fetching current user data');
    const response = await this.request<{ user: User }>('/api/auth/me');
    localStorage.setItem('user', JSON.stringify(response.user));
    return response.user;
  }

  // ========================================================================
  // GOOGLE OAUTH AUTHENTICATION
  // ========================================================================

  // Internal: Authenticate with Google OAuth.
  // Use googleLogin() instead.
  private async _googleOAuthLogin(credential: string, nonce: string): Promise<GoogleOAuthResponse> {
    console.log('[API] Google OAuth login attempt');
    
    const data = await this.request<GoogleOAuthResponse>('/api/auth/google/login', {
      method: 'POST',
      body: JSON.stringify({ credential, nonce }),
    });

    this.token = data.access_token;
    this.refreshToken = data.refresh_token || null;
    localStorage.setItem('auth_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
    localStorage.setItem('user_data', JSON.stringify(data.user));
    
    this.scheduleProactiveRefresh();
    console.log(`[API] Google OAuth successful (new_user: ${data.is_new_user})`);
    return data;
  }

  // Simplified Google OAuth login.
  //
  // This is the default method for Google Sign-In. It handles the complete
  // OAuth flow in a single call:
  //
  // 1. Retrieve nonce from sessionStorage (must exist from generateOAuthNonce())
  // 2. Send credential + nonce to backend for verification
  // 3. Store JWT tokens on success
  // 4. Clear nonce to prevent replay attacks
  //
  // If any step fails, the entire operation fails cleanly. No partial states.
  //
  // credential - The Google ID token (JWT from GoogleLogin onSuccess)
  // Returns GoogleOAuthResponse with tokens, user data, and is_new_user flag
  // Throws Error if nonce is missing or authentication fails
  //
  // Example:
  //   // In component: generate nonce ONCE on mount
  //   const [nonce] = useState(() => generateOAuthNonce());
  //
  //   // Pass nonce to GoogleLogin, then on success:
  //   const handleSuccess = async (response: CredentialResponse) => {
  //     const result = await authApi.googleLogin(response.credential!);
  //     // Done! Tokens stored, nonce cleared, user authenticated.
  //   };
  async googleLogin(credential: string): Promise<GoogleOAuthResponse> {
    console.log('[API] Google OAuth login');
    
    // Step 1: Retrieve nonce - MUST exist or we fail immediately
    const nonce = getOAuthNonce();
    if (!nonce) {
      throw new Error('Security validation failed: OAuth nonce not found. Call generateOAuthNonce() before Google Sign-In.');
    }
    
    // Step 2: Authenticate with backend
    const result = await this._googleOAuthLogin(credential, nonce);
    
    // Step 3: Clear nonce AFTER success to prevent replay attacks
    clearOAuthNonce();
    console.log('[API] OAuth nonce cleared (replay protection)');
    
    return result;
  }

  // ========================================================================
  // PASSWORD RESET FLOW
  // ========================================================================

  // Request a password reset email (forgot password flow).
  // email - The email address to send reset link to.
  // Returns message confirming email was sent (or would be sent).
  async requestPasswordReset(email: string): Promise<PasswordResetRequestResponse> {
    console.log('[API] Requesting password reset for:', email);
    
    return this.request<PasswordResetRequestResponse>('/api/auth/request-password-reset', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  // Reset password using token from email.
  // token - The password reset token from the email link.
  // newPassword - The new password (min 8 characters).
  // Returns success message.
  async resetPassword(token: string, newPassword: string): Promise<PasswordResetResponse> {
    console.log('[API] Resetting password with token');
    
    return this.request<PasswordResetResponse>('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    });
  }

  // ========================================================================
  // EMAIL VERIFICATION FLOW
  // ========================================================================

  // Verify email address using token from verification email.
  // token - The verification token from the email link.
  // Returns success message.
  async verifyEmail(token: string): Promise<EmailVerificationResponse> {
    console.log('[API] Verifying email with token');
    
    return this.request<EmailVerificationResponse>('/api/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  // Request a new verification email.
  // email - The email address to send verification to.
  // Returns message confirming email was sent.
  async requestVerificationEmail(email: string): Promise<EmailVerificationResponse> {
    console.log('[API] Requesting verification email for:', email);
    
    return this.request<EmailVerificationResponse>('/api/auth/request-verification-email', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  // ========================================================================
  // SET PASSWORD (FOR OAUTH-ONLY ACCOUNTS)
  // ========================================================================

  // Set password for OAuth-only accounts.
  //
  // Allows users who registered via Google OAuth to set a password
  // so they can also log in with email/password.
  // newPassword - The password to set (min 8 characters).
  // Returns success message.
  async setPassword(newPassword: string): Promise<SetPasswordResponse> {
    console.log('[API] Setting password for OAuth account');
    
    return this.request<SetPasswordResponse>('/api/auth/set-password', {
      method: 'POST',
      body: JSON.stringify({ new_password: newPassword }),
    });
  }

  // ========================================================================
  // ACCOUNT MANAGEMENT
  // ========================================================================

  // Verify password without performing any destructive operation.
  // Used before account deletion to ensure password is correct BEFORE
  // deleting any projects.
  async verifyPassword(password: string): Promise<{ verified: boolean }> {
    console.log('[API] Verifying password');
    
    return this.request<{ verified: boolean }>('/api/auth/verify-password', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
  }

  async deleteAccount(password: string, confirmText: string): Promise<{ message: string; note: string }> {
    console.log('[API] Deleting account (DESTRUCTIVE)');
    
    const response = await this.request<{ message: string; note: string }>('/api/auth/me', {
      method: 'DELETE',
      body: JSON.stringify({ 
        password, 
        confirm_text: confirmText 
      }),
    });
    
    this.clearAuth();
    console.log('[API] Account deleted successfully');
    return response;
  }

  async logout(): Promise<void> {
    console.log('[API] Logging out');
    
    try {
      if (this.refreshToken) {
        await this.request('/api/auth/logout', {
          method: 'POST',
          body: JSON.stringify({ refresh_token: this.refreshToken }),
        });
        console.log('[API] Refresh token revoked on server');
      }
    } finally {
      // Always clear local auth state, even if server revocation failed
      this.clearAuth();
    }
  }

  async logoutAllDevices(): Promise<void> {
    console.log('[API] Logging out from all devices');
    
    try {
      await this.request('/api/auth/logout-all', { method: 'POST' });
      console.log('[API] All sessions revoked on server');
    } finally {
      // Always clear local auth state, even if server revocation failed
      this.clearAuth();
    }
  }

  protected clearAuth(): void {
    if (this.proactiveRefreshTimer) {
      clearTimeout(this.proactiveRefreshTimer);
      this.proactiveRefreshTimer = null;
    }
    
    this.token = null;
    this.refreshToken = null;
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_data');
    console.log('[API] Auth cache cleared');
    
    window.dispatchEvent(new CustomEvent('auth:cleared'));
  }

  // ========================================================================
  // API KEY MANAGEMENT
  // ========================================================================

  async listApiKeys(): Promise<{ api_keys: ApiKey[]; total: number }> {
    console.log('[API] Listing user API keys');
    return this.request('/api/auth/api-keys', { method: 'GET' });
  }

  async createApiKey(data: {
    name: string;
    scopes?: string;
    expires_in_days?: number;
    rate_limit_per_minute?: number;
  }): Promise<ApiKeyCreateResponse> {
    console.log(`[API] Creating API key: ${data.name}`);
    return this.request('/api/auth/api-keys', {
      method: 'POST',
      body: JSON.stringify({
        name: data.name,
        scopes: data.scopes || 'read,write',
        expires_in_days: data.expires_in_days,
        rate_limit_per_minute: data.rate_limit_per_minute || 60
      }),
    });
  }

  async revokeApiKey(keyId: string): Promise<{ message: string; key_prefix: string; revoked_at: string }> {
    console.log(`[API] Revoking API key: ${keyId}`);
    return this.request(`/api/auth/api-keys/${keyId}`, { method: 'DELETE' });
  }
}

// ========================================================================
// FACTORY FUNCTION (RECOMMENDED)
// ========================================================================
// Use this instead of extending BaseApi. Cleaner, no inheritance.
//
// Usage:
//   import { createAuthApi } from '@rationalbloks/frontblok-auth';
//   export const authApi = createAuthApi(import.meta.env.VITE_API_URL);
//
//   // Then use directly:
//   authApi.login(email, password);
//   authApi.logout();
//   authApi.listApiKeys();

// Creates an auth API client instance.
// Preferred over class inheritance - simpler and cleaner.
// apiBaseUrl - The backend API base URL.
// Returns a BaseApi instance with all auth methods.
export function createAuthApi(apiBaseUrl: string): BaseApi {
  return new BaseApi(apiBaseUrl);
}

// ========================================================================
// STORAGE UTILITIES
// ========================================================================

export const getStoredUser = (): User | null => {
  const userData = localStorage.getItem('user_data');
  if (!userData) return null;
  
  try {
    return JSON.parse(userData);
  } catch (error) {
    console.error('[API] Invalid user_data in localStorage:', error);
    localStorage.removeItem('user_data');
    return null;
  }
};

export const getStoredToken = (): string | null => {
  return localStorage.getItem('auth_token');
};

export const isAuthenticated = (): boolean => {
  return !!getStoredToken();
};
