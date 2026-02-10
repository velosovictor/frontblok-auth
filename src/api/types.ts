// ========================================================================
// CORE API TYPES
// Universal types for authentication and API responses
// ========================================================================

// Authenticated user interface.
// Represents the user data returned from authentication endpoints.
export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  full_name: string;
  role: string;
  is_active: boolean;
  is_admin: boolean;
  created_at: string;
  last_login?: string;
  oauth_provider?: string | null;
  has_google_linked?: boolean;
}

// API Key interface for MCP servers and external integrations.
export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string;
  rate_limit_per_minute: number;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

// Response from creating a new API key.
// Includes the full key (only shown once).
export interface ApiKeyCreateResponse {
  api_key: string;  // Full key - only shown once!
  id: string;
  name: string;
  key_prefix: string;
  scopes: string;
  rate_limit_per_minute: number;
  expires_at: string | null;
  created_at: string;
  message: string;
}

// Login/Register response with tokens and user data.
export interface AuthResponse {
  access_token: string;
  refresh_token?: string;
  user: User;
}

// Google OAuth login response.
export interface GoogleOAuthResponse {
  message: string;
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  user: User;
  is_new_user: boolean;
  is_account_link?: boolean;
}

// Password reset request response.
export interface PasswordResetRequestResponse {
  message: string;
  dev_token?: string;  // Only in development mode
}

// Password reset response.
export interface PasswordResetResponse {
  message: string;
}

// Email verification response.
export interface EmailVerificationResponse {
  message: string;
  dev_token?: string;  // Only in development mode
}

// Set password response (for OAuth-only accounts).
export interface SetPasswordResponse {
  message: string;
}
