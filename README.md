# @rationalbloks/frontblok-auth

**Universal Frontend Authentication for RationalBloks Apps**

Pure authentication, API, and token management. **NO STYLING** - each template app provides its own aesthetics.

---

## 🎯 Philosophy

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FRONTBLOK-AUTH (npm package)                    │
│                                                                     │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────────────────┐   │
│  │   AUTH    │  │    API    │  │        PROVIDERS             │   │
│  │           │  │           │  │                              │   │
│  │ • Tokens  │  │ • BaseApi │  │ • createAppRoot              │   │
│  │ • Storage │  │ • Client  │  │ • createAuthProvider         │   │
│  │ • Context │  │ • Types   │  │ • useAuth                    │   │
│  └───────────┘  └───────────┘  └──────────────────────────────┘   │
│                                                                     │
│                          ↓  NO STYLING  ↓                          │
└─────────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  Template #1  │   │  Template #2  │   │  Template #3  │
│ (rationalbloks│   │ (Investment   │   │ (E-commerce   │
│    front)     │   │   Portfolio)  │   │   Template)   │
│               │   │               │   │               │
│ ✓ Own theme   │   │ ✓ Own theme   │   │ ✓ Own theme   │
│ ✓ Own styles  │   │ ✓ Own styles  │   │ ✓ Own styles  │
│ ✓ Own Navbar  │   │ ✓ Own Navbar  │   │ ✓ Own Navbar  │
└───────────────┘   └───────────────┘   └───────────────┘
```

---

## 📦 Installation

### For Published Package (Production)
```bash
npm install @rationalbloks/frontblok-auth
```

### For Local Development (npm link)
```bash
# In frontblok-auth directory
cd frontblok-auth
npm install
npm run build
npm link

# In your app directory
cd your-app
npm link @rationalbloks/frontblok-auth
```

---

## 🚀 Usage

### 1. Bootstrap Your App

```tsx
// main.tsx
import { createAppRoot } from '@rationalbloks/frontblok-auth';
import './styles/globals.css';  // YOUR app's styling
import App from './App';

createAppRoot(App, {
  googleClientId: import.meta.env.VITE_GOOGLE_CLIENT_ID || '',
});
```

### 2. Create Your Auth Provider

```tsx
// contexts/ClientAuthContext.tsx
import { createAuthProvider, useAuth } from '@rationalbloks/frontblok-auth';
import { myApi } from '../services/myApi';

export const ClientAuthProvider = createAuthProvider(myApi);
export const useClientAuth = useAuth;
```

### 3. Extend BaseApi for Your App

```tsx
// services/myApi.ts
import { BaseApi, getStoredUser, getStoredToken, isAuthenticated } from '@rationalbloks/frontblok-auth';
import type { User } from '@rationalbloks/frontblok-auth';

// Re-export utilities
export { getStoredUser, getStoredToken, isAuthenticated };
export type { User };

// Your custom endpoints
class MyAppApi extends BaseApi {
  async getProjects() {
    return this.get<Project[]>('/projects');
  }
  
  async createProject(data: CreateProjectDTO) {
    return this.post<Project>('/projects', data);
  }
}

export const myApi = new MyAppApi({
  baseURL: import.meta.env.VITE_API_URL,
});
```

---

## 📚 API Reference

### Auth Exports

| Export | Description |
|--------|-------------|
| `createAppRoot(App, config)` | Bootstrap app with Google OAuth provider |
| `createAuthProvider(api)` | Create auth context provider for your API |
| `useAuth()` | Hook to access auth state and actions |

### API Exports

| Export | Description |
|--------|-------------|
| `BaseApi` | Extensible API client with token management |
| `createAuthApi(baseUrl)` | Create pre-configured auth API instance |
| `getStoredUser()` | Get user from localStorage |
| `getStoredToken()` | Get token from localStorage |
| `isAuthenticated()` | Check if user is logged in |

### OAuth Utilities

| Export | Description |
|--------|-------------|
| `generateOAuthNonce()` | Generate CSRF nonce for Google OAuth |
| `getOAuthNonce()` | Retrieve stored OAuth nonce |
| `clearOAuthNonce()` | Clear stored nonce after login |

### BaseApi Methods

#### Core Authentication
| Method | Description |
|--------|-------------|
| `login(email, password)` | Email/password login |
| `register(email, password, firstName, lastName)` | Register new account |
| `logout()` | Logout current session |
| `logoutAllDevices()` | Revoke all sessions |
| `getCurrentUser()` | Get authenticated user info |
| `deleteAccount(password, confirmText)` | Delete account permanently |

#### Google OAuth (v0.2.0+)
| Method | Description |
|--------|-------------|
| `googleOAuthLogin(credential, nonce)` | Login with Google OAuth |

#### Password Reset (v0.2.0+)
| Method | Description |
|--------|-------------|
| `requestPasswordReset(email)` | Send password reset email |
| `resetPassword(token, newPassword)` | Reset password with token |

#### Email Verification (v0.2.0+)
| Method | Description |
|--------|-------------|
| `verifyEmail(token)` | Verify email with token |
| `requestVerificationEmail(email)` | Resend verification email |
| `setPassword(newPassword)` | Set password for OAuth accounts |

#### API Key Management
| Method | Description |
|--------|-------------|
| `listApiKeys()` | List user's API keys |
| `createApiKey(data)` | Create new API key |
| `revokeApiKey(keyId)` | Revoke an API key |

---

## 🔐 Google OAuth Example

```tsx
import { GoogleLogin } from '@react-oauth/google';
import { generateOAuthNonce, getOAuthNonce, createAuthApi } from '@rationalbloks/frontblok-auth';

const authApi = createAuthApi(import.meta.env.VITE_API_URL);

function LoginPage() {
  // Generate nonce before rendering GoogleLogin
  const nonce = generateOAuthNonce();

  return (
    <GoogleLogin
      nonce={nonce}
      onSuccess={async (response) => {
        const result = await authApi.googleOAuthLogin(
          response.credential!,
          getOAuthNonce()!
        );
        console.log('Logged in:', result.user);
      }}
    />
  );
}
```

---

## 🔧 Development

```bash
# Install dependencies
npm install

# Type check
npm run typecheck

# Build library
npm run build

# Outputs:
#   dist/index.js     - ESM bundle
#   dist/index.cjs    - CommonJS bundle  
#   dist/index.d.ts   - TypeScript declarations
```

---

## 📋 Peer Dependencies

This package requires these dependencies in your app:

```json
{
  "react": "^18.0.0 || ^19.0.0",
  "react-dom": "^18.0.0 || ^19.0.0",
  "react-router-dom": "^6.0.0 || ^7.0.0",
  "@react-oauth/google": "^0.12.0"
}
```

---

## 🏗️ Architecture for New Template Apps

When creating a new template app that uses frontblok-auth:

1. **Install the package**
   ```bash
   npm install @rationalbloks/frontblok-auth
   ```

2. **Create your own styling** (theme/, styles/)
3. **Create your own components** (style them yourself)
4. **Create your own API service** (extend BaseApi)
5. **Use createAuthProvider** with your API
6. **Bootstrap with createAppRoot**

---

## 📝 License

MIT © RationalBloks Team
