import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react';
import type { UserResponse } from '../api/types';
import { authApi, userApi, ApiError } from '../api/client';

interface AuthState {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  permissions: string[];
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string, email: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const STORAGE_KEYS = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
} as const;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    permissions: [],
  });

  const clearAuth = useCallback(() => {
    localStorage.removeItem(STORAGE_KEYS.ACCESS_TOKEN);
    localStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
    setState({ user: null, isAuthenticated: false, isLoading: false, permissions: [] });
  }, []);

  const loadUser = useCallback(async (accessToken?: string) => {
    try {
      const token = accessToken || localStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN);
      if (!token) {
        setState((s) => ({ ...s, isLoading: false }));
        return;
      }

      const user = await userApi.getMe(token);
      const payload = decodeTokenPayload(token);
      
      setState({
        user,
        isAuthenticated: true,
        isLoading: false,
        permissions: payload?.permissions || [],
      });
    } catch (err) {
      if (err instanceof ApiError && err.isUnauthorized) {
        clearAuth();
      } else {
        setState((s) => ({ ...s, isLoading: false }));
      }
    }
  }, [clearAuth]);

  const checkAuth = useCallback(async () => {
    setState((s) => ({ ...s, isLoading: true }));
    await loadUser();
  }, [loadUser]);

  const login = useCallback(async (username: string, password: string) => {
    const response = await authApi.login({ username, password });
    localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, response.access_token);
    localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, response.refresh_token);
    await loadUser(response.access_token);
  }, [loadUser]);

  const register = useCallback(async (username: string, password: string, email: string) => {
    await authApi.register({ username, password, email });
  }, []);

  const logout = useCallback(() => {
    clearAuth();
  }, [clearAuth]);

  const hasPermission = useCallback((permission: string) => {
    return state.permissions.includes(permission);
  }, [state.permissions]);

  useEffect(() => {
    const handleTokenRefresh = (event: CustomEvent) => {
      const newToken = event.detail.access_token;
      setState((s) => ({ ...s, permissions: getPermissionsFromToken(newToken) }));
    };

    window.addEventListener('token_refreshed', handleTokenRefresh as EventListener);
    loadUser();

    return () => {
      window.removeEventListener('token_refreshed', handleTokenRefresh as EventListener);
    };
  }, [loadUser]);

  return (
    <AuthContext.Provider value={{ ...state, login, register, logout, checkAuth, hasPermission }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

function decodeTokenPayload(token: string) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload) as { permissions: string[] };
  } catch {
    return null;
  }
}

function getPermissionsFromToken(token: string): string[] {
  const payload = decodeTokenPayload(token);
  return payload?.permissions || [];
}