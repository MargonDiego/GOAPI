import type {
  AuthRequest,
  AuthResponse,
  RefreshRequest,
  UserResponse,
  RoleResponse,
  PermissionResponse,
  MessageResponse,
  ErrorResponse,
  AssignRolesRequest,
  RoleCreateRequest,
  AssignPermissionsRequest,
  JWTPayload,
} from './types';

const API_BASE = import.meta.env.VITE_API_URL || '';

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public isUnauthorized = false,
    public isForbidden = false
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function decodeJWT(token: string): JWTPayload | null {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

function isTokenExpired(token: string): boolean {
  const payload = decodeJWT(token);
  if (!payload) return true;
  return Date.now() / 1000 > payload.exp;
}

let refreshPromise: Promise<AuthResponse | null> | null = null;

async function refreshAccessToken(refreshToken: string): Promise<AuthResponse | null> {
  if (refreshPromise) return refreshPromise;
  
  refreshPromise = fetch(`${API_BASE}/api/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  })
    .then(async (res) => {
      if (!res.ok) {
        if (res.status === 401) return null;
        throw new ApiError(res.status, 'Refresh failed');
      }
      return res.json() as Promise<AuthResponse>;
    })
    .finally(() => {
      refreshPromise = null;
    });
  
  return refreshPromise;
}

export const api = {
  async auth<T>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
    
    if (!res.ok) {
      const error = (await res.json().catch(() => ({ error: 'Request failed' }))) as ErrorResponse;
      throw new ApiError(res.status, error.error);
    }
    
    return res.json() as Promise<T>;
  },

  async protected<T>(
    path: string,
    options: RequestInit = {},
    accessToken?: string
  ): Promise<T> {
    const token = accessToken || localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');
    
    if (!token) throw new ApiError(401, 'No token', true);
    
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        ...options.headers,
      },
    });
    
    if (res.status === 401 && refreshToken && !isTokenExpired(refreshToken)) {
      const newTokens = await refreshAccessToken(refreshToken);
      if (newTokens) {
        localStorage.setItem('access_token', newTokens.access_token);
        localStorage.setItem('refresh_token', newTokens.refresh_token);
        window.dispatchEvent(new CustomEvent('token_refreshed', { detail: newTokens }));
        
        const retryRes = await fetch(`${API_BASE}${path}`, {
          ...options,
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${newTokens.access_token}`,
            ...options.headers,
          },
        });
        
        if (!retryRes.ok) {
          const error = (await retryRes.json().catch(() => ({ error: 'Request failed' }))) as ErrorResponse;
          throw new ApiError(retryRes.status, error.error, retryRes.status === 401, retryRes.status === 403);
        }
        
        return retryRes.json() as Promise<T>;
      }
    }
    
    if (!res.ok) {
      const error = (await res.json().catch(() => ({ error: 'Request failed' }))) as ErrorResponse;
      throw new ApiError(res.status, error.error, res.status === 401, res.status === 403);
    }
    
    return res.json() as Promise<T>;
  },

  getPermissions(token?: string): string[] {
    const t = token || localStorage.getItem('access_token');
    if (!t) return [];
    const payload = decodeJWT(t);
    return payload?.permissions || [];
  },

  hasPermission(permission: string, token?: string): boolean {
    return this.getPermissions(token).includes(permission);
  },
};

export const authApi = {
  register: (data: AuthRequest) =>
    api.auth<MessageResponse>('/api/register', { method: 'POST', body: JSON.stringify(data) }),

  login: (data: AuthRequest) =>
    api.auth<AuthResponse>('/api/login', { method: 'POST', body: JSON.stringify(data) }),

  refresh: (refreshToken: string) =>
    api.auth<AuthResponse>('/api/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    }),
};

export const userApi = {
  getMe: (token?: string) => api.protected<UserResponse>('/api/me', {}, token),
  getAll: (page = 1, size = 10, token?: string) =>
    api.protected<UserResponse[]>(`/api/users?page=${page}&size=${size}`, {}, token),
  assignRoles: (userId: number, data: AssignRolesRequest, token?: string) =>
    api.protected<MessageResponse>(`/api/users/${userId}/roles`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }, token),
};

export const roleApi = {
  getAll: (token?: string) => api.protected<RoleResponse[]>('/api/roles', {}, token),
  create: (data: RoleCreateRequest, token?: string) =>
    api.protected<RoleResponse>('/api/roles', { method: 'POST', body: JSON.stringify(data) }, token),
  assignPermissions: (roleId: number, data: AssignPermissionsRequest, token?: string) =>
    api.protected<MessageResponse>(`/api/roles/${roleId}/permissions`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }, token),
  getPermissions: (token?: string) => api.protected<PermissionResponse[]>('/api/permissions', {}, token),
};

export { ApiError, decodeJWT, isTokenExpired };