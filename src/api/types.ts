export interface AuthRequest {
  username: string;
  password: string;
  email?: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
}

export interface RefreshRequest {
  refresh_token: string;
}

export interface UserResponse {
  id: number;
  username: string;
  roles: RoleResponse[];
}

export interface RoleResponse {
  id: number;
  name: string;
  permissions: PermissionResponse[];
}

export interface PermissionResponse {
  id: number;
  name: string;
}

export interface MessageResponse {
  message: string;
}

export interface ErrorResponse {
  error: string;
}

export interface AssignRolesRequest {
  role_ids: number[];
}

export interface RoleCreateRequest {
  name: string;
}

export interface AssignPermissionsRequest {
  permission_ids: number[];
}

export interface JWTPayload {
  sub: string;
  exp: number;
  iat: number;
  permissions: string[];
}