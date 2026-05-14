import { useAuth } from '../context/AuthContext';

export function useAuthHook() {
  return useAuth();
}

export function useRequireAuth() {
  const auth = useAuth();
  
  if (!auth.isAuthenticated && !auth.isLoading) {
    throw new Error('Unauthorized');
  }
  
  return auth;
}

export function useRequirePermission(permission: string) {
  const auth = useAuth();
  
  if (!auth.hasPermission(permission)) {
    throw new Error('Forbidden');
  }
  
  return auth;
}