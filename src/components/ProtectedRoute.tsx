import { type ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

interface ProtectedRouteProps {
  children: ReactNode;
  permission?: string;
  redirectTo?: string;
}

export function ProtectedRoute({ children, permission, redirectTo = '/login' }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, hasPermission } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-neutral-950 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to={redirectTo} replace />;
  }

  if (permission && !hasPermission(permission)) {
    return (
      <div className="min-h-screen bg-neutral-950 flex items-center justify-center">
        <div className="bg-neutral-900 border border-red-500/20 rounded-2xl p-8 text-center">
          <h2 className="text-2xl font-bold text-red-400 mb-2">Acceso Denegado</h2>
          <p className="text-neutral-400">No tenés permiso para ver este contenido.</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}