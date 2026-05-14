import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { type ReactNode } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginForm } from './pages/LoginForm';
import { RegisterForm } from './pages/RegisterForm';
import { DashboardPage } from './pages/DashboardPage';
import { ProfilePage } from './pages/ProfilePage';
import { LogOut, Home, User } from 'lucide-react';

function NavBar() {
  const { logout, user } = useAuth();

  return (
    <nav className="bg-neutral-900 border-b border-neutral-800">
      <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <a href="/dashboard" className="flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors">
            <Home size={20} />
            <span className="font-medium">Inicio</span>
          </a>
          <a href="/profile" className="flex items-center gap-2 text-neutral-400 hover:text-neutral-200 transition-colors">
            <User size={20} />
            <span>Perfil</span>
          </a>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-neutral-500 text-sm">@{user?.username}</span>
          <button
            onClick={logout}
            className="flex items-center gap-2 px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded-lg transition-colors"
          >
            <LogOut size={18} />
            <span>Salir</span>
          </button>
        </div>
      </div>
    </nav>
  );
}

function AuthLayout({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-neutral-950 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  return (
    <>
      <NavBar />
      <Routes>
        <Route path="/login" element={<AuthLayout><LoginForm /></AuthLayout>} />
        <Route path="/register" element={<AuthLayout><RegisterForm /></AuthLayout>} />
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        } />
        <Route path="/profile" element={
          <ProtectedRoute>
            <ProfilePage />
          </ProtectedRoute>
        } />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}