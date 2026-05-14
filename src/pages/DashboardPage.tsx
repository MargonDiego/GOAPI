import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { userApi } from '../api/client';
import type { UserResponse } from '../api/types';
import { Users, Shield, Lock, Loader2, ChevronLeft, ChevronRight } from 'lucide-react';

export function DashboardPage() {
  const { user, hasPermission } = useAuth();
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    loadUsers();
  }, [page]);

  const loadUsers = async () => {
    setIsLoading(true);
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const data = await userApi.getAll(page, 10, token);
        setUsers(data);
        setTotalPages(Math.ceil(data.length / 10) || 1);
      }
    } catch (err) {
      console.error('Failed to load users:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 p-6">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-emerald-500/10 text-emerald-400 flex items-center justify-center rounded-xl">
              <Users size={24} />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Dashboard</h1>
              <p className="text-neutral-400">Bienvenido, @{user?.username}</p>
            </div>
          </div>
        </div>

        {hasPermission('read:users') && (
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <Shield size={20} className="text-blue-400" />
                Gestión de Usuarios
              </h2>
              {isLoading && <Loader2 size={20} className="animate-spin text-neutral-500" />}
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-neutral-800">
                    <th className="text-left py-3 px-4 text-neutral-500 font-medium text-sm">ID</th>
                    <th className="text-left py-3 px-4 text-neutral-500 font-medium text-sm">Usuario</th>
                    <th className="text-left py-3 px-4 text-neutral-500 font-medium text-sm">Roles</th>
                    <th className="text-left py-3 px-4 text-neutral-500 font-medium text-sm">Permisos</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} className="border-b border-neutral-800/50 hover:bg-neutral-800/30 transition-colors">
                      <td className="py-3 px-4 font-mono text-neutral-400">#{u.id}</td>
                      <td className="py-3 px-4">{u.username}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {u.roles.map((r) => (
                            <span key={r.id} className="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded text-xs">
                              {r.name}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {u.roles.flatMap((r) => r.permissions).slice(0, 3).map((p) => (
                            <span key={p.id} className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded text-xs font-mono">
                              {p.name}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between mt-4 pt-4 border-t border-neutral-800">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 bg-neutral-800 hover:bg-neutral-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                <ChevronLeft size={20} />
              </button>
              <p className="text-neutral-400 text-sm">
                Página {page} de {totalPages}
              </p>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= totalPages}
                className="p-2 bg-neutral-800 hover:bg-neutral-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                <ChevronRight size={20} />
              </button>
            </div>
          </div>
        )}

        {!hasPermission('read:users') && (
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-12 text-center shadow-xl">
            <div className="w-16 h-16 bg-yellow-500/10 text-yellow-400 flex items-center justify-center rounded-full mx-auto mb-4">
              <Lock size={32} />
            </div>
            <h2 className="text-xl font-bold mb-2">Acceso Restringido</h2>
            <p className="text-neutral-400">
              No tenés permisos para ver la lista de usuarios. Contactá a un administrador.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}