import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { userApi, roleApi, ApiError } from '../api/client';
import type { UserResponse, RoleResponse } from '../api/types';
import { User, Shield, Loader2 } from 'lucide-react';

export function ProfilePage() {
  const { user, permissions } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [roles, setRoles] = useState<RoleResponse[]>([]);
  const [isLoadingRoles, setIsLoadingRoles] = useState(true);

  useEffect(() => {
    loadRoles();
  }, []);

  const loadRoles = async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const data = await roleApi.getAll(token);
        setRoles(data);
      }
    } catch (err) {
      console.error('Failed to load roles:', err);
    } finally {
      setIsLoadingRoles(false);
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 p-6">
      <div className="max-w-2xl mx-auto">
        <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-8 shadow-2xl">
          <div className="flex items-center gap-4 mb-8">
            <div className="w-16 h-16 bg-blue-500/10 text-blue-400 flex items-center justify-center rounded-2xl">
              <User size={32} />
            </div>
            <div>
              <h1 className="text-3xl font-bold">Mi Perfil</h1>
              <p className="text-neutral-400">@{user?.username}</p>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Shield size={20} className="text-blue-400" />
                Información de Cuenta
              </h2>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-neutral-500 text-sm">ID de Usuario</p>
                  <p className="text-neutral-100 font-mono">#{user?.id}</p>
                </div>
                <div>
                  <p className="text-neutral-500 text-sm">Roles Asignados</p>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {user?.roles.map((role) => (
                      <span
                        key={role.id}
                        className="px-2 py-1 bg-blue-500/10 text-blue-400 rounded-lg text-sm"
                      >
                        {role.name}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
              <h2 className="text-lg font-semibold mb-4">Permisos del Sistema</h2>
              {isLoadingRoles ? (
                <div className="flex items-center justify-center py-4">
                  <Loader2 size={20} className="animate-spin text-neutral-500" />
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {permissions.length > 0 ? (
                    permissions.map((perm) => (
                      <span
                        key={perm}
                        className="px-3 py-1.5 bg-emerald-500/10 text-emerald-400 rounded-lg text-sm font-mono"
                      >
                        {perm}
                      </span>
                    ))
                  ) : (
                    <p className="text-neutral-500 text-sm">Sin permisos específicos</p>
                  )}
                </div>
              )}
            </div>

            <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
              <h2 className="text-lg font-semibold mb-4">Roles Disponibles</h2>
              {isLoadingRoles ? (
                <div className="flex items-center justify-center py-4">
                  <Loader2 size={20} className="animate-spin text-neutral-500" />
                </div>
              ) : (
                <div className="space-y-3">
                  {roles.map((role) => (
                    <div
                      key={role.id}
                      className="flex items-center justify-between p-3 bg-neutral-900 rounded-lg"
                    >
                      <div>
                        <p className="font-medium">{role.name}</p>
                        <p className="text-sm text-neutral-500">
                          {role.permissions.length} permisos
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {role.permissions.slice(0, 3).map((p) => (
                          <span
                            key={p.id}
                            className="px-2 py-0.5 bg-neutral-800 text-neutral-400 rounded text-xs font-mono"
                          >
                            {p.name}
                          </span>
                        ))}
                        {role.permissions.length > 3 && (
                          <span className="px-2 py-0.5 text-neutral-500 text-xs">
                            +{role.permissions.length - 3}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}