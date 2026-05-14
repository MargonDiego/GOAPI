import { type FormEvent, type ChangeEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { UserPlus, AlertCircle, CheckCircle2 } from 'lucide-react';

export function RegisterForm() {
  const navigate = useNavigate();
  const { register } = useAuth();
  const [formData, setFormData] = useState({ username: '', password: '', email: '' });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await register(formData.username, formData.password, formData.email);
      setSuccess(true);
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-neutral-900 border border-neutral-800 rounded-2xl p-8 shadow-2xl">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-12 h-12 bg-emerald-500/10 text-emerald-400 flex items-center justify-center rounded-xl">
            <UserPlus size={24} />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Crear Cuenta</h1>
            <p className="text-neutral-400">Registrate en la plataforma</p>
          </div>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-6 flex items-center gap-3">
            <AlertCircle size={20} className="text-red-400 flex-shrink-0" />
            <p className="text-red-200 text-sm">{error}</p>
          </div>
        )}

        {success && (
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-4 mb-6 flex items-center gap-3">
            <CheckCircle2 size={20} className="text-emerald-400 flex-shrink-0" />
            <p className="text-emerald-200 text-sm">¡Cuenta creada! Redirigiendo al login...</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-neutral-300 mb-2">
              Usuario
            </label>
            <input
              id="username"
              type="text"
              value={formData.username}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setFormData({ ...formData, username: e.target.value })}
              className="w-full px-4 py-3 bg-neutral-950 border border-neutral-700 rounded-xl text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
              placeholder="Elige tu usuario"
              required
              minLength={3}
              autoComplete="username"
            />
          </div>

          <div>
            <label htmlFor="email" className="block text-sm font-medium text-neutral-300 mb-2">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={formData.email}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setFormData({ ...formData, email: e.target.value })}
              className="w-full px-4 py-3 bg-neutral-950 border border-neutral-700 rounded-xl text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
              placeholder="tu@email.com"
              required
              autoComplete="email"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-neutral-300 mb-2">
              Contraseña
            </label>
            <input
              id="password"
              type="password"
              value={formData.password}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setFormData({ ...formData, password: e.target.value })}
              className="w-full px-4 py-3 bg-neutral-950 border border-neutral-700 rounded-xl text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
              placeholder="Mínimo 8 caracteres"
              required
              minLength={8}
              autoComplete="new-password"
            />
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-3 px-4 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-600/50 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              'Crear Cuenta'
            )}
          </button>
        </form>

        <p className="mt-6 text-center text-neutral-400 text-sm">
          ¿Ya tenés cuenta?{' '}
          <button
            onClick={() => navigate('/login')}
            className="text-emerald-400 hover:text-emerald-300 font-medium"
          >
            Iniciá sesión
          </button>
        </p>
      </div>
    </div>
  );
}