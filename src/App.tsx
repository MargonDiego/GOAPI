import { FileCode2, Download, Terminal, CheckCircle2 } from "lucide-react";

export default function App() {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-50 flex items-center justify-center p-6">
      <div className="max-w-2xl w-full bg-neutral-900 border border-neutral-800 rounded-2xl p-8 shadow-2xl">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-12 h-12 bg-blue-500/10 text-blue-400 flex items-center justify-center rounded-xl">
            <FileCode2 size={24} />
          </div>
          <div>
            <h1 className="text-2xl font-bold">API en Go Generada</h1>
            <p className="text-neutral-400">Autenticación, Usuarios, Roles y Permisos</p>
          </div>
        </div>

        <div className="space-y-6 text-neutral-300">
          <p>
            ¡Hola! He construido tu servidor API completo en <b>Golang (Go)</b> siguiendo tus requisitos. 
            Dado que este entorno de vista previa de Google AI Studio se ejecuta nativamente en Node.js de forma predeterminada, he creado el código fuente directamente en la carpeta <code>/go-api/</code> de tu espacio de trabajo para que lo exportes y lo ejecutes en tu máquina.
          </p>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-neutral-100 mb-3 uppercase tracking-wider flex items-center gap-2">
              <CheckCircle2 size={16} className="text-emerald-500"/> Características Incluidas
            </h3>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
              <li>• JWT Middleware & Auth</li>
              <li>• Modelos Usuarios, Roles, Permisos</li>
              <li>• RBAC Mapeo N:M Autorización</li>
              <li>• Integración Supabase (PostgreSQL)</li>
              <li>• Clean Architecture / DDD</li>
              <li>• Hash de contraseñas (Bcrypt)</li>
            </ul>
          </div>

          <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 text-blue-200">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              <Download size={18} /> ¿Cómo usar y ejecutar el código?
            </h3>
            <ol className="list-decimal ml-5 space-y-1 text-sm">
              <li>Haz clic en el engranaje superior derecho (Settings) y pulsa en <b>Export...</b>.</li>
              <li>Descarga el proyecto generado como un archivo ZIP.</li>
              <li>Descomprime en tu PC y entra a la carpeta <code>go-api/</code> por consola.</li>
            </ol>
          </div>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-neutral-100 mb-3 flex items-center gap-2">
              <Terminal size={18} /> Terminal:
            </h3>
            <pre className="text-xs text-neutral-400 bg-black p-3 rounded-lg overflow-x-auto leading-relaxed">
{`cd go-api
go mod tidy
go run cmd/api/main.go`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
