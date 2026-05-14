package domain

// --- Entidades de Autorización (Role y Permission) ---

// Permission representa un permiso atómico del sistema (ej: "read:users", "manage:roles").
type Permission struct {
	ID          uint
	Name        string
	Description string
}

// Role agrupa permisos. Un usuario puede tener múltiples roles.
// IsSystem = true indica roles críticos que NO se pueden eliminar (ej: Admin, User).
// Scope restringe la visibilidad y gestión del rol a administradores de ese dominio.
type Role struct {
	ID          uint
	Name        string
	Description string
	IsSystem    bool
	Scope       string
	Permissions []Permission
}
