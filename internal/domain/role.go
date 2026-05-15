package domain

// --- Entidades de AutorizaciÃ³n (Role y Permission) ---

// Permission representa un permiso atÃ³mico del sistema (ej: "read:users", "manage:roles").
type Permission struct {
	ID          uint
	Name        string
	Description string
}

// Role agrupa permisos. Un usuario puede tener mÃºltiples roles.
// IsSystem = true indica roles crÃ­ticos que NO se pueden eliminar (ej: Admin, User).
// Scope restringe la visibilidad y gestiÃ³n del rol a administradores de ese dominio.
type Role struct {
	ID          uint
	Name        string
	Description string
	IsSystem    bool
	Scope       string
	Permissions []Permission
}
