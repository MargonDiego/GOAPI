package domain

// --- Entidades de Autorización (Role y Permission) ---

// Permission representa un permiso atómico del sistema (ej: "read:users", "manage:roles").
type Permission struct {
	ID   uint
	Name string
}

// Role agrupa permisos. Un usuario puede tener múltiples roles.
type Role struct {
	ID          uint
	Name        string
	Permissions []Permission
}
