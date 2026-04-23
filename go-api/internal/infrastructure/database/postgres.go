package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewPostgresDB(dsn string) (*gorm.DB, error) {
	// Configuramos Gorm para usar PostgreSQL (compatible con Supabase)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&User{}, &Role{}, &Permission{})
	if err != nil {
		return nil, err
	}

	seedDefaults(db)

	return db, nil
}

func seedDefaults(db *gorm.DB) {
	adminRole := Role{Name: "Admin"}
	db.FirstOrCreate(&adminRole, Role{Name: "Admin"})

	userRole := Role{Name: "User"}
	db.FirstOrCreate(&userRole, Role{Name: "User"})

	readPerm := Permission{Name: "read:users"}
	db.FirstOrCreate(&readPerm, Permission{Name: "read:users"})

	writePerm := Permission{Name: "write:users"}
	db.FirstOrCreate(&writePerm, Permission{Name: "write:users"})

	db.Model(&adminRole).Association("Permissions").Append(&readPerm, &writePerm)
	db.Model(&userRole).Association("Permissions").Append(&readPerm)
}
