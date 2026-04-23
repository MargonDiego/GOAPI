module github.com/diego/go-api

go 1.21

require (
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/gorilla/mux v1.8.1
	github.com/joho/godotenv v1.5.1 // Auto-loads .env files
	golang.org/x/crypto v0.19.0
	gorm.io/driver/postgres v1.5.7 // Using postgres for Supabase
	gorm.io/gorm v1.25.7
)
