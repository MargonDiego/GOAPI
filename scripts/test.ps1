# Script de testing para Windows (PowerShell)
# Uso: .\scripts\test.ps1

Write-Host "Ejecutando suite de pruebas..." -ForegroundColor Cyan
go test -v ./...
