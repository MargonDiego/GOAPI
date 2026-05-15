# Script de cobertura para Windows (PowerShell)
# Uso: .\scripts\coverage.ps1

Write-Host "Calculando cobertura de código..." -ForegroundColor Cyan
go test -coverprofile=coverage.out ./...

Write-Host "Abriendo reporte HTML en el navegador..." -ForegroundColor Green
go tool cover -html=coverage.out
