package main

// go:generate es la herramienta nativa de Go para ejecutar comandos en tiempo de compilación.
// Al ejecutar `go generate ./...`, Go leerá esta línea e invocará a mockery.
// Mockery leerá la configuración de .mockery.yaml y autogenerará los mocks.

//go:generate go run github.com/vektra/mockery/v2@latest
