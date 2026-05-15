// Package crypto provee utilidades de cifrado para proteger PII (Personal Identifiable Information).
//
// Estrategia de doble representación para campos buscables:
//   - EmailEncrypted: AES-256-GCM con IV aleatorio → para mostrar al usuario.
//   - EmailHash: HMAC-SHA256 determinista → para buscar en la BD con O(log n).
//
// Esta separación resuelve el problema fundamental del cifrado simétrico:
// si usamos un IV aleatorio, dos cifrados del mismo email dan resultados diferentes,
// imposibilitando el WHERE email = ?, pero si usamos IV fijo, perdemos el nonce y
// el cifrado es determinista (vulnerable a análisis de frecuencia).
//
// La solución: cifrar para confidencialidad (IV aleatorio) y hashear para búsqueda (HMAC).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var ErrInvalidKey = errors.New("encryption key must be exactly 32 bytes (AES-256)")

// Encryptor maneja cifrado AES-256-GCM y hashing HMAC-SHA256 de PII.
// Debe ser instanciado una sola vez y compartido (thread-safe).
type Encryptor struct {
	key []byte // 32 bytes = AES-256
}

// NewEncryptor valida y crea un Encryptor desde la clave de entorno.
// Falla rápido en startup si la clave no tiene el tamaño correcto.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(key))
	}
	return &Encryptor{key: key}, nil
}

// EncryptEmail cifra el email con AES-256-GCM usando un nonce aleatorio.
// El resultado es: base64(nonce || ciphertext || tag) — todo en un solo campo.
// Cada llamada produce un resultado DIFERENTE aunque el email sea el mismo.
func (e *Encryptor) EncryptEmail(email string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("aes cipher init: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes-gcm init: %w", err)
	}

	// Nonce aleatorio de 12 bytes (estándar GCM).
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}

	// Seal: nonce || ciphertext || tag (autenticado).
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(email), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptEmail descifra el email cifrado por EncryptEmail.
// Retorna error si el ciphertext fue modificado (autenticidad garantizada por GCM).
func (e *Encryptor) DecryptEmail(encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("aes cipher init: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes-gcm init: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// No exponer el error interno: puede informar sobre el IV
		return "", errors.New("decryption failed: invalid ciphertext or tampered data")
	}

	return string(plaintext), nil
}

// HashEmail genera un HMAC-SHA256 del email usando la misma clave del encryptor.
// El resultado es DETERMINISTA: el mismo email siempre da el mismo hash.
// Se usa como índice único en la BD para hacer WHERE email_hash = ? de forma segura.
//
// Importante: NO se debe usar SHA256 sin clave (vulnerable a rainbow tables).
// HMAC agrega la clave como secreto, haciendo que la tabla de hashes sea inútil
// sin conocer la clave de la aplicación.
func (e *Encryptor) HashEmail(email string) string {
	mac := hmac.New(sha256.New, e.key)
	mac.Write([]byte(email))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
