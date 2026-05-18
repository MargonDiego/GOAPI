// Package crypto provee utilidades de cifrado para proteger PII (Personal Identifiable Information).
//
// Estrategia de doble representacion para campos buscables:
//   - EmailEncrypted: AES-256-GCM con IV aleatorio -> para mostrar al usuario.
//   - EmailHash: HMAC-SHA256 determinista -> para buscar en la BD con O(log n).
//
// Esta separacion resuelve el problema fundamental del cifrado simetrico:
// si usamos un IV aleatorio, dos cifrados del mismo email dan resultados diferentes,
// imposibilitando el WHERE email = ?, pero si usamos IV fijo, perdemos el nonce y
// el cifrado es determinista (vulnerable a analisis de frecuencia).
//
// La solucion: cifrar para confidencialidad (IV aleatorio) y hashear para busqueda (HMAC).
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
// Falla rapido en startup si la clave no tiene el tamano correcto.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(key))
	}
	return &Encryptor{key: key}, nil
}

// Encrypt cifra cualquier string con AES-256-GCM y nonce aleatorio.
// Resultado: base64(nonce || ciphertext || tag). No determinista.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("aes cipher init: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes-gcm init: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt descifra un valor producido por Encrypt.
func (e *Encryptor) Decrypt(encrypted string) (string, error) {
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
		return "", errors.New("decryption failed: invalid ciphertext or tampered data")
	}
	return string(plaintext), nil
}

// Hash genera un HMAC-SHA256 determinista de cualquier valor.
func (e *Encryptor) Hash(value string) string {
	mac := hmac.New(sha256.New, e.key)
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// EncryptEmail cifra el email. Delega en Encrypt (mantiene la API existente).
func (e *Encryptor) EncryptEmail(email string) (string, error) {
	return e.Encrypt(email)
}

// DecryptEmail descifra el email. Delega en Decrypt.
func (e *Encryptor) DecryptEmail(encrypted string) (string, error) {
	return e.Decrypt(encrypted)
}

// HashEmail genera el HMAC-SHA256 del email. Delega en Hash.
func (e *Encryptor) HashEmail(email string) string {
	return e.Hash(email)
}
