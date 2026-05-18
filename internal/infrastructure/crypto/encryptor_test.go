package crypto_test

import (
	"testing"

	appcrypto "github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
	"github.com/stretchr/testify/assert"
)

func newEnc(t *testing.T) *appcrypto.Encryptor {
	t.Helper()
	enc, err := appcrypto.NewEncryptor([]byte("12345678901234567890123456789012"))
	assert.NoError(t, err)
	return enc
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	plain := "12345678-5"
	ct, err := enc.Encrypt(plain)
	assert.NoError(t, err)
	assert.NotEqual(t, plain, ct)
	got, err := enc.Decrypt(ct)
	assert.NoError(t, err)
	assert.Equal(t, plain, got)
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	a, _ := enc.Encrypt("nombre")
	b, _ := enc.Encrypt("nombre")
	assert.NotEqual(t, a, b)
}

func TestHashIsDeterministic(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	assert.Equal(t, enc.Hash("12345678-5"), enc.Hash("12345678-5"))
	assert.NotEqual(t, enc.Hash("a"), enc.Hash("b"))
}

func TestEmailMethodsStillWork(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	ct, err := enc.EncryptEmail("user@example.com")
	assert.NoError(t, err)
	got, err := enc.DecryptEmail(ct)
	assert.NoError(t, err)
	assert.Equal(t, "user@example.com", got)
	assert.NotEmpty(t, enc.HashEmail("user@example.com"))
}
