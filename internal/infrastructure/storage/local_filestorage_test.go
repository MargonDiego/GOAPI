package storage_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalFileStorage_SaveAndOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fs, err := storage.NewLocalFileStorage(dir)
	require.NoError(t, err)

	ctx := context.Background()
	content := []byte("contenido del adjunto de prueba")
	meta := domain.FileMeta{OriginalName: "prueba.pdf", MimeType: "application/pdf"}

	stored, err := fs.Save(ctx, bytes.NewReader(content), meta)
	require.NoError(t, err)
	assert.NotEmpty(t, stored.StoredName)
	assert.NotEmpty(t, stored.SHA256)
	assert.Equal(t, int64(len(content)), stored.SizeBytes)

	rc, err := fs.Open(ctx, stored.StoredName)
	require.NoError(t, err)
	defer rc.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rc)
	require.NoError(t, err)
	assert.Equal(t, content, buf.Bytes())
}

func TestLocalFileStorage_Delete(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fs, err := storage.NewLocalFileStorage(dir)
	require.NoError(t, err)

	ctx := context.Background()
	stored, err := fs.Save(ctx, bytes.NewReader([]byte("data")), domain.FileMeta{OriginalName: "f.txt"})
	require.NoError(t, err)

	require.NoError(t, fs.Delete(ctx, stored.StoredName))

	_, err = fs.Open(ctx, stored.StoredName)
	assert.Error(t, err)
}

func TestLocalFileStorage_Open_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fs, err := storage.NewLocalFileStorage(dir)
	require.NoError(t, err)

	_, err = fs.Open(context.Background(), "no-existe.pdf")
	assert.Error(t, err)
}

func TestNewLocalFileStorage_DirNoExiste(t *testing.T) {
	t.Parallel()
	_, err := storage.NewLocalFileStorage("/ruta/que/no/existe/jamas")
	assert.Error(t, err)
}
