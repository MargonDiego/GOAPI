// Package storage implementa el puerto domain.FileStorage sobre el sistema de archivos local.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/google/uuid"
)

// LocalFileStorage guarda adjuntos en un directorio local con nombre UUID.
// Implementa domain.FileStorage.
type LocalFileStorage struct {
	dir string
}

// NewLocalFileStorage valida que el directorio exista y sea escribible.
func NewLocalFileStorage(dir string) (*LocalFileStorage, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("storage dir unavailable: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("storage path is not a directory: %s", dir)
	}
	return &LocalFileStorage{dir: dir}, nil
}

// Save lee el reader, calcula SHA-256, y guarda en dir/<uuid>.
// El StoredName devuelto es el UUID generado (sin extensión).
func (s *LocalFileStorage) Save(_ context.Context, r io.Reader, _ domain.FileMeta) (domain.StoredFile, error) {
	storedName := uuid.NewString()
	dst := filepath.Join(s.dir, storedName)

	f, err := os.Create(dst)
	if err != nil {
		return domain.StoredFile{}, fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	mw := io.MultiWriter(f, h)

	n, err := io.Copy(mw, r)
	if err != nil {
		os.Remove(dst)
		return domain.StoredFile{}, fmt.Errorf("write file: %w", err)
	}

	return domain.StoredFile{
		StoredName: storedName,
		SHA256:     hex.EncodeToString(h.Sum(nil)),
		SizeBytes:  n,
	}, nil
}

// Open devuelve un ReadCloser del archivo almacenado.
func (s *LocalFileStorage) Open(_ context.Context, storedName string) (io.ReadCloser, error) {
	f, err := os.Open(filepath.Join(s.dir, storedName))
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", storedName, err)
	}
	return f, nil
}

// Delete elimina el archivo del disco.
func (s *LocalFileStorage) Delete(_ context.Context, storedName string) error {
	if err := os.Remove(filepath.Join(s.dir, storedName)); err != nil {
		return fmt.Errorf("delete file %s: %w", storedName, err)
	}
	return nil
}
