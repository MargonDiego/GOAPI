package domain

import (
	"context"
	"io"
)

// FileMeta contiene los metadatos conocidos antes de almacenar un archivo.
type FileMeta struct {
	OriginalName string
	MimeType     string
}

// StoredFile es el resultado de guardar un archivo: nombre asignado, hash y tamaño reales.
type StoredFile struct {
	StoredName string
	SHA256     string
	SizeBytes  int64
}

// FileStorage es el puerto hexagonal para almacenamiento de adjuntos.
// La implementación concreta (LocalFileStorage) vive en infrastructure/storage/.
type FileStorage interface {
	Save(ctx context.Context, r io.Reader, meta FileMeta) (StoredFile, error)
	Open(ctx context.Context, storedName string) (io.ReadCloser, error)
	Delete(ctx context.Context, storedName string) error
}
