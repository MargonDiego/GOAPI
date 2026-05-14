package domain

// PaginatedResult encapsula datos paginados con metadatos de paginación.
type PaginatedResult[T any] struct {
	Data       []T `json:"data"`
	Page       int `json:"page"`
	Size       int `json:"size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// NewPaginatedResult construye un resultado paginado calculando total_pages.
func NewPaginatedResult[T any](data []T, page, size, total int) PaginatedResult[T] {
	if size <= 0 {
		size = 10
	}
	tp := total / size
	if total%size > 0 {
		tp++
	}
	return PaginatedResult[T]{
		Data:       data,
		Page:       page,
		Size:       size,
		Total:      total,
		TotalPages: tp,
	}
}
