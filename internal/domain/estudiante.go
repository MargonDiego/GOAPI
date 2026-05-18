package domain

import (
	"strconv"
	"strings"
)

// Estudiante es solo un dato del dominio de convivencia: NUNCA es un usuario
// (no autentica, no tiene login). Los campos Nombre y Rut son transitorios
// (texto plano en memoria); su cifrado/hash lo realiza la capa de aplicación
// antes de persistir, igual que el email de User.
type Estudiante struct {
	ID              uint
	Rut             string // transitorio: RUT normalizado en claro (no se persiste así)
	RutHash         string // HMAC-SHA256 — índice único, búsqueda
	RutEncrypted    string // AES-256-GCM — solo display
	Nombre          string // transitorio: nombre en claro
	NombreEncrypted string // AES-256-GCM — solo display
	Curso           string
	Scope           string
}

// NewEstudiante es la factory del dominio. Valida invariantes de creación.
// El RUT se valida y normaliza por separado vía ValidarRut en la capa de aplicación.
func NewEstudiante(nombre, curso, scope string) (*Estudiante, error) {
	nombre = strings.TrimSpace(nombre)
	curso = strings.TrimSpace(curso)
	if nombre == "" {
		return nil, ErrInvalidInput
	}
	if curso == "" {
		return nil, ErrInvalidInput
	}
	return &Estudiante{Nombre: nombre, Curso: curso, Scope: scope}, nil
}

// ValidarRut valida un RUT chileno con el algoritmo de módulo 11 y retorna
// el RUT normalizado en formato "cuerpo-DV" (DV en mayúscula).
// Retorna ErrRutInvalido si el formato o el dígito verificador son incorrectos.
func ValidarRut(rut string) (string, error) {
	var b strings.Builder
	for _, c := range strings.ToUpper(strings.TrimSpace(rut)) {
		if c != '.' && c != '-' && c != ' ' {
			b.WriteRune(c)
		}
	}
	clean := b.String()
	if len(clean) < 2 {
		return "", ErrRutInvalido
	}

	cuerpo := clean[:len(clean)-1]
	dv := clean[len(clean)-1:]

	for _, c := range cuerpo {
		if c < '0' || c > '9' {
			return "", ErrRutInvalido
		}
	}

	suma := 0
	factor := 2
	for i := len(cuerpo) - 1; i >= 0; i-- {
		suma += int(cuerpo[i]-'0') * factor
		factor++
		if factor > 7 {
			factor = 2
		}
	}

	resto := 11 - (suma % 11)
	var dvEsperado string
	switch resto {
	case 11:
		dvEsperado = "0"
	case 10:
		dvEsperado = "K"
	default:
		dvEsperado = strconv.Itoa(resto)
	}

	if dv != dvEsperado {
		return "", ErrRutInvalido
	}
	return cuerpo + "-" + dvEsperado, nil
}
