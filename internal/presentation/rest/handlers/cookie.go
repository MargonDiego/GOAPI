package handlers

import "net/http"

const accessTokenCookie = "access_token"

// setAccessTokenCookie establece el JWT como cookie HttpOnly.
// HttpOnly: invisible a JavaScript (previene robo por XSS).
// Secure: solo se envia por HTTPS (en produccion).
// SameSite=Strict: no se envia en requests cross-site (anti-CSRF).
// Path=/api: solo se envia a endpoints de la API.
// MaxAge=900: 15 minutos (mismo TTL que el JWT).
func setAccessTokenCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenCookie,
		Value:    token,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Path:     "/api",
		MaxAge:   900, // 15 minutos
	})
}

// clearAccessTokenCookie elimina la cookie de sesion (logout).
func clearAccessTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenCookie,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/api",
		MaxAge:   -1, // expirar inmediatamente
	})
}
