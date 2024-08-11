package httphandler

import (
	"log"
	"net/http"
)

func LogUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {

		log.Println("Request received:", req.Method, req.URL.Path, req.RemoteAddr, req.UserAgent(),
			"userID:", req.Header.Get(HeaderUserID))
		next.ServeHTTP(resp, req)

	})
}
