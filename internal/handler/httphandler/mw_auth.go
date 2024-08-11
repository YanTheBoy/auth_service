package httphandler

import (
	"authservice/internal/service"
	"errors"
	"net/http"
)

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {

		token := req.Header.Get(HeaderAuthorization)

		if len(token) == 0 {
			resp.WriteHeader(http.StatusUnauthorized)

			respBody := &HTTPResponse{}
			respBody.SetError(errors.New("token is missing"))
			resp.Write(respBody.Marshall())

			return
		}

		userID, err := service.GetUserIDByToken(token)

		if err != nil {
			resp.WriteHeader(http.StatusUnauthorized)

			respBody := &HTTPResponse{}
			respBody.SetError(errors.New("invalid token"))
			resp.Write(respBody.Marshall())

			return
		}

		if ok, _ := service.GetUserAccessRights(*userID); !ok {
			resp.WriteHeader(http.StatusForbidden)

			respBody := &HTTPResponse{}
			respBody.SetError(errors.New("sorry, you have been blocked"))
			resp.Write(respBody.Marshall())

			return
		}

		req.Header.Set(HeaderUserID, userID.Hex())

		next.ServeHTTP(resp, req)
	})

}
