package httphandler

type SetUserInfoReq struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Access bool   `json:"access"`
}

type ChangePswReq struct {
	Password string `json:"password"`
}

type ChangeRoleReq struct {
	Role string `json:"role"`
}

func (r ChangeRoleReq) IsValid() bool {
	return r.Role != ""
}

func (r SetUserInfoReq) IsValid() bool {
	return r.Name != ""
}

func (r ChangePswReq) IsValid() bool {
	return r.Password != ""
}
