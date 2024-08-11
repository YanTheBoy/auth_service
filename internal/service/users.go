package service

import (
	"authservice/internal/domain"
	"github.com/sethvargo/go-password/password"
	"authservice/internal/repository/tokendb"
	"authservice/internal/repository/userdb"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

var users userdb.DB
var tokens tokendb.DB

func Init(userDB userdb.DB, tokenDB tokendb.DB) {
	users = userDB
	tokens = tokenDB
}

func SignUp(lp *domain.LoginPassword) (*domain.UserToken, error) {

	if _, ok := users.CheckExistLogin(lp.Login); ok {
		return nil, errors.New("login " + lp.Login + " already exists")
	}

	newUser := domain.User{
		ID:       primitive.NewObjectID(),
		Login:    lp.Login,
		Password: hash(lp.Password),
		Role:     domain.UserRoleDefault,
		Access: true,
	}

	if err := users.SetUser(&newUser); err != nil {
		return nil, err
	}

	token := createToken(lp.Login)

	if err := tokens.SetUserToken(token, newUser.ID); err != nil {
		return nil, err
	}

	return &domain.UserToken{
		UserId: newUser.ID,
		Token:  token,
	}, nil
}

func SignIn(lp *domain.LoginPassword) (*domain.UserToken, error) {

	userId, ok := users.CheckExistLogin(lp.Login)
	if !ok {
		return nil, errors.New("user not found")
	}

	user, err := users.GetUser(*userId)
	if err != nil {
		return nil, err
	}

	if !user.Access {
		return nil, errors.New("sorry, you have been blocked")
	}

	if user.Password != hash(lp.Password) {
		return nil, errors.New("wrong password")
	}



	token := createToken(lp.Login)

	if err := tokens.SetUserToken(token, *userId); err != nil {
		return nil, err
	}

	return &domain.UserToken{
		UserId: *userId,
		Token:  token,
	}, nil
}

func SetUserInfo(ui *domain.UserInfo) error {

	user, err := users.GetUser(ui.ID)
	if err != nil {
		return err
	}

	user.Role = ui.Role
	user.Access = ui.Access
	user.Name = ui.Name

	return users.SetUser(user)

}

func PatchRole(ur *domain.UserRole) error {
	user, err := users.GetUser(ur.ID)
	if err != nil {
		return err
	}
	user.Role = ur.Role
	return users.SetUser(user)

}

func ChangeAccess(ua *domain.UserAccess) error {
	user, err := users.GetUser(ua.ID)
	if err != nil {
		return err
	}
	if !user.Access {
		user.Access=true
	} else {
		user.Access = false
	}
	return users.SetUser(user)
}

func ChangePsw(up *domain.UserPassword) error {

	user, err := users.GetUser(up.ID)
	if err != nil {
		return err
	}

	user.Password = hash(up.Password)

	return users.SetUser(user)
}

func GetUserShortInfo(id primitive.ObjectID) (*domain.UserInfo, error) {

	user, err := users.GetUser(id)
	if err != nil {
		return nil, err
	}

	ui := domain.UserInfo{
		ID:   user.ID,
		Name: user.Name,
	}

	return &ui, nil
}

func GetUserFullInfo(id primitive.ObjectID) (*domain.User, error) {

	user, err := users.GetUser(id)
	return user, err
}

func GetUserIDByToken(token string) (*primitive.ObjectID, error) {
	return tokens.GetUserByToken(token)
}

func GetUserAccessRights(id primitive.ObjectID) (bool, error) {

	userAccess, err := users.GetUser(id)
	return userAccess.Access, err
}

func hash(str string) string {
	hp := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hp[:])
}

func createToken(login string) string {

	timeChs := md5.Sum([]byte(time.Now().String()))
	loginChs := md5.Sum([]byte(login))

	return hex.EncodeToString(timeChs[:]) + hex.EncodeToString(loginChs[:])
}

func CreateTempPsw(id primitive.ObjectID) (string, error) {
	tmpPsw, err := password.Generate(6, 4, 2, false, false)
	if err != nil {
		return "", err
	}
	if err = tokens.ClearTokens(id); err!=nil {
		return tmpPsw, err
	}
	return tmpPsw, err
}
