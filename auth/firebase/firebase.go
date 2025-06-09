package firebase

import (
	"context"
	"log"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

// User domain model
type User struct {
	UID            string                 `bson:"uid,omitempty" json:"uid,omitempty"`
	Email          string                 `bson:"email,omitempty" json:"email,omitempty"`
	EmailVerified  bool                   `bson:"email_verified,omitempty" json:"email_verified,omitempty"`
	PhoneNumber    string                 `bson:"phone_number,omitempty" json:"phone_number,omitempty"`
	DisplayName    string                 `bson:"display_name,omitempty" json:"display_name,omitempty"`
	PhotoURL       string                 `bson:"photo_url,omitempty" json:"photo_url,omitempty"`
	Disabled       bool                   `bson:"disabled,omitempty" json:"disabled,omitempty"`
	Password       string                 `json:"password,omitempty"`
	CustomClaims   map[string]interface{} `json:"custom_claims,omitempty"`
	WhatsAppNumber string                 `bson:"whatsapp_number,omitempty" json:"whatsapp,omitempty"`
}

// Client ...
type Client struct {
	*auth.Client
}

type Token struct {
	*auth.Token
}

func Connect(ctx context.Context, serviceAccount string) (*Client, error) {
	opt := option.WithCredentialsFile(serviceAccount)
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		log.Fatalf("error connecting firebase: %v\n", err)
	}
	client := new(Client)
	auth, err := app.Auth(ctx)
	client.Client = auth

	return client, err
}

func (client *Client) GetByEmail(ctx context.Context, email string) (*auth.UserRecord, error) {
	u, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (client *Client) GetByPhone(ctx context.Context, phone string) (*auth.UserRecord, error) {
	u, err := client.GetUserByPhoneNumber(ctx, phone)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (client *Client) Create(ctx context.Context, user User) (*auth.UserRecord, error) {
	params := (&auth.UserToCreate{})

	if user.Email != "" {
		params = params.Email(user.Email)
	}
	if user.PhoneNumber != "" {
		params = params.PhoneNumber(user.PhoneNumber)
	}
	if user.DisplayName != "" {
		params = params.DisplayName(user.DisplayName)
	}
	if user.PhotoURL != "" {
		params = params.PhotoURL(user.PhotoURL)
	}
	if user.Password != "" {
		params = params.Password(user.Password)
	}

	u, err := client.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}
	err = client.SetUserCustomClaims(ctx, u.UID, user.CustomClaims)

	return u, err
}

func (client *Client) Update(ctx context.Context, user User) (*auth.UserRecord, error) {

	params := (&auth.UserToUpdate{})
	if user.Email != "" {
		params = params.Email(user.Email)
	}
	if user.PhoneNumber != "" {
		params = params.PhoneNumber(user.PhoneNumber)
	}
	if user.DisplayName != "" {
		params = params.DisplayName(user.DisplayName)
	}
	if user.PhotoURL != "" {
		params = params.PhotoURL(user.PhotoURL)
	}
	if user.Password != "" {
		params = params.Password(user.Password)
	}

	u, err := client.UpdateUser(ctx, user.UID, params)
	if err != nil {
		return nil, err
	}
	err = client.SetUserCustomClaims(ctx, u.UID, user.CustomClaims)
	return u, err
}

func (client *Client) SetUserCustomClaims(ctx context.Context, uid string, claims map[string]interface{}) error {
	return client.SetCustomUserClaims(ctx, uid, claims)
}

func (client *Client) Delete(ctx context.Context, user User) error {
	err := client.DeleteUser(ctx, user.UID)
	return err
}

func (client *Client) VerifyToken(ctx context.Context, idToken string, customClaims map[string]interface{}) (*Token, error) {
	token := new(Token)
	tokenReturn, err := client.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, err
	}
	token.Token = tokenReturn
	return token, err
}
