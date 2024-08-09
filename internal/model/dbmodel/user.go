package dbmodel

type User struct {
	Id           int    `db:"id"`
	UserId       string `db:"user_id"`
	Email        string `db:"email"`
	Password     string `db:"password"`
	RefreshToken string `db:"refresh_token"`
}
