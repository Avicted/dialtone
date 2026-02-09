package user

type ID string

type User struct {
	ID   ID
	Name string
}

type Repository interface {
	GetByID(id ID) (User, error)
}
