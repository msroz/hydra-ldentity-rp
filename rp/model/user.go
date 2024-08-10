package model

import "sync"

type ID int

type User struct {
	ID        ID
	Subject   string // IdPのユーザーID
	Telephone string
	IDToken   string
}

type UserStore struct {
	sync.Mutex
	users  map[ID]*User
	nextID ID
}

var Store = &UserStore{
	users:  map[ID]*User{},
	nextID: 100,
}

func (us *UserStore) Create(u *User) *User {
	us.Lock()
	defer us.Unlock()

	u.ID = us.nextID
	us.nextID++
	us.users[u.ID] = u
	return u
}

func (us *UserStore) FindOrCreateBySubject(u *User) *User {
	for _, user := range us.users {
		if user.Subject == u.Subject {
			return user
		}
	}

	return us.Create(u)
}

func (us *UserStore) FindAll() []*User {
	us.Lock()
	defer us.Unlock()
	users := make([]*User, 0, len(us.users))
	for _, user := range us.users {
		users = append(users, user)
	}
	return users
}

func (us *UserStore) Find(id ID) (*User, bool) {
	us.Lock()
	defer us.Unlock()
	user, exists := us.users[ID(id)]
	return user, exists
}

func (us *UserStore) GetByTelephone(tel string) (*User, bool) {
	us.Lock()
	defer us.Unlock()
	for _, user := range us.users {
		if user.Telephone == tel {
			return user, true
		}
	}

	return nil, false
}

func (us *UserStore) Delete(id ID) bool {
	us.Lock()
	defer us.Unlock()
	_, exists := us.users[id]
	if exists {
		delete(us.users, id)
	}
	return exists
}
