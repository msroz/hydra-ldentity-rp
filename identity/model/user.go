package model

import "sync"

type ID int

type User struct {
	ID      ID
	LoginID string
}

type UserStore struct {
	sync.Mutex
	users  map[ID]*User
	nextID ID
}

var Store = &UserStore{
	users: map[ID]*User{
		1: {ID: 1, LoginID: "login-id@example.com"},
		2: {ID: 2, LoginID: "login-id2@example.com"},
		3: {ID: 3, LoginID: "login-id3@example.com"},
	},
	nextID: 4,
}

func (us *UserStore) Create(u *User) ID {
	us.Lock()
	defer us.Unlock()

	u.ID = us.nextID
	us.nextID++
	us.users[u.ID] = u
	return u.ID
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

func (us *UserStore) FindByLoginID(loginID string) (*User, bool) {
	us.Lock()
	defer us.Unlock()
	for _, user := range us.users {
		if user.LoginID == loginID {
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
