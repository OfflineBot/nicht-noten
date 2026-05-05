package main

import (
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

type User struct {
	ID       int64
	Username string
}

type Klausur struct {
	ID        int64
	Name      string
	MaxPoints float64
	CreatedAt time.Time
}

type Submission struct {
	Points float64
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS klausuren (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		max_points REAL NOT NULL CHECK (max_points > 0),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS punkte (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		klausur_id INTEGER NOT NULL REFERENCES klausuren(id) ON DELETE CASCADE,
		points REAL NOT NULL
	);
	CREATE TABLE IF NOT EXISTS abgegeben (
		klausur_id INTEGER NOT NULL REFERENCES klausuren(id) ON DELETE CASCADE,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (klausur_id, user_id)
	);
	CREATE INDEX IF NOT EXISTS idx_punkte_klausur ON punkte(klausur_id);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return db, nil
}

func createUser(db *sql.DB, username, passwordHash string) (int64, error) {
	res, err := db.Exec(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, username, passwordHash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func getUserByName(db *sql.DB, username string) (id int64, hash string, err error) {
	err = db.QueryRow(`SELECT id, password_hash FROM users WHERE username = ?`, username).Scan(&id, &hash)
	return
}

func getUserByID(db *sql.DB, id int64) (*User, error) {
	u := &User{}
	err := db.QueryRow(`SELECT id, username FROM users WHERE id = ?`, id).Scan(&u.ID, &u.Username)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func createSession(db *sql.DB, token string, userID int64, expires time.Time) error {
	_, err := db.Exec(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`, token, userID, expires)
	return err
}

func getSessionUser(db *sql.DB, token string) (*User, error) {
	if token == "" {
		return nil, errors.New("no token")
	}
	var userID int64
	var expires time.Time
	err := db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token = ?`, token).Scan(&userID, &expires)
	if err != nil {
		return nil, err
	}
	if time.Now().After(expires) {
		_, _ = db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
		return nil, errors.New("expired")
	}
	return getUserByID(db, userID)
}

func deleteSession(db *sql.DB, token string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func createKlausur(db *sql.DB, name string, maxPoints float64) (int64, error) {
	res, err := db.Exec(`INSERT INTO klausuren (name, max_points) VALUES (?, ?)`, name, maxPoints)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func listKlausuren(db *sql.DB) ([]Klausur, error) {
	rows, err := db.Query(`SELECT id, name, max_points, created_at FROM klausuren ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Klausur
	for rows.Next() {
		var k Klausur
		if err := rows.Scan(&k.ID, &k.Name, &k.MaxPoints, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func getKlausur(db *sql.DB, id int64) (*Klausur, error) {
	k := &Klausur{}
	err := db.QueryRow(`SELECT id, name, max_points, created_at FROM klausuren WHERE id = ?`, id).
		Scan(&k.ID, &k.Name, &k.MaxPoints, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func countPunkte(db *sql.DB, klausurID int64) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM punkte WHERE klausur_id = ?`, klausurID).Scan(&n)
	return n, err
}

func listPunkte(db *sql.DB, klausurID int64) ([]float64, error) {
	rows, err := db.Query(`SELECT points FROM punkte WHERE klausur_id = ?`, klausurID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []float64
	for rows.Next() {
		var p float64
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func hasSubmitted(db *sql.DB, klausurID, userID int64) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM abgegeben WHERE klausur_id = ? AND user_id = ?`, klausurID, userID).Scan(&n)
	return n > 0, err
}

func submitPunkte(db *sql.DB, klausurID, userID int64, points float64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM abgegeben WHERE klausur_id = ? AND user_id = ?`, klausurID, userID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("bereits abgegeben")
	}
	if _, err := tx.Exec(`INSERT INTO punkte (klausur_id, points) VALUES (?, ?)`, klausurID, points); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO abgegeben (klausur_id, user_id) VALUES (?, ?)`, klausurID, userID); err != nil {
		return err
	}
	return tx.Commit()
}
