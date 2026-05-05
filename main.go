package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static/*
var staticFS embed.FS

const sessionCookieName = "ndsession"
const sessionDuration = 30 * 24 * time.Hour

type ctxKey string

const userKey ctxKey = "user"

type App struct {
	db    *sql.DB
	pages map[string]*template.Template
}

func main() {
	addr := envOr("ADDR", ":8080")
	dbPath := envOr("DB_PATH", "data.db")

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	funcs := template.FuncMap{
		"fmtFloat": func(f float64) string {
			return strconv.FormatFloat(f, 'f', 2, 64)
		},
		"pct": func(v, total float64) float64 {
			if total == 0 {
				return 0
			}
			return v / total * 100
		},
	}
	pageNames := []string{
		"login.html",
		"register.html",
		"index.html",
		"klausur_new.html",
		"klausur.html",
	}
	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcs).ParseFS(tmplFS, "templates/layout.html", "templates/"+name)
		if err != nil {
			log.Fatalf("template %s: %v", name, err)
		}
		pages[name] = t
	}

	app := &App{db: db, pages: pages}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /register", app.handleRegisterForm)
	mux.HandleFunc("POST /register", app.handleRegister)
	mux.HandleFunc("GET /login", app.handleLoginForm)
	mux.HandleFunc("POST /login", app.handleLogin)
	mux.HandleFunc("POST /logout", app.handleLogout)

	mux.HandleFunc("GET /{$}", app.requireAuth(app.handleIndex))
	mux.HandleFunc("GET /klausur/new", app.requireAuth(app.handleKlausurForm))
	mux.HandleFunc("POST /klausur/new", app.requireAuth(app.handleKlausurCreate))
	mux.HandleFunc("GET /klausur/{id}", app.requireAuth(app.handleKlausurShow))
	mux.HandleFunc("POST /klausur/{id}/submit", app.requireAuth(app.handleKlausurSubmit))

	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (a *App) currentUser(r *http.Request) *User {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	u, err := getSessionUser(a.db, c.Value)
	if err != nil {
		return nil
	}
	return u
}

func (a *App) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := a.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r = r.WithContext(withUser(r, u))
		h(w, r)
	}
}

func withUser(r *http.Request, u *User) requestContext {
	return requestContext{r.Context(), u}
}

type requestContext struct {
	parent any
	user   *User
}

func (c requestContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c requestContext) Done() <-chan struct{}       { return nil }
func (c requestContext) Err() error                  { return nil }
func (c requestContext) Value(key any) any {
	if k, ok := key.(ctxKey); ok && k == userKey {
		return c.user
	}
	if p, ok := c.parent.(interface{ Value(any) any }); ok {
		return p.Value(key)
	}
	return nil
}

func userFrom(r *http.Request) *User {
	u, _ := r.Context().Value(userKey).(*User)
	return u
}

func (a *App) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, ok := a.pages[name]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (a *App) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	if a.currentUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.render(w, "register.html", map[string]any{})
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(username) < 3 || len(username) > 32 {
		a.render(w, "register.html", map[string]any{"Error": "Username muss 3–32 Zeichen lang sein."})
		return
	}
	if len(password) < 6 {
		a.render(w, "register.html", map[string]any{"Error": "Passwort muss mindestens 6 Zeichen haben."})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "hash error", http.StatusInternalServerError)
		return
	}
	id, err := createUser(a.db, username, string(hash))
	if err != nil {
		a.render(w, "register.html", map[string]any{"Error": "Username bereits vergeben."})
		return
	}
	a.startSession(w, id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if a.currentUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.render(w, "login.html", map[string]any{})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	id, hash, err := getUserByName(a.db, username)
	if err != nil {
		a.render(w, "login.html", map[string]any{"Error": "Username oder Passwort falsch."})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		a.render(w, "login.html", map[string]any{"Error": "Username oder Passwort falsch."})
		return
	}
	a.startSession(w, id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) startSession(w http.ResponseWriter, userID int64) {
	token := newToken()
	expires := time.Now().Add(sessionDuration)
	if err := createSession(a.db, token, userID, expires); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		_ = deleteSession(a.db, c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type klausurRow struct {
	Klausur
	Count       int
	Submitted   bool
	HasStats    bool
	Average     float64
	AveragePct  float64
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	klausuren, err := listKlausuren(a.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]klausurRow, 0, len(klausuren))
	for _, k := range klausuren {
		count, _ := countPunkte(a.db, k.ID)
		submitted, _ := hasSubmitted(a.db, k.ID, user.ID)
		row := klausurRow{Klausur: k, Count: count, Submitted: submitted}
		if count >= 5 {
			pts, _ := listPunkte(a.db, k.ID)
			avg := mean(pts)
			row.HasStats = true
			row.Average = avg
			if k.MaxPoints > 0 {
				row.AveragePct = avg / k.MaxPoints * 100
			}
		}
		rows = append(rows, row)
	}
	a.render(w, "index.html", map[string]any{
		"User":      user,
		"Klausuren": rows,
	})
}

func (a *App) handleKlausurForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, "klausur_new.html", map[string]any{"User": userFrom(r)})
}

func (a *App) handleKlausurCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	maxStr := strings.Replace(strings.TrimSpace(r.FormValue("max_points")), ",", ".", 1)
	if name == "" || len(name) > 100 {
		a.render(w, "klausur_new.html", map[string]any{"User": userFrom(r), "Error": "Name fehlt oder zu lang."})
		return
	}
	maxPoints, err := strconv.ParseFloat(maxStr, 64)
	if err != nil || maxPoints <= 0 {
		a.render(w, "klausur_new.html", map[string]any{"User": userFrom(r), "Error": "Maximalpunkte ungültig."})
		return
	}
	id, err := createKlausur(a.db, name, maxPoints)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/klausur/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

type histBin struct {
	Label string
	Count int
	Pct   float64
}

func (a *App) handleKlausurShow(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	k, err := getKlausur(a.db, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	pts, _ := listPunkte(a.db, id)
	submitted, _ := hasSubmitted(a.db, id, user.ID)

	data := map[string]any{
		"User":      user,
		"Klausur":   k,
		"Count":     len(pts),
		"Submitted": submitted,
		"MinReached": len(pts) >= 5,
	}

	if errMsg := r.URL.Query().Get("err"); errMsg != "" {
		data["Error"] = errMsg
	}

	if len(pts) >= 5 {
		avg := mean(pts)
		data["Average"] = avg
		data["AveragePct"] = avg / k.MaxPoints * 100
		data["Min"] = minF(pts)
		data["Max"] = maxF(pts)
		medSingle, medPair := medianValues(pts)
		data["Median"] = medSingle
		if medPair != nil {
			data["MedianPair"] = medPair
		}
		data["StdDev"] = stddev(pts, avg)
		data["Histogram"] = histogram(pts, k.MaxPoints, 10)
	}

	a.render(w, "klausur.html", data)
}

func (a *App) handleKlausurSubmit(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	k, err := getKlausur(a.db, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pStr := strings.Replace(strings.TrimSpace(r.FormValue("points")), ",", ".", 1)
	points, err := strconv.ParseFloat(pStr, 64)
	target := "/klausur/" + strconv.FormatInt(id, 10)
	if err != nil || points < 0 || points > k.MaxPoints {
		http.Redirect(w, r, target+"?err=Punkte+ung%C3%BCltig", http.StatusSeeOther)
		return
	}
	if err := submitPunkte(a.db, id, user.ID, points); err != nil {
		http.Redirect(w, r, target+"?err=Bereits+abgegeben", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func minF(xs []float64) float64 {
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func maxF(xs []float64) float64 {
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func medianValues(xs []float64) (single float64, pair []float64) {
	cp := make([]float64, len(xs))
	copy(cp, xs)
	sortFloats(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2], nil
	}
	return 0, []float64{cp[n/2-1], cp[n/2]}
}

func sortFloats(xs []float64) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}

func stddev(xs []float64, m float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var s float64
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return sqrt(s / float64(len(xs)-1))
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 20; i++ {
		z = (z + x/z) / 2
	}
	return z
}

func histogram(xs []float64, maxPts float64, bins int) []histBin {
	if bins <= 0 {
		bins = 10
	}
	counts := make([]int, bins)
	width := maxPts / float64(bins)
	for _, x := range xs {
		idx := int(x / width)
		if idx >= bins {
			idx = bins - 1
		}
		if idx < 0 {
			idx = 0
		}
		counts[idx]++
	}
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	out := make([]histBin, bins)
	for i := 0; i < bins; i++ {
		lo := float64(i) * width
		hi := float64(i+1) * width
		out[i] = histBin{
			Label: strconv.FormatFloat(lo, 'f', 1, 64) + "–" + strconv.FormatFloat(hi, 'f', 1, 64),
			Count: counts[i],
		}
		if maxCount > 0 {
			out[i].Pct = float64(counts[i]) / float64(maxCount) * 100
		}
	}
	return out
}
