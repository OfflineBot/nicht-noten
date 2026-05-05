package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
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
		"add": func(a, b float64) float64 { return a + b },
		"sub": func(a, b float64) float64 { return a - b },
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
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
	mux.HandleFunc("POST /klausur/{id}/withdraw", app.requireAuth(app.handleKlausurWithdraw))
	mux.HandleFunc("POST /klausur/{id}/delete", app.requireAuth(app.handleKlausurDelete))

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
	myPoints, submitted, hasMyPoints, _ := getUserSubmission(a.db, id, user.ID)

	data := map[string]any{
		"User":        user,
		"Klausur":     k,
		"Count":       len(pts),
		"Submitted":   submitted,
		"MyPoints":    myPoints,
		"HasMyPoints": hasMyPoints,
		"MinReached":  len(pts) >= 5,
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
		data["Freq"] = buildFreqChart(pts, k.MaxPoints, parseStep(r.URL.Query().Get("bin")))
	}

	a.render(w, "klausur.html", data)
}

func (a *App) handleKlausurWithdraw(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := getKlausur(a.db, id); err != nil {
		http.NotFound(w, r)
		return
	}
	target := "/klausur/" + strconv.FormatInt(id, 10)
	if err := withdrawSubmission(a.db, id, user.ID); err != nil {
		http.Redirect(w, r, target+"?err=Zur%C3%BCckziehen+fehlgeschlagen", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (a *App) handleKlausurDelete(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := getKlausur(a.db, id); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target := "/klausur/" + strconv.FormatInt(id, 10)
	confirm := strings.TrimSpace(r.FormValue("confirm_username"))
	if confirm != user.Username {
		http.Redirect(w, r, target+"?err=Username+stimmt+nicht", http.StatusSeeOther)
		return
	}
	if err := deleteKlausur(a.db, id); err != nil {
		http.Redirect(w, r, target+"?err=L%C3%B6schen+fehlgeschlagen", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

type chartDot struct {
	CX, CY  float64
	Bin     float64
	BinEnd  float64
	Count   int
}

type chartTick struct {
	Pos   float64
	Label string
}

type freqChart struct {
	Width, Height          float64
	PadL, PadR, PadT, PadB float64
	ChartW, ChartH         float64
	BaseY                  float64
	Step                   float64
	StepOptions            []float64
	LinePath               string
	AreaPath               string
	Dots                   []chartDot
	YTicks                 []chartTick
	XTicks                 []chartTick
	MaxCount               int
}

func buildFreqChart(pts []float64, maxPts, step float64) freqChart {
	if step <= 0 {
		step = 5
	}
	nBins := int(maxPts/step) + 1
	counts := make([]int, nBins)
	for _, p := range pts {
		idx := int(p / step)
		if idx >= nBins {
			idx = nBins - 1
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

	const w, h = 600.0, 240.0
	const padL, padR, padT, padB = 42.0, 14.0, 28.0, 32.0
	chartW := w - padL - padR
	chartH := h - padT - padB
	yMax := float64(maxCount)
	if yMax < 1 {
		yMax = 1
	}

	xPos := func(bin float64) float64 {
		return padL + (bin/maxPts)*chartW
	}
	yPos := func(c float64) float64 {
		return padT + (1-c/yMax)*chartH
	}

	dots := make([]chartDot, nBins)
	raw := make([][2]float64, nBins)
	for i := 0; i < nBins; i++ {
		binStart := float64(i) * step
		binEnd := binStart + step
		if binEnd > maxPts {
			binEnd = maxPts
		}
		x := xPos(binStart)
		y := yPos(float64(counts[i]))
		dots[i] = chartDot{CX: x, CY: y, Bin: binStart, BinEnd: binEnd, Count: counts[i]}
		raw[i] = [2]float64{x, y}
	}

	line := smoothPath(raw, padT, padT+chartH)
	area := ""
	if nBins > 0 {
		var b strings.Builder
		b.WriteString(line)
		fmt.Fprintf(&b, " L%.2f %.2f L%.2f %.2f Z", raw[nBins-1][0], padT+chartH, raw[0][0], padT+chartH)
		area = b.String()
	}

	yTicks := []chartTick{{Pos: yPos(0), Label: "0"}}
	if maxCount >= 2 {
		mid := maxCount / 2
		yTicks = append(yTicks, chartTick{Pos: yPos(float64(mid)), Label: strconv.Itoa(mid)})
	}
	yTicks = append(yTicks, chartTick{Pos: yPos(yMax), Label: strconv.Itoa(maxCount)})

	xTicks := []chartTick{}
	tickEvery := 1
	for nBins/tickEvery > 8 {
		tickEvery++
	}
	for i := 0; i < nBins; i += tickEvery {
		binStart := float64(i) * step
		xTicks = append(xTicks, chartTick{Pos: xPos(binStart), Label: strconv.FormatFloat(binStart, 'f', -1, 64)})
	}
	if (nBins-1)%tickEvery != 0 && nBins > 0 {
		last := float64(nBins-1) * step
		xTicks = append(xTicks, chartTick{Pos: xPos(last), Label: strconv.FormatFloat(last, 'f', -1, 64)})
	}

	return freqChart{
		Width: w, Height: h,
		PadL: padL, PadR: padR, PadT: padT, PadB: padB,
		ChartW: chartW, ChartH: chartH,
		BaseY:       padT + chartH,
		Step:        step,
		StepOptions: []float64{1, 2, 5, 10},
		LinePath:    line,
		AreaPath:    area,
		Dots:        dots,
		YTicks:      yTicks,
		XTicks:      xTicks,
		MaxCount:    maxCount,
	}
}

// smoothPath builds a Catmull-Rom-to-Bezier path through the given points.
// Control points are clamped to [yMin, yMax] so the curve doesn't undershoot
// the chart area when going to/from zero counts.
func smoothPath(pts [][2]float64, yMin, yMax float64) string {
	n := len(pts)
	if n == 0 {
		return ""
	}
	if n == 1 {
		return fmt.Sprintf("M%.2f %.2f", pts[0][0], pts[0][1])
	}
	clamp := func(y float64) float64 {
		if y < yMin {
			return yMin
		}
		if y > yMax {
			return yMax
		}
		return y
	}
	var b strings.Builder
	fmt.Fprintf(&b, "M%.2f %.2f", pts[0][0], pts[0][1])
	for i := 0; i < n-1; i++ {
		p1 := pts[i]
		p2 := pts[i+1]
		var p0, p3 [2]float64
		if i == 0 {
			p0 = p1
		} else {
			p0 = pts[i-1]
		}
		if i+2 < n {
			p3 = pts[i+2]
		} else {
			p3 = p2
		}
		c1x := p1[0] + (p2[0]-p0[0])/6
		c1y := clamp(p1[1] + (p2[1]-p0[1])/6)
		c2x := p2[0] - (p3[0]-p1[0])/6
		c2y := clamp(p2[1] - (p3[1]-p1[1])/6)
		fmt.Fprintf(&b, " C%.2f %.2f %.2f %.2f %.2f %.2f", c1x, c1y, c2x, c2y, p2[0], p2[1])
	}
	return b.String()
}

func parseStep(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 5
	}
	for _, allowed := range []float64{1, 2, 5, 10} {
		if v == allowed {
			return v
		}
	}
	return 5
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
