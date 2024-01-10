package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"text/template"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Paste struct {
	ID        int       `gorm:"column:id"`
	UID       string    `gorm:"column:uid"`
	Content   string    `gorm:"column:content"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

var (
	//go:embed tmpl/*.html
	tmplFS embed.FS

	//go:embed assets/*
	assetFs embed.FS

	dbFile = "pastes.db"

	tmplFuncs = template.FuncMap{
		"truncate": func(content string, length int) string {
			if len(content) <= length {
				return content
			}
			return content[:length]
		},
	}

	tmpl = template.Must(template.New("").Funcs(tmplFuncs).ParseFS(tmplFS, "tmpl/*.html"))

	CFTurnstileURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	port               = os.Getenv("PORT")
	CFTurnstileSecret  = os.Getenv("CF_SECRET")
	CFTurnstileSiteKey = os.Getenv("CF_SITEKEY")
	GHClientID         = os.Getenv("GH_CLIENT_ID")
	GHSecret           = os.Getenv("GH_SECRET")
	SiteURL            = os.Getenv("SITE_URL")

	GHRedirectURL = fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s", GHClientID, fmt.Sprintf("%s/login/callback", SiteURL))

	CipherKey = []byte{}
)

func initDB(filepath string) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(filepath), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	err = db.AutoMigrate(&Paste{})
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func randCipherKey() {
	CipherKey = make([]byte, 32)
	_, err := rand.Read(CipherKey[:])
	if err != nil {
		log.Panic(err)
	}
}

func getAllPastes(db *gorm.DB) []Paste {
	pastes := []Paste{}
	db.Order("created_at desc").Find(&pastes)
	return pastes
}

func getPasteWithID(db *gorm.DB, uid string) Paste {
	paste := Paste{}
	db.First(&paste, "uid = ?", uid)
	return paste
}

func insertPaste(db *gorm.DB, content string) string {
	paste := Paste{UID: uuid.New().String(), Content: content, CreatedAt: time.Now()}
	db.Create(&paste)
	return paste.UID
}

func deletePaste(db *gorm.DB, uid string) {
	db.Delete(&Paste{}, "uid = ?", uid)
}

func (p Paste) isNil() bool {
	return p.UID == ""
}

func escapeContent(content string) string {
	return template.HTMLEscapeString(content)
}

func cfValidate(r *http.Request) bool {
	token := r.Form.Get("cf-turnstile-response")
	ip := r.Header.Get("CF-Connecting-IP")

	if token == "" || ip == "" {
		return false
	}

	form := url.Values{}
	form.Set("secret", CFTurnstileSecret)
	form.Set("response", token)
	form.Set("remoteip", ip)
	idempotencyKey := uuid.New().String()
	form.Set("idempotency_key", idempotencyKey)

	resp, err := http.PostForm(CFTurnstileURL, form)
	if err != nil {
		return false
	}

	type CFTurnstileResponse struct {
		Success bool `json:"success"`
	}

	var cfresp CFTurnstileResponse
	err = json.NewDecoder(resp.Body).Decode(&cfresp)

	return err != nil || cfresp.Success
}

type Session struct {
	AK     string `json:"ak"`
	RK     string `json:"rk"`
	Expire int    `json:"ak_expire"`
}

func checkRefreshGHStatus(w http.ResponseWriter, r *http.Request) bool {
	session := getCookieSession(r)
	if session == nil {
		log.Printf("session is nil")
		return false
	}

	log.Printf("session: %+v", session)

	if time.Now().Unix() > int64(session.Expire) {
		log.Printf("now: %d, expire: %d", time.Now().Unix(), session.Expire)
		if session.RK == "" {
			return false
		}
		ak, sk, expiresIn := getGithubAccessToken("", session.RK)
		if ak == "" {
			return false
		}

		setCookieSession(w, "s", ak, sk, expiresIn)
	}

	if getGithubData(session.AK) == "" {
		return false
	}

	return true
}

func getCookieSession(r *http.Request) *Session {
	s, _ := r.Cookie("s")
	if s == nil || s.Value == "" {
		return nil
	}

	session, err := decryptSession(s.Value)
	if err != nil {
		log.Printf("decrypt session error: %v", err)
		return nil
	}

	return &session
}

func setCookieSession(w http.ResponseWriter, name, ak, sk string, expiresIn int) {
	session := Session{
		AK:     ak,
		RK:     sk,
		Expire: int(time.Now().Unix()) + expiresIn,
	}

	encryptSess, err := encryptSession(session)
	if err != nil {
		log.Printf("encrypt session error: %v", err)
		return
	}

	cookie := http.Cookie{
		Name:   name,
		Value:  encryptSess,
		MaxAge: 24 * 60 * 60 * 7,
		Path:   "/",
	}

	log.Printf("Set-Cookie: %s, session: %+v\n", cookie.String(), session)
	http.SetCookie(w, &cookie)
}

func getGithubAccessToken(code, rk string) (string, string, int) {
	params := map[string]string{"client_id": GHClientID, "client_secret": GHSecret}
	if rk != "" {
		params["refresh_token"] = rk
		params["grant_type"] = "refresh_token"
	} else {
		params["code"] = code
	}

	rbody, _ := json.Marshal(params)

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(rbody))
	if err != nil {
		log.Printf("Error: %s\n", err)
		return "", "", 0
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Printf("Error: %s\n", resperr)
		return "", "", 0
	}

	type githubAKResp struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	var ghresp githubAKResp

	err = json.NewDecoder(resp.Body).Decode(&ghresp)
	if err != nil {
		log.Printf("Error: %s\n", err)
		return "", "", 0
	}

	log.Printf("Github: %+v", ghresp)
	return ghresp.AccessToken, ghresp.RefreshToken, ghresp.ExpiresIn
}

func getGithubData(accessToken string) string {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return ""
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", accessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}

	type githubDataResp struct {
		Login string `json:"login"`
	}

	var ghresp githubDataResp

	err = json.NewDecoder(resp.Body).Decode(&ghresp)
	if err != nil {
		return ""
	}

	log.Printf("Github Data: %s\n", ghresp.Login)
	return ghresp.Login
}

func main() {
	randCipherKey()

	flag.StringVar(&dbFile, "db", dbFile, "database file")

	db := initDB(dbFile)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !checkRefreshGHStatus(w, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if r.Method == "GET" {
			pastes := getAllPastes(db)
			tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
				"Pastes":             pastes,
				"CFTurnstileSiteKey": CFTurnstileSiteKey,
			})
		} else {
			r.ParseForm()
			if !cfValidate(r) {
				fmt.Fprintf(w, "Turnstile validation failed, IP: <%s>", r.Header.Get("CF-Connecting-IP"))
				return
			}

			content := r.Form.Get("content")

			uid := insertPaste(db, escapeContent(content))
			http.Redirect(w, r, "/paste/"+uid, http.StatusSeeOther)
		}
	})

	http.HandleFunc("/paste/", func(w http.ResponseWriter, r *http.Request) {
		uid := r.URL.Path[len("/paste/"):]

		if r.Method == "GET" {
			paste := getPasteWithID(db, uid)
			if paste.isNil() {
				http.NotFound(w, r)
				return
			}
			tmpl.ExecuteTemplate(w, "paste.html", paste)
		} else {
			deletePaste(db, uid)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		favicon, _ := assetFs.ReadFile("assets/favicon.ico")
		w.Write(favicon)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, GHRedirectURL, http.StatusSeeOther)
	})

	http.HandleFunc("/login/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		ak, sk, expiresIn := getGithubAccessToken(code, "")
		if ak == "" {
			fmt.Sprintln(w, "<html><body><h1>Failed to login</h1></body></html>")
			return
		}

		setCookieSession(w, "s", ak, sk, expiresIn)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	log.Printf("starting at http://127.0.0.1:%s", port)
	http.ListenAndServe(":"+port, nil)
}

func encryptSession(session Session) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("could not marshal: %v", err)
	}

	return encryptData(data)
}

func decryptSession(str string) (Session, error) {
	var session Session

	data, err := decryptStr(str)
	if err != nil {
		return session, fmt.Errorf("could not decrypt: %v", err)
	}

	err = json.Unmarshal(data, &session)
	if err != nil {
		return session, fmt.Errorf("could not unmarshal: %v", err)
	}

	return session, nil
}

func encryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(CipherKey)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decryptStr(str string) ([]byte, error) {
	cipherText, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(CipherKey)
	if err != nil {
		return nil, fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return cipherText, nil
}
