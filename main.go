package main

import (
	"embed"
	"encoding/json"
	"flag"
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

	port = os.Getenv("PORT")

	CFTurnstileSecret  = os.Getenv("CF_SECRET")
	CFTurnstileURL     = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	CFTurnstileSiteKey = os.Getenv("CF_SITEKEY")
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

func getAllPastes(db *gorm.DB) []Paste {
	pastes := []Paste{}
	db.Find(&pastes)
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

	cfresp := CFTurnstileResponse{}

	err = json.NewDecoder(resp.Body).Decode(&cfresp)

	return err != nil || cfresp.Success
}

func main() {
	flag.StringVar(&dbFile, "db", dbFile, "database file")

	db := initDB(dbFile)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			pastes := getAllPastes(db)
			tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
				"Pastes":             pastes,
				"CFTurnstileSiteKey": CFTurnstileSiteKey,
			})
		} else {
			r.ParseForm()
			if !cfValidate(r) {
				http.Error(w, "invalid captcha", http.StatusBadRequest)
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

	log.Printf("starting at http://127.0.0.1:%s", port)
	http.ListenAndServe(":"+port, nil)
}
