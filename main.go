package main

import (
	"embed"
	"flag"
	"log"
	"net/http"
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

func insertPaste(db *gorm.DB, content string) {
	paste := Paste{UID: uuid.New().String(), Content: content, CreatedAt: time.Now()}
	db.Create(&paste)
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

func main() {
	flag.StringVar(&dbFile, "db", dbFile, "database file")

	db := initDB(dbFile)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			pastes := getAllPastes(db)
			tmpl.ExecuteTemplate(w, "index.html", pastes)
		} else {
			r.ParseForm()
			content := r.Form.Get("content")
			insertPaste(db, escapeContent(content))
			http.Redirect(w, r, "/", http.StatusSeeOther)
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

	http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}
