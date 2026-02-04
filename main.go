package main

import (
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Paste struct {
	ID        int       `gorm:"column:id"`
	UID       string    `gorm:"column:uid"`
	Title     string    `gorm:"column:title"`
	Content   string    `gorm:"column:content"`
	Type      string    `gorm:"column:type"` // text, image
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

	port = getEnvDefault("PORT", "8080")
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
	db.Order("created_at desc").Find(&pastes)
	return pastes
}

func getPasteWithID(db *gorm.DB, uid string) Paste {
	paste := Paste{}
	db.First(&paste, "uid = ?", uid)
	return paste
}

func insertPaste(db *gorm.DB, title, content, pasteType string) string {
	paste := Paste{
		UID:       uuid.New().String(),
		Title:     title,
		Content:   content,
		Type:      pasteType,
		CreatedAt: time.Now(),
	}
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

func getEnvDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func main() {
	flag.StringVar(&dbFile, "db", dbFile, "database file")
	flag.Parse()

	db := initDB(dbFile)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			pastes := getAllPastes(db)
			tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
				"Pastes": pastes,
			})
		} else {
			// Check for multipart form (file upload) or regular form
			contentType := r.Header.Get("Content-Type")
			var title, content, pasteType string

			if strings.Contains(contentType, "multipart/form-data") {
				// Parse multipart form (32MB max memory)
				r.ParseMultipartForm(32 << 20)

				title = r.FormValue("title")

				// Check for file upload
				file, header, err := r.FormFile("image")
				if err == nil && file != nil {
					defer file.Close()

					// Validate image type
					contentType = header.Header.Get("Content-Type")
					if !strings.HasPrefix(contentType, "image/") {
						fmt.Fprintf(w, "Invalid file type: only images are allowed")
						return
					}

					// Read and encode image to base64
					data, err := io.ReadAll(file)
					if err != nil {
						fmt.Fprintf(w, "Error reading file: %v", err)
						return
					}

					pasteType = "image"
					content = fmt.Sprintf("data:%s;base64,%s", contentType, base64.StdEncoding.EncodeToString(data))
				} else {
					// Text paste
					pasteType = "text"
					content = escapeContent(r.FormValue("content"))
				}
			} else {
				// Regular form
				r.ParseForm()

				title = r.FormValue("title")
				pasteType = "text"
				content = escapeContent(r.FormValue("content"))
			}

			// Use UID as title if not provided
			if strings.TrimSpace(title) == "" {
				title = ""
			}

			uid := insertPaste(db, title, content, pasteType)
			http.Redirect(w, r, "/paste/"+uid, http.StatusSeeOther)
		}
	})

	http.HandleFunc("/paste/", func(w http.ResponseWriter, r *http.Request) {
		uid := r.URL.Path[len("/paste/"):]

		// Skip favicon.ico requests
		if uid == "favicon.ico" {
			http.NotFound(w, r)
			return
		}

		if r.Method == "GET" {
			paste := getPasteWithID(db, uid)
			if paste.isNil() {
				http.NotFound(w, r)
				return
			}
			title := paste.Title
			if title == "" {
				title = paste.UID
			}
			tmpl.ExecuteTemplate(w, "paste.html", map[string]interface{}{
				"UID":       paste.UID,
				"Title":     title,
				"Content":   paste.Content,
				"Type":      paste.Type,
				"CreatedAt": paste.CreatedAt,
			})
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
