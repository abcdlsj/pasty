package main

import (
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Paste struct {
	ID             int       `gorm:"column:id"`
	UID            string    `gorm:"column:uid"`
	Title          string    `gorm:"column:title"`
	Content        string    `gorm:"column:content"`
	Type           string    `gorm:"column:type"` // text, image
	RawOnly        bool      `gorm:"column:raw_only"`
	RawFileName    string    `gorm:"column:raw_file_name"`
	ContentVersion int       `gorm:"column:content_version"`
	CreatedAt      time.Time `gorm:"column:created_at"`
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
	db.Where("raw_only = ?", false).Order("created_at desc").Find(&pastes)
	return pastes
}

func getAllPastesForView(db *gorm.DB) []Paste {
	pastes := getAllPastes(db)
	for i := range pastes {
		pastes[i].Content = normalizeTextContent(pastes[i])
	}
	return pastes
}

func getPasteWithID(db *gorm.DB, uid string) Paste {
	paste := Paste{}
	db.First(&paste, "uid = ?", uid)
	return paste
}

func insertPaste(db *gorm.DB, title, content, pasteType string, rawOnly bool, rawFileName string) string {
	paste := Paste{
		UID:            uuid.New().String(),
		Title:          title,
		Content:        content,
		Type:           pasteType,
		RawOnly:        rawOnly,
		RawFileName:    rawFileName,
		ContentVersion: 1,
		CreatedAt:      time.Now(),
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

func extractUID(path, prefix string) string {
	return strings.TrimPrefix(path, prefix)
}

func isLegacyEscapedText(p Paste) bool {
	return p.Type == "text" && !p.RawOnly && p.ContentVersion == 0
}

func normalizeTextContent(p Paste) string {
	if isLegacyEscapedText(p) {
		return html.UnescapeString(p.Content)
	}
	return p.Content
}

func getRawTextContent(p Paste) string {
	return normalizeTextContent(p)
}

func sanitizeFileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"\"", "",
		"\r", "",
		"\n", "",
		"\t", " ",
	)
	name = replacer.Replace(name)
	name = strings.TrimSpace(name)
	if name == "." || name == ".." {
		return ""
	}
	if len(name) > 180 {
		name = name[:180]
	}
	return name
}

func getRawDownloadFileName(p Paste) string {
	if !p.RawOnly {
		return ""
	}

	if name := sanitizeFileName(p.RawFileName); name != "" {
		return name
	}
	if name := sanitizeFileName(p.Title); name != "" {
		return name
	}
	return p.UID + ".txt"
}

func buildRawContentDisposition(p Paste) string {
	fileName := getRawDownloadFileName(p)
	if fileName == "" {
		return ""
	}
	return mime.FormatMediaType("inline", map[string]string{"filename": fileName})
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
			pastes := getAllPastesForView(db)
			tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
				"Pastes": pastes,
			})
		} else {
			// Check for multipart form (file upload) or regular form
			contentType := r.Header.Get("Content-Type")
			var title, content, pasteType string
			rawOnly := false
			rawFileName := ""

			if strings.Contains(contentType, "multipart/form-data") {
				// Parse multipart form (32MB max memory)
				r.ParseMultipartForm(32 << 20)

				title = r.FormValue("title")
				rawOnly = r.FormValue("raw_only") == "on"
				rawFileName = sanitizeFileName(r.FormValue("raw_file_name"))

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
					rawOnly = false
					rawFileName = ""
					content = fmt.Sprintf("data:%s;base64,%s", contentType, base64.StdEncoding.EncodeToString(data))
				} else {
					// Text paste
					pasteType = "text"
					content = r.FormValue("content")
				}
			} else {
				// Regular form
				r.ParseForm()

				title = r.FormValue("title")
				pasteType = "text"
				rawOnly = r.FormValue("raw_only") == "on"
				rawFileName = sanitizeFileName(r.FormValue("raw_file_name"))
				content = r.FormValue("content")
			}

			if strings.TrimSpace(title) == "" {
				title = ""
			}

			if strings.TrimSpace(content) == "" {
				http.Error(w, "content is required", http.StatusBadRequest)
				return
			}

			uid := insertPaste(db, title, content, pasteType, rawOnly, rawFileName)
			if pasteType == "text" && rawOnly {
				http.Redirect(w, r, "/raw-link/"+uid, http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/paste/"+uid, http.StatusSeeOther)
		}
	})

	http.HandleFunc("/raw/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		uid := extractUID(r.URL.Path, "/raw/")
		if uid == "" || uid == "favicon.ico" {
			http.NotFound(w, r)
			return
		}

		paste := getPasteWithID(db, uid)
		if paste.isNil() || paste.Type != "text" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if disposition := buildRawContentDisposition(paste); disposition != "" {
			w.Header().Set("Content-Disposition", disposition)
		}
		fmt.Fprint(w, getRawTextContent(paste))
	})

	http.HandleFunc("/raw-link/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		uid := extractUID(r.URL.Path, "/raw-link/")
		if uid == "" || uid == "favicon.ico" {
			http.NotFound(w, r)
			return
		}

		paste := getPasteWithID(db, uid)
		if paste.isNil() || paste.Type != "text" || !paste.RawOnly {
			http.NotFound(w, r)
			return
		}

		title := paste.Title
		if title == "" {
			title = paste.UID
		}
		tmpl.ExecuteTemplate(w, "raw_link.html", map[string]interface{}{
			"UID":                paste.UID,
			"Title":              title,
			"CreatedAt":          paste.CreatedAt,
			"RawFileName":        getRawDownloadFileName(paste),
			"ContentDisposition": buildRawContentDisposition(paste),
		})
	})

	http.HandleFunc("/paste/", func(w http.ResponseWriter, r *http.Request) {
		uid := extractUID(r.URL.Path, "/paste/")

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
			if paste.Type == "text" && paste.RawOnly {
				http.Redirect(w, r, "/raw-link/"+uid, http.StatusSeeOther)
				return
			}
			title := paste.Title
			if title == "" {
				title = paste.UID
			}
			tmpl.ExecuteTemplate(w, "paste.html", map[string]interface{}{
				"UID":       paste.UID,
				"Title":     title,
				"Content":   normalizeTextContent(paste),
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
