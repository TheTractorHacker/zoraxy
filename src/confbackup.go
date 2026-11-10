package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	Configuration backup (zip export) and restore (zip import)

	Archive layout: every file of the config folder is stored as "conf/<relative path>"
	no matter where the folder lives (-conf flag), the optional system database as
	"sys.db". Restoring maps these entries back to the running -conf / -dbpath locations.
*/

// writeConfigZip writes the config folder (and optionally the system database) as a backup archive
func writeConfigZip(out io.Writer, confDir string, dbPath string) error {
	zw := zip.NewWriter(out)

	err := filepath.Walk(confDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".history" && filePath != confDir {
			return filepath.SkipDir //the sealed change history is per install and stays out of exports
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(confDir, filePath)
		if err != nil {
			return err
		}
		return addFileToZip(zw, "conf/"+filepath.ToSlash(rel), filePath)
	})
	if err != nil {
		zw.Close()
		return err
	}

	if dbPath != "" {
		if err := addFileToZip(zw, "sys.db", dbPath); err != nil {
			zw.Close()
			return err
		}
	}
	return zw.Close()
}

func addFileToZip(zw *zip.Writer, name string, src string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()
	dst, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, file)
	return err
}

// zipRestoreTarget maps an archive entry name to its destination. The second return value is
// false for entries that are not part of a valid backup (anything outside "conf/" and "sys.db",
// absolute paths and parent directory references).
func zipRestoreTarget(name string, confDir string, dbPath string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "sys.db" {
		return dbPath, true
	}
	if !strings.HasPrefix(name, "conf/") {
		return "", false
	}
	rel := path.Clean(strings.TrimPrefix(name, "conf/"))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.Join(confDir, filepath.FromSlash(rel)), true
}

// restoreConfigZip validates the whole archive first and only then replaces the config folder
// (the old one is kept as <confDir>.old_<timestamp>). beforeDBRestore is called right before
// sys.db is overwritten. It returns true when the system database was part of the archive.
func restoreConfigZip(zr *zip.Reader, confDir string, dbPath string, beforeDBRestore func()) (bool, error) {
	hasConf := false
	hasDB := false
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if _, ok := zipRestoreTarget(f.Name, confDir, dbPath); !ok {
			return false, errors.New("invalid zip file structure or version too old: " + f.Name)
		}
		if f.Name == "sys.db" {
			hasDB = true
		} else {
			hasConf = true
		}
	}
	if !hasConf && !hasDB {
		return false, errors.New("the zip file contains no configuration")
	}

	if hasConf {
		if utils.FileExists(confDir) {
			if err := os.Rename(confDir, confDir+".old_"+strconv.Itoa(int(time.Now().Unix()))); err != nil {
				return false, fmt.Errorf("unable to back up the current config folder: %w", err)
			}
		}
		if err := os.MkdirAll(confDir, 0775); err != nil {
			return false, fmt.Errorf("failed to create target directory: %w", err)
		}
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		target, _ := zipRestoreTarget(f.Name, confDir, dbPath)
		if f.Name == "sys.db" && beforeDBRestore != nil {
			beforeDBRestore()
		}
		if err := extractZipEntry(f, target); err != nil {
			return hasDB, err
		}
	}
	return hasDB, nil
}

func extractZipEntry(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0775); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func ExportConfigAsZip(w http.ResponseWriter, r *http.Request) {
	includeSysDB, _ := utils.GetBool(r, "includeDB")

	if !utils.FileExists(CONF_FOLDER) {
		SystemWideLogger.PrintAndLog("Backup", "Configuration folder not found", nil)
		http.Error(w, "Configuration folder not found", http.StatusInternalServerError)
		return
	}

	dbPath := ""
	if includeSysDB {
		dbPath = *path_database
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"zoraxy-config-"+time.Now().Format("2006-01-02-15-04-05")+".zip\"")
	if err := writeConfigZip(w, CONF_FOLDER, dbPath); err != nil {
		SystemWideLogger.PrintAndLog("Backup", "Unable to write the backup archive", err)
	}
}

func ImportConfigFromZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusBadRequest)
		return
	}

	r.ParseMultipartForm(10 << 20)
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to retrieve uploaded file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	if filepath.Ext(handler.Filename) != ".zip" {
		http.Error(w, "Upload file is not a zip file", http.StatusInternalServerError)
		return
	}

	zipReader, err := zip.NewReader(file, handler.Size)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open zip file: %v", err), http.StatusInternalServerError)
		return
	}

	restoreDatabase, err := restoreConfigZip(zipReader, CONF_FOLDER, *path_database, func() {
		//Sysdb replacement. Close the database before the file is overwritten
		sysdb.Close()
	})
	if err != nil {
		SystemWideLogger.PrintAndLog("Backup", "Configuration restore failed", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	SystemWideLogger.Println("Configuration restored")
	fmt.Fprintln(w, "Configuration restored")

	if restoreDatabase {
		go func() {
			SystemWideLogger.Println("Database altered. Restarting in 3 seconds...")
			time.Sleep(3 * time.Second)
			os.Exit(0)
		}()
	}
}
