package ca

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ZipFiles struct {
	Filename, ZipPath string
}

// Packages the certificate authority lambda into a zip archive on writer
func lambdaCreateArchive(wr io.Writer, filename ...string) error {

	archive := zip.NewWriter(wr)
	defer archive.Close()

	for _, path := range filename {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(writer, file); err != nil {
			return err
		}
	}

	return nil
}

// Packages the certificate authority function into a GCP compatible zip archive on writer
func gcpCreateArchive(wr io.Writer, files ...ZipFiles) error {

	archive := zip.NewWriter(wr)
	defer archive.Close()

	for _, fileinfo := range files {
		info, err := os.Stat(fileinfo.Filename)
		if err != nil {
			return err
		}
		if info.IsDir() {
			err = zipDirectory(archive, fileinfo.Filename, fileinfo.ZipPath)
			if err != nil {
				return err
			}
			continue
		}

		if strings.TrimSpace(fileinfo.ZipPath) == "" {
			fileinfo.ZipPath = fileinfo.Filename
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = fileinfo.ZipPath

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(fileinfo.Filename)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(writer, file); err != nil {
			return err
		}
	}

	return nil
}

func zipDirectory(archive *zip.Writer, dir, zipDir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		var zipPath string
		if strings.TrimSpace(zipDir) == "" {
			zipPath = path
		} else {
			zipPath = strings.Replace(path, dir, zipDir, 1)
		}
		if info.IsDir() {
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = zipPath

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(writer, file); err != nil {
			return err
		}
		return nil
	})
}
