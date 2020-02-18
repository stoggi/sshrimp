package ca

import (
	"archive/zip"
	"io"
	"os"
)

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
