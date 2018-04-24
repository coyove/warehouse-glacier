//cyvignore
package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	_path "path"
	"path/filepath"
	"regexp"
	"strings"
)

var password = flag.String("p", "", "encrypt password")
var action = flag.String("a", "e", "action: enc, dec")
var directory = flag.String("d", "!", "directory to tar")
var outputArchive = flag.String("o", "a.tar", "output archive name")
var splitArchivePart = flag.Int("s", 1024*1024*10, "split tar into parts")
var upperDirectory string
var pat = regexp.MustCompile(`\.[0-9a-f]{6}\.cyv$`)

type Filed struct {
	Name   string
	Path   string
	Prefix string
	Info   os.FileInfo
}

type Star struct {
	writer   *tar.Writer
	file     *os.File
	size     int
	filename string
}

func NewStar(filename string) Star {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalln(err)
	}

	tw := tar.NewWriter(f)

	return Star{tw, f, 0, filename}
}

func (s *Star) Close() {
	if err := s.writer.Close(); err != nil {
		log.Fatalln(err)
	}

	if err := s.file.Close(); err != nil {
		log.Fatalln(err)
	}

	if s.size == 0 {
		os.Remove(s.filename)
	}
}

func (s *Star) Write(file Filed) int {
	body, err := ioutil.ReadFile(file.Path)
	if err != nil {
		log.Fatalln(err)
	}

	hdr, err := tar.FileInfoHeader(file.Info, file.Info.Name())
	if err != nil {
		log.Fatalln(err)
	}

	hdr.Name = file.Name

	if err := s.writer.WriteHeader(hdr); err != nil {
		log.Fatalln(err)
	}

	if _, err := s.writer.Write(body); err != nil {
		log.Fatalln(err)
	}

	s.size += len(body)
	return s.size
}

func buildDirectoryTree(upper, base string) []Filed {
	ret := []Filed{}
	dirpath := upper + "/" + base

	if err := filepath.Walk(dirpath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			path = strings.Replace(path, "\\", "/", -1)

			file := Filed{}
			file.Path = path
			file.Info = info
			file.Name = filepath.Join(base, strings.TrimPrefix(path, dirpath))

			if !info.IsDir() {
				if len(file.Name) > 100 {
					fmt.Println("very long name:", strings.TrimPrefix(path, dirpath))
				} else if !strings.HasSuffix(file.Name, ".posted") {
					ret = append(ret, file)
				}
			}

			return nil
		}); err != nil {
		log.Fatalln(err)
	}

	return ret
}

type ereader struct {
	r   io.Reader
	str cipher.Stream
}

func shouldIgnore(path string) bool {
	from, err := os.Open(path)
	if err != nil {
		return true
	}
	buf := make([]byte, 11)
	from.Read(buf)
	from.Close()
	return bytes.Equal(buf, []byte("//cyvignore"))
}

func (e *ereader) Read(buf []byte) (int, error) {
	n, err := e.r.Read(buf)
	e.str.XORKeyStream(buf[:n], buf[:n])
	return n, err
}

func aes128e(dir string, str cipher.Stream) {
	fmt.Println("doing encryption")

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || pat.MatchString(path) || strings.Contains(path, ".git/") || shouldIgnore(path) {
			return nil
		}

		npath := fmt.Sprintf("%s.%s.cyv", path, fmt.Sprintf("%x", sha1.Sum([]byte(path)))[:6])
		from, err := os.Open(path)
		if err != nil {
			panic(err)
		}

		to, err := os.Create(npath)
		if err != nil {
			panic(err)
		}

		_, err = io.Copy(to, &ereader{from, str})
		if err != nil {
			panic(err)
		}

		from.Close()
		to.Close()

		os.Remove(path)
		return nil
	})
	fmt.Println("done")
}

func aes128d(dir string, str cipher.Stream) {
	fmt.Println("doing decryption")
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || !pat.MatchString(path) || strings.Contains(path, ".git/") || shouldIgnore(path) {
			return nil
		}

		// .123456.cyv
		npath := path[:len(path)-11]
		from, err := os.Open(path)
		if err != nil {
			panic(err)
		}

		to, err := os.Create(npath)
		if err != nil {
			panic(err)
		}

		_, err = io.Copy(to, &ereader{from, str})
		if err != nil {
			panic(err)
		}

		from.Close()
		to.Close()

		os.Remove(path)
		return nil
	})
	fmt.Println("done")
}

func main() {
	flag.Parse()

	filename := *outputArchive
	directory := strings.Replace(*directory, "\\", "/", -1)
	if strings.HasSuffix(directory, "/") {
		directory = directory[:len(directory)-1]
	}

	upperDirectory = _path.Dir(directory)
	directory = _path.Base(directory)

	fmt.Println("parent:", upperDirectory)
	fmt.Println("base:", directory)

	if *password != "" {
		iv := []byte(*password)
		for len(iv) < 16 {
			iv = append(iv, iv...)
		}
		iv = iv[:16]
		blk, _ := aes.NewCipher(iv)

		if *action == "e" {
			aes128e(upperDirectory+"/"+directory, cipher.NewCTR(blk, iv))
		} else {
			aes128d(upperDirectory+"/"+directory, cipher.NewCTR(blk, iv))
		}
		return
	}

	files := buildDirectoryTree(upperDirectory, directory)
	idx := 1

	star := NewStar(filename + ".1")
	lp := 0
	for i, file := range files {
		p := int(float64(i)/float64(len(files))*100) + 1
		if p != lp {
			fmt.Printf("\rprogress: %d%%, output: %s.%d", p, *outputArchive, idx)
			lp = p
		}

		if star.Write(file) > *splitArchivePart {
			star.Close()
			idx++
			star = NewStar(fmt.Sprintf("%s.%d", *outputArchive, idx))
		}
	}

	star.Close()
	fmt.Println("\ndone")

	os.Exit(idx)
}
