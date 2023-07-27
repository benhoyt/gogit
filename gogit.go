// Implement just enough git (in Go) to commit and push to GitHub.
//
// Read the story here: https://benhoyt.com/writings/gogit/
//
// Released under a permissive MIT license (see LICENSE.txt).

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init":
		err := initRepo()
		check(err)

	case "commit":
		// "gogit commit" is different from "git commit": for simplicity, gogit
		// doesn't maintain the git index (staging area), so you have to
		// specify the list of paths you want committed each time.
		var (
			author  string
			message string
		)
		flagSet := flag.NewFlagSet("gogit commit --author 'name <email>' -m 'message' paths...", flag.ExitOnError)
		flagSet.StringVar(&author, "author", "", "commit author (required)")
		flagSet.StringVar(&message, "m", "", "commit message (required)")
		flagSet.Parse(os.Args[2:])
		if author == "" || message == "" || len(flagSet.Args()) == 0 {
			flagSet.Usage()
		}
		hash, err := commit(message, author, flagSet.Args())
		check(err)
		fmt.Printf("committed %s to master\n", hash[:7])

	case "push":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: gogit push git-url")
			os.Exit(1)
		}
		gitURL := os.Args[2]
		username := os.Getenv("GIT_USERNAME")
		password := os.Getenv("GIT_PASSWORD")
		if username == "" || password == "" {
			fmt.Fprintln(os.Stderr, "GIT_USERNAME and GIT_PASSWORD must be set")
			os.Exit(1)
		}
		remote, local, num, err := push(gitURL, username, password)
		check(err)
		fmt.Printf("updating remote master from %s to %s (%d objects)\n", remote[:7], local[:7], num)

	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gogit [cat-file|commit|init|hash-object|push|...]")
	os.Exit(2)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Create the directories and files required to initialise a git repo.
func initRepo() error {
	for _, name := range []string{".git/objects", ".git/refs/heads"} {
		err := os.MkdirAll(name, 0o775)
		if err != nil {
			return err
		}
	}
	return os.WriteFile(".git/HEAD", []byte("ref: refs/heads/master"), 0o664)
}

// Commit tree of given paths to master, returning the commit hash.
func commit(message, author string, paths []string) (string, error) {
	tree, err := writeTree(paths)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "tree", hex.EncodeToString(tree))
	parent := getLocalHash()
	if parent != "" {
		fmt.Fprintln(&buf, "parent", parent)
	}
	now := time.Now()
	offset := now.Format("-0700")
	fmt.Fprintln(&buf, "author", author, now.Unix(), offset)
	fmt.Fprintln(&buf, "committer", author, now.Unix(), offset)
	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, message)
	data := buf.Bytes()
	hash, err := hashObject("commit", data)
	if err != nil {
		return "", err
	}
	err = os.WriteFile(".git/refs/heads/master", []byte(hex.EncodeToString(hash)+"\n"), 0o664)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// Write a "tree" object with the given paths (sub-trees are not supported).
func writeTree(paths []string) ([]byte, error) {
	sort.Strings(paths) // tree object needs paths sorted
	var buf bytes.Buffer
	for _, path := range paths {
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			panic("sub-trees not supported")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		hash, err := hashObject("blob", data)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "%o %s\x00%s", st.Mode().Perm()|0o100000, path, hash)
	}
	return hashObject("tree", buf.Bytes())
}

// Hash and write the given data as a git object of the given type.
func hashObject(objType string, data []byte) ([]byte, error) {
	sha := sha1.New()
	header := fmt.Sprintf("%s %d\x00", objType, len(data))
	io.WriteString(sha, header) // these writes can't fail
	sha.Write(data)
	hash := sha.Sum(nil)
	hashStr := hex.EncodeToString(hash)
	path := filepath.Join(".git/objects", hashStr[:2], hashStr[2:])
	err := os.MkdirAll(filepath.Dir(path), 0o775)
	if err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() // doesn't hurt to call f.Close() twice (also below)

	compressed, err := compress(append([]byte(header), data...))
	_, err = f.Write(compressed)
	if err != nil {
		return nil, err
	}
	err = f.Close()
	return hash, err
}

// Return current commit hash of the local master branch.
func getLocalHash() string {
	hash, err := os.ReadFile(".git/refs/heads/master")
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(hash))
}

// Read git object with given hash (or hash prefix).
func readObject(hashPrefix string) (objType string, data []byte, err error) {
	path, err := findObject(hashPrefix)
	if err != nil {
		return "", nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	decompressor, err := zlib.NewReader(f)
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	_, err = io.Copy(&buf, decompressor)
	if err != nil {
		return "", nil, err
	}
	err = decompressor.Close()
	if err != nil {
		return "", nil, err
	}
	fullData := buf.Bytes()

	nulIndex := bytes.IndexByte(fullData, 0)
	if nulIndex < 0 {
		return "", nil, fmt.Errorf("invalid object data: no NUL byte")
	}
	header := fullData[:nulIndex]
	objType, sizeStr, ok := strings.Cut(string(header), " ")
	if !ok {
		return "", nil, fmt.Errorf("invalid object header")
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return "", nil, fmt.Errorf("invalid object header: invalid size")
	}
	data = fullData[nulIndex+1:]
	if size != len(data) {
		return "", nil, fmt.Errorf("invalid object: expected size %d, got %d",
			size, len(data))
	}
	return objType, data, nil
}

// Find object with given hash prefix and return full hash, or error if not found.
func findObject(hashPrefix string) (string, error) {
	if len(hashPrefix) < 2 {
		return "", fmt.Errorf("hash prefix must be 2 or more characters")
	}
	objDir := filepath.Join(".git/objects", hashPrefix[:2])
	rest := hashPrefix[2:]
	entries, err := os.ReadDir(objDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("object %q not found", hashPrefix)
		}
		return "", err
	}
	var match string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), rest) {
			if match != "" {
				return "", fmt.Errorf("multiple objects with prefix %q", hashPrefix)
			}
			match = entry.Name()
		}
	}
	if match == "" {
		return "", fmt.Errorf("object %q not found", hashPrefix)
	}
	return filepath.Join(objDir, match), nil
}

// Push master branch (and missing objects) to remote.
func push(gitURL, username, password string) (remoteHash, localHash string, num int, err error) {
	client := &http.Client{Timeout: 10 * time.Second}
	remoteHash, err = getRemoteHash(client, gitURL, username, password)
	if err != nil {
		return "", "", 0, err
	}
	localHash = getLocalHash()

	missing, err := findMissingObjects(localHash, remoteHash)
	if err != nil {
		return "", "", 0, err
	}
	if remoteHash == "" {
		remoteHash = strings.Repeat("0", 40)
	}
	line := fmt.Sprintf("%s %s refs/heads/master\x00 report-status\n",
		remoteHash, localHash)
	packData, err := createPack(missing)
	if err != nil {
		return "", "", 0, err
	}
	sendData := append([]byte(fmt.Sprintf("%04x%s0000", len(line)+4, line)), packData...)

	fout, err := os.Create("test.pack")
	if err != nil {
		return "", "", 0, err
	}
	_, err = fout.Write(sendData)
	if err != nil {
		return "", "", 0, err
	}
	err = fout.Close()
	if err != nil {
		return "", "", 0, err
	}
	request, err := http.NewRequest("POST", gitURL+"/git-receive-pack", bytes.NewReader(sendData))
	if err != nil {
		return "", "", 0, err
	}
	addBasicAuth(request, username, password)
	response, err := client.Do(request)
	if err != nil {
		return "", "", 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", "", 0, err
	}
	if response.StatusCode != 200 {
		return "", "", 0, fmt.Errorf("expected status 200, got %d", response.StatusCode)
	}
	os.Stdout.Write(data)
	lines, err := extractLines(data)
	if err != nil {
		return "", "", 0, err
	}
	if lines[0] != "unpack ok\n" {
		return "", "", 0, fmt.Errorf(`expected line 1 to be "unpack ok\n", got %q`, lines[0])
	}
	if lines[1] != "ok refs/heads/master\n" {
		return "", "", 0, fmt.Errorf(`expected line 2 to be "ok refs/heads/master\n", got %q`, lines[1])
	}
	return remoteHash, localHash, len(missing), nil
}

// Get current hash of master branch on remote.
func getRemoteHash(client *http.Client, gitURL, username, password string) (string, error) {
	request, err := http.NewRequest("GET", gitURL+"/info/refs?service=git-receive-pack", nil)
	if err != nil {
		return "", err
	}
	addBasicAuth(request, username, password)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != 200 {
		return "", fmt.Errorf("expected status 200, got %d", response.StatusCode)
	}
	lines, err := extractLines(data)
	if err != nil {
		return "", err
	}
	if lines[0] != "# service=git-receive-pack\n" {
		return "", fmt.Errorf("invalid service line %q", lines[0])
	}
	if lines[1] != "" {
		return "", fmt.Errorf("expected empty second line, got %q", lines[1])
	}
	if lines[2][:40] == strings.Repeat("0", 40) {
		return "", nil
	}
	hash, ref, ok := strings.Cut(lines[2], "\x00")
	if !ok {
		return "", fmt.Errorf("expected hash and ref, got %q", lines[2])
	}
	if ref != "refs/heads/master" {
		return "", fmt.Errorf(`expected "refs/heads/master", got %q`, ref)
	}
	if len(hash) != 40 {
		return "", fmt.Errorf("expected 40-char hash, got %q (%d)", hash, len(hash))
	}
	return hash, nil
}

// Add basic authentication header to request.
func addBasicAuth(request *http.Request, username, password string) {
	auth := username + ":" + password
	value := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	request.Header.Set("Authorization", value)
}

// Extract list of lines from given server data.
func extractLines(data []byte) ([]string, error) {
	var lines []string
	i := 0
	for j := 0; j < 1000 && i < len(data); j++ {
		length, err := strconv.ParseInt(string(data[i:i+4]), 16, 32)
		if err != nil {
			return nil, fmt.Errorf("expected hex length, got %q", data[i:i+4])
		}
		var line []byte
		if length != 0 {
			line = data[i+4 : i+int(length)]
		}
		lines = append(lines, string(line))
		if length == 0 {
			i += 4
		} else {
			i += int(length)
		}
	}
	return lines, nil
}

// Find sorted list of object hashes in local commit that are missing at the remote.
func findMissingObjects(localHash, remoteHash string) ([]string, error) {
	localObjects, err := findCommitObjects(localHash)
	if err != nil {
		return nil, err
	}
	if remoteHash != "" {
		remoteObjects, err := findCommitObjects(remoteHash)
		if err != nil {
			return nil, err
		}
		for object := range remoteObjects {
			delete(localObjects, object)
		}
	}
	missing := make([]string, 0, len(localObjects))
	for object := range localObjects {
		missing = append(missing, object)
	}
	sort.Strings(missing)
	return missing, nil
}

// Find set of object hashes in this commit (recursively), its tree, its
// parents, and the hash of the commit itself.
func findCommitObjects(commitHash string) (map[string]struct{}, error) {
	objects := map[string]struct{}{commitHash: {}}
	objType, data, err := readObject(commitHash)
	if err != nil {
		return nil, err
	}
	if objType != "commit" {
		return nil, fmt.Errorf("expected commit, got %s", objType)
	}
	lines := strings.Split(string(data), "\n")
	tree := ""
	var parents []string
	for _, line := range lines {
		if strings.HasPrefix(line, "tree ") {
			tree = line[5:45]
		} else if strings.HasPrefix(line, "parent ") {
			parents = append(parents, line[7:47])
		}
	}
	if tree == "" {
		return nil, fmt.Errorf("tree not found in commit %s", commitHash)
	}
	treeObjects, err := findTreeObjects(tree)
	if err != nil {
		return nil, err
	}
	for object := range treeObjects {
		objects[object] = struct{}{}
	}
	for _, parent := range parents {
		parentObjects, err := findCommitObjects(parent)
		if err != nil {
			return nil, err
		}
		for object := range parentObjects {
			objects[object] = struct{}{}
		}
	}
	return objects, nil
}

// Find set of object hashes in this tree (recursively), including the hash
// of the tree itself.
func findTreeObjects(treeHash string) (map[string]struct{}, error) {
	objects := map[string]struct{}{treeHash: {}}
	entries, err := readTree(treeHash)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.isDir {
			subObjects, err := findTreeObjects(entry.hash)
			if err != nil {
				return nil, err
			}
			for object := range subObjects {
				objects[object] = struct{}{}
			}
		} else {
			objects[entry.hash] = struct{}{}
		}
	}
	return objects, nil
}

type treeEntry struct {
	isDir bool
	hash  string
}

// Read list of entries in tree object.
func readTree(treeHash string) ([]treeEntry, error) {
	objType, data, err := readObject(treeHash)
	if err != nil {
		return nil, err
	}
	if objType != "tree" {
		return nil, fmt.Errorf("expected tree, got %s", objType)
	}
	var entries []treeEntry
	i := 0
	for j := 0; j < 1000; j++ {
		end := bytes.IndexByte(data[i:], 0)
		if end < 0 {
			break
		}
		chunk := string(data[i : i+end])
		modeStr, _, ok := strings.Cut(chunk, " ")
		if !ok {
			return nil, fmt.Errorf("expected space in %q", chunk)
		}
		mode, err := strconv.ParseInt(modeStr, 8, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid mode %q", modeStr)
		}
		digest := data[i+end+1 : i+end+21]
		entries = append(entries, treeEntry{isDir: mode&0o040000 != 0, hash: hex.EncodeToString(digest)})
		i += end + 1 + 20
	}
	return entries, nil
}

// Create pack file containing all objects in given list of object hashes.
func createPack(objects []string) ([]byte, error) {
	var buf bytes.Buffer
	header := []byte("PACK")
	header = binary.BigEndian.AppendUint32(header, 2)
	header = binary.BigEndian.AppendUint32(header, uint32(len(objects)))
	buf.Write(header)
	for _, object := range objects {
		data, err := encodePackObject(object)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "encoded pack object %s, %d bytes\n", object, len(data))
		buf.Write(data)
	}
	sha := sha1.New()
	sha.Write(buf.Bytes())
	buf.Write(sha.Sum(nil))
	return buf.Bytes(), nil
}

// Encode a single object in pack file.
func encodePackObject(object string) ([]byte, error) {
	objType, data, err := readObject(object)
	if err != nil {
		return nil, err
	}
	typeNum := objTypes[objType]
	size := len(data)
	b := byte(typeNum<<4) | byte(size&0x0f)
	size >>= 4
	var header []byte
	for size != 0 {
		header = append(header, b|0x80)
		b = byte(size & 0x7f)
		size >>= 7
	}
	header = append(header, b)
	compressed, err := compress(data)
	if err != nil {
		return nil, err
	}
	return append(header, compressed...), nil
}

var objTypes = map[string]int{"commit": 1, "tree": 2, "blob": 3}

// Helper to zlib-compress a slice of bytes.
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	compressor := zlib.NewWriter(&buf)
	_, err := compressor.Write(data)
	if err != nil {
		return nil, err
	}
	err = compressor.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
