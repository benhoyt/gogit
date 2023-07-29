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
	"flag"
	"fmt"
	"io"
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
		fmt.Fprintln(os.Stderr, "usage: gogit init|commit|push [...]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		initRepo()

	case "commit":
		// "gogit commit" is different from "git commit": for simplicity, gogit
		// doesn't maintain the git index (staging area), so you have to
		// specify the list of paths you want committed each time.
		var message string
		flagSet := flag.NewFlagSet("gogit commit -m 'message' paths...", flag.ExitOnError)
		flagSet.StringVar(&message, "m", "", "commit message (required)")
		flagSet.Parse(os.Args[2:])
		if message == "" || len(flagSet.Args()) == 0 {
			flagSet.Usage()
			os.Exit(1)
		}
		authorName := os.Getenv("GIT_AUTHOR_NAME")
		authorEmail := os.Getenv("GIT_AUTHOR_EMAIL")
		if authorName == "" || authorEmail == "" {
			fmt.Fprintln(os.Stderr, "GIT_AUTHOR_NAME and GIT_AUTHOR_EMAIL must be set")
			os.Exit(1)
		}
		author := fmt.Sprintf("%s <%s>", authorName, authorEmail)
		hash := commit(message, author, flagSet.Args())
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
		remote, local, num := push(gitURL, username, password)
		if num == 0 {
			fmt.Printf("local and remote at %s, nothing to update\n", local[:7])
		} else {
			fmt.Printf("updating remote master from %s to %s (%d objects)\n", remote[:7], local[:7], num)
		}

	default:
		fmt.Fprintln(os.Stderr, "usage: gogit init|commit|push [...]")
		os.Exit(2)
	}
}

func check0(err error) {
	if err != nil {
		panic(err)
	}
}

func check[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func assert(cond bool, format string, args ...any) {
	if !cond {
		panic(fmt.Sprintf(format, args...))
	}
}

// Create the directories and files required to initialise a git repo.
func initRepo() {
	for _, name := range []string{".git/objects", ".git/refs/heads"} {
		check0(os.MkdirAll(name, 0o775))
	}
	check0(os.WriteFile(".git/HEAD", []byte("ref: refs/heads/master"), 0o664))
}

// Commit tree of given paths to master, returning the commit hash.
func commit(message, author string, paths []string) string {
	tree := writeTree(paths)
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
	hash := hashObject("commit", data)
	check0(os.WriteFile(".git/refs/heads/master", []byte(hex.EncodeToString(hash)+"\n"), 0o664))
	return hex.EncodeToString(hash)
}

// Write a "tree" object with the given paths (sub-trees are not supported).
func writeTree(paths []string) []byte {
	sort.Strings(paths) // tree object needs paths sorted
	var buf bytes.Buffer
	for _, path := range paths {
		st := check(os.Stat(path))
		assert(!st.IsDir(), "sub-trees not supported")
		data := check(os.ReadFile(path))
		hash := hashObject("blob", data)
		fmt.Fprintf(&buf, "%o %s\x00%s", st.Mode().Perm()|0o100000, path, hash)
	}
	return hashObject("tree", buf.Bytes())
}

// Hash and write the given data as a git object of the given type.
func hashObject(objType string, data []byte) []byte {
	sha := sha1.New()
	header := fmt.Sprintf("%s %d\x00", objType, len(data))
	io.WriteString(sha, header) // these writes can't fail
	sha.Write(data)
	hash := sha.Sum(nil)
	hashStr := hex.EncodeToString(hash)
	path := filepath.Join(".git/objects", hashStr[:2], hashStr[2:])
	if _, err := os.Stat(path); err == nil {
		return hash // file already exists
	}
	check0(os.MkdirAll(filepath.Dir(path), 0o775))
	f := check(os.Create(path))
	compressed := compress(append([]byte(header), data...))
	check(f.Write(compressed))
	check0(f.Close())
	return hash
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
func readObject(hashPrefix string) (objType string, data []byte) {
	path := findObject(hashPrefix)
	f := check(os.Open(path))
	defer f.Close()
	decompressor := check(zlib.NewReader(f))
	var buf bytes.Buffer
	check(io.Copy(&buf, decompressor))
	check0(decompressor.Close())
	fullData := buf.Bytes()
	header, data, ok := bytes.Cut(fullData, []byte{0})
	assert(ok, "invalid object data: no NUL byte")
	objType, sizeStr, ok := strings.Cut(string(header), " ")
	assert(ok, "invalid object header")
	size := check(strconv.Atoi(sizeStr))
	assert(size == len(data), "invalid object: expected size %d, got %d", size, len(data))
	return objType, data
}

// Find object with given hash prefix and return path to object.
func findObject(hashPrefix string) string {
	objDir := filepath.Join(".git/objects", hashPrefix[:2])
	rest := hashPrefix[2:]
	entries, _ := os.ReadDir(objDir)
	var matches []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), rest) {
			matches = append(matches, entry.Name())
		}
	}
	assert(len(matches) > 0, "object %q not found", hashPrefix)
	assert(len(matches) == 1, "multiple objects with prefix %q", hashPrefix)
	return filepath.Join(objDir, matches[0])
}

// Push master branch (and missing objects) to remote.
func push(gitURL, username, password string) (remoteHash, localHash string, num int) {
	client := &http.Client{Timeout: 10 * time.Second}
	remoteHash = getRemoteHash(client, gitURL, username, password)
	localHash = getLocalHash()
	missing := findMissingObjects(localHash, remoteHash)
	if len(missing) == 0 {
		return remoteHash, localHash, 0
	}
	if remoteHash == "" {
		remoteHash = strings.Repeat("0", 40)
	}
	line := fmt.Sprintf("%s %s refs/heads/master\x00 report-status\n", remoteHash, localHash)
	packData := createPack(missing)
	sendData := append([]byte(fmt.Sprintf("%04x%s0000", len(line)+4, line)), packData...)
	request := check(http.NewRequest("POST", gitURL+"/git-receive-pack", bytes.NewReader(sendData)))
	addBasicAuth(request, username, password)
	response := check(client.Do(request))
	defer response.Body.Close()
	data := check(io.ReadAll(response.Body))
	assert(response.StatusCode == 200, "expected status 200, got %d", response.StatusCode)
	lines := extractLines(data)
	assert(lines[0] == "unpack ok\n", `expected line 1 to be "unpack ok\n", got %q`, lines[0])
	assert(lines[1] == "ok refs/heads/master\n", `expected line 2 to be "ok refs/heads/master\n", got %q`, lines[1])
	return remoteHash, localHash, len(missing)
}

// Get current hash of master branch on remote.
func getRemoteHash(client *http.Client, gitURL, username, password string) string {
	request := check(http.NewRequest("GET", gitURL+"/info/refs?service=git-receive-pack", nil))
	addBasicAuth(request, username, password)
	response := check(client.Do(request))
	defer response.Body.Close()
	data := check(io.ReadAll(response.Body))
	assert(response.StatusCode == 200, "expected status 200, got %d", response.StatusCode)
	lines := extractLines(data)
	assert(lines[0] == "# service=git-receive-pack\n", "invalid service line %q", lines[0])
	assert(lines[1] == "", "expected empty second line, got %q", lines[1])
	if lines[2][:40] == strings.Repeat("0", 40) {
		return ""
	}
	hashRef := strings.Split(lines[2], "\x00")[0]
	fields := strings.Fields(hashRef)
	hash, ref := fields[0], fields[1]
	assert(ref == "refs/heads/master", `expected "refs/heads/master", got %q`, ref)
	assert(len(hash) == 40, "expected 40-char hash, got %q (%d)", hash, len(hash))
	return hash
}

// Add basic authentication header to request.
func addBasicAuth(request *http.Request, username, password string) {
	auth := username + ":" + password
	value := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	request.Header.Set("Authorization", value)
}

// Extract list of lines from given server data.
func extractLines(data []byte) []string {
	var lines []string
	for i := 0; i < len(data); {
		length := check(strconv.ParseInt(string(data[i:i+4]), 16, 32))
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
	return lines
}

// Find sorted list of object hashes in local commit that are missing at the remote.
func findMissingObjects(localHash, remoteHash string) []string {
	localObjects := findCommitObjects(localHash)
	if remoteHash != "" {
		remoteObjects := findCommitObjects(remoteHash)
		for object := range remoteObjects {
			delete(localObjects, object)
		}
	}
	missing := make([]string, 0, len(localObjects))
	for object := range localObjects {
		missing = append(missing, object)
	}
	sort.Strings(missing)
	return missing
}

// Find set of object hashes in this commit (recursively), its tree, its
// parents, and the hash of the commit itself.
func findCommitObjects(commitHash string) map[string]struct{} {
	objects := map[string]struct{}{commitHash: {}}
	objType, data := readObject(commitHash)
	assert(objType == "commit", "expected commit, got %s", objType)
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
	assert(tree != "", "tree not found in commit %s", commitHash)
	treeObjects := findTreeObjects(tree)
	for object := range treeObjects {
		objects[object] = struct{}{}
	}
	for _, parent := range parents {
		parentObjects := findCommitObjects(parent)
		for object := range parentObjects {
			objects[object] = struct{}{}
		}
	}
	return objects
}

// Find set of object hashes in this tree, including the hash of the tree itself.
func findTreeObjects(treeHash string) map[string]struct{} {
	objType, data := readObject(treeHash)
	assert(objType == "tree", "expected tree, got %s", objType)
	objects := map[string]struct{}{treeHash: {}}
	for i := 0; ; {
		end := bytes.IndexByte(data[i:], 0)
		if end < 0 {
			return objects
		}
		chunk := string(data[i : i+end])
		modeStr, _, ok := strings.Cut(chunk, " ")
		assert(ok, "expected space in %q", chunk)
		mode := check(strconv.ParseInt(modeStr, 8, 64))
		assert(mode&0o040000 == 0, "sub-trees not supported")
		hash := hex.EncodeToString(data[i+end+1 : i+end+21])
		objects[hash] = struct{}{}
		i += end + 1 + 20
	}
}

// Create pack file containing all objects in given list of object hashes.
func createPack(objects []string) []byte {
	var buf bytes.Buffer
	header := []byte("PACK")
	header = binary.BigEndian.AppendUint32(header, 2)
	header = binary.BigEndian.AppendUint32(header, uint32(len(objects)))
	buf.Write(header)
	for _, object := range objects {
		buf.Write(encodePackObject(object))
	}
	sha := sha1.New()
	sha.Write(buf.Bytes())
	buf.Write(sha.Sum(nil))
	return buf.Bytes()
}

// Encode a single object in pack file.
func encodePackObject(object string) []byte {
	objType, data := readObject(object)
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
	return append(header, compress(data)...)
}

var objTypes = map[string]int{"commit": 1, "tree": 2, "blob": 3}

// Helper to zlib-compress a slice of bytes.
func compress(data []byte) []byte {
	var buf bytes.Buffer
	compressor := zlib.NewWriter(&buf)
	check(compressor.Write(data))
	check0(compressor.Close())
	return buf.Bytes()
}
