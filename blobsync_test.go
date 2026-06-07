package blobsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/nats-io/nats.go"
)

func sha256HexOf(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ---- validateAdvertiseAddress ----

func TestValidateAdvertiseAddress(t *testing.T) {
	cases := []struct {
		addr    string
		wantErr string
	}{
		{"192.168.1.1:8080", ""},
		{"10.0.0.1:443", ""},
		{"myhost.internal:9000", ""},
		{"", "host:port"},
		{"noport", "host:port"},
		{":8080", "host is required"},
		{"localhost:8080", "not localhost"},
		{"127.0.0.1:8080", "loopback"},
		{"0.0.0.0:8080", "wildcard"},
		{"192.168.1.1:0", "range 1..65535"},
		{"192.168.1.1:65536", "range 1..65535"},
		{"192.168.1.1:abc", "range 1..65535"},
	}
	for _, c := range cases {
		err := validateAdvertiseAddress(c.addr)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("addr=%q: unexpected error: %v", c.addr, err)
			}
		} else {
			if err == nil {
				t.Errorf("addr=%q: expected error containing %q, got nil", c.addr, c.wantErr)
			} else if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("addr=%q: error %q does not contain %q", c.addr, err.Error(), c.wantErr)
			}
		}
	}
}

// ---- New validation ----

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, mock
}

func validConfig(db *sql.DB) Config {
	return Config{
		Node:             "node1",
		DB:               db,
		BindAddress:      "127.0.0.1:0",
		AdvertiseAddress: "10.0.0.1:8080",
	}
}

func TestNew_MissingNode(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = ""
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "node is required") {
		t.Fatalf("expected 'node is required', got: %v", err)
	}
}

func TestNew_MissingDB(t *testing.T) {
	_, err := New(Config{Node: "n1", BindAddress: "127.0.0.1:0", AdvertiseAddress: "10.0.0.1:8080"})
	if err == nil || !strings.Contains(err.Error(), "DB is required") {
		t.Fatalf("expected 'DB is required', got: %v", err)
	}
}

func TestNew_SubjectWithoutNATS(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.Subject = "events"
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "nats connection is required") {
		t.Fatalf("expected nats connection error, got: %v", err)
	}
}

func TestNew_MissingBindAddress(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.BindAddress = ""
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "bind address is required") {
		t.Fatalf("expected bind address error, got: %v", err)
	}
}

func TestNew_BadBindAddress(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.BindAddress = "notanaddress"
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "bind address must be host:port") {
		t.Fatalf("expected bind address format error, got: %v", err)
	}
}

func TestNew_MissingAdvertiseAddress(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.AdvertiseAddress = ""
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "advertise address is required") {
		t.Fatalf("expected advertise address error, got: %v", err)
	}
}

func TestNew_InvalidAdvertiseAddress(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.AdvertiseAddress = "localhost:9000"
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for localhost advertise address")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	db, _ := newMockDB(t)
	bs, err := New(validConfig(db))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if bs.cfg.ResyncWorkers != DefaultResyncWorkers {
		t.Errorf("ResyncWorkers default: got %d, want %d", bs.cfg.ResyncWorkers, DefaultResyncWorkers)
	}
	if bs.cfg.HTTPClient == nil {
		t.Error("HTTPClient should be set by default")
	}
	if !filepath.IsAbs(bs.cfg.StoragePath) {
		t.Fatalf("StoragePath should be absolute, got %q", bs.cfg.StoragePath)
	}
	if filepath.Base(bs.cfg.StoragePath) != DefaultStoragePath {
		t.Fatalf("StoragePath default = %q, want path ending in %q", bs.cfg.StoragePath, DefaultStoragePath)
	}
}

func TestNew_RejectsDotStoragePath(t *testing.T) {
	db, _ := newMockDB(t)
	for _, storagePath := range []string{".", "./", "data/.."} {
		cfg := validConfig(db)
		cfg.StoragePath = storagePath
		_, err := New(cfg)
		if err == nil || !strings.Contains(err.Error(), "storage path must not be empty or .") {
			t.Fatalf("StoragePath=%q: expected storage path error, got %v", storagePath, err)
		}
	}
}

func TestNew_NormalizesStorageHTTPPrefixAndACL(t *testing.T) {
	db, _ := newMockDB(t)
	dir := t.TempDir()
	cfg := validConfig(db)
	cfg.StoragePath = dir
	cfg.HTTPPrefix = "blob-files/"
	acl := ACL{
		Whitelist: []string{"images", "images/"},
		Blacklist: []string{"images/tmp"},
	}

	bs, err := New(cfg, WithACL(acl))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !filepath.IsAbs(bs.cfg.StoragePath) {
		t.Fatalf("StoragePath should be absolute, got %q", bs.cfg.StoragePath)
	}
	if bs.cfg.HTTPPrefix != "/blob-files" {
		t.Fatalf("HTTPPrefix = %q, want /blob-files", bs.cfg.HTTPPrefix)
	}
	if !bs.allowedFilename("images/photo.jpg") {
		t.Fatal("expected whitelisted file to be allowed")
	}
	if bs.allowedFilename("docs/readme.txt") {
		t.Fatal("expected non-whitelisted file to be denied")
	}
	if bs.allowedFilename("images/tmp/cache.bin") {
		t.Fatal("expected blacklisted file to be denied")
	}
}

func TestResolveInputFilename_WithStoragePath(t *testing.T) {
	db, _ := newMockDB(t)
	dir := t.TempDir()
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	name, path, err := bs.resolveInputFilename(filepath.Join(dir, "nested", "file.bin"))
	if err != nil {
		t.Fatalf("resolve absolute under storage: %v", err)
	}
	if name != "nested/file.bin" {
		t.Fatalf("name = %q, want nested/file.bin", name)
	}
	if path != filepath.Join(dir, "nested", "file.bin") {
		t.Fatalf("path = %q", path)
	}

	if _, _, err := bs.resolveInputFilename(filepath.Join(filepath.Dir(dir), "outside.bin")); err == nil {
		t.Fatal("expected error for path outside StoragePath")
	}
	if _, _, err := bs.resolveInputFilename("../outside.bin"); err == nil {
		t.Fatal("expected error for relative path escaping StoragePath")
	}
}

func TestStart_ExistingNodeACLChangedRunsResync(t *testing.T) {
	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.BindAddress = "127.0.0.1:0"
	bs, err := New(cfg, WithACL(ACL{Whitelist: []string{"public/"}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bs.Close()

	mock.ExpectQuery(`SELECT lasteventid, aclsha256 FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnRows(sqlmock.NewRows([]string{"lasteventid", "aclsha256"}).AddRow(int64(7), strings.Repeat("0", 64)))
	mock.ExpectQuery(`SELECT MAX\(id\) FROM bsevents`).
		WillReturnRows(sqlmock.NewRows([]string{"MAX(id)"}).AddRow(int64(12)))
	mock.ExpectQuery(`SELECT MAX\(id\) FROM bsfiles`).
		WillReturnRows(sqlmock.NewRows([]string{"MAX(id)"}).AddRow(int64(0)))
	mock.ExpectExec(`UPDATE bsnodes SET address = \?, lasteventid = \?, aclsha256 = \?, lastseen = NOW\(\) WHERE node = \?`).
		WithArgs("10.0.0.1:8080", int64(12), bs.aclHash(), "testnode").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := bs.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestStart_ExistingNodeSameACLSkipsResync(t *testing.T) {
	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.BindAddress = "127.0.0.1:0"
	bs, err := New(cfg, WithACL(ACL{Whitelist: []string{"public/"}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bs.Close()

	mock.ExpectQuery(`SELECT lasteventid, aclsha256 FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnRows(sqlmock.NewRows([]string{"lasteventid", "aclsha256"}).AddRow(int64(7), bs.aclHash()))
	mock.ExpectExec(`UPDATE bsnodes SET address = \?, aclsha256 = \?, lastseen = NOW\(\) WHERE node = \?`).
		WithArgs("10.0.0.1:8080", bs.aclHash(), "testnode").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := bs.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestStart_FirstNodeBootstrapsStorageWithoutEvents(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "public", "file.bin")
	privatePath := filepath.Join(dir, "private.bin")
	content := []byte("bootstrap")
	if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.BindAddress = "127.0.0.1:0"
	cfg.StoragePath = dir
	bs, err := New(cfg, WithACL(ACL{Whitelist: []string{"public/"}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bs.Close()

	mock.ExpectQuery(`SELECT lasteventid, aclsha256 FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM bsnodes`).
		WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(int64(0)))
	mock.ExpectExec(`INSERT INTO bsfiles`).
		WithArgs("public/file.bin", int64(len(content)), sha256HexOf(content)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT MAX\(id\) FROM bsevents`).
		WillReturnRows(sqlmock.NewRows([]string{"MAX(id)"}).AddRow(nil))
	mock.ExpectQuery(`SELECT MAX\(id\) FROM bsfiles`).
		WillReturnRows(sqlmock.NewRows([]string{"MAX(id)"}).AddRow(int64(1)))
	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles`).
		WithArgs(int64(0), int64(1), DefaultResyncBatch).
		WillReturnRows(sqlmock.NewRows([]string{"id", "filename", "size", "sha256", "datedeleted"}).
			AddRow(int64(1), "public/file.bin", int64(len(content)), sha256HexOf(content), nil))
	mock.ExpectExec(`INSERT INTO bsnodes SET node = \?, address = \?, lasteventid = \?, aclsha256 = \?, lastseen = NOW\(\)`).
		WithArgs("testnode", "10.0.0.1:8080", int64(0), bs.aclHash()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := bs.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestStart_CanceledContext(t *testing.T) {
	db, _ := newMockDB(t)
	bs, err := New(validConfig(db))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bs.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// ---- copyWithContext ----

func TestCopyWithContext_Basic(t *testing.T) {
	data := []byte("hello blobsync world")
	var buf bytes.Buffer
	n, err := copyWithContext(context.Background(), &buf, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("copied %d bytes, want %d", n, len(data))
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("content mismatch")
	}
}

func TestCopyWithContext_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := bytes.NewReader(bytes.Repeat([]byte("x"), 1024*1024))
	var buf bytes.Buffer
	_, err := copyWithContext(ctx, &buf, r)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestCopyWithContext_Empty(t *testing.T) {
	var buf bytes.Buffer
	n, err := copyWithContext(context.Background(), &buf, bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
}

// ---- hashFileContext ----

func TestHashFileContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.bin")
	data := []byte("blobsync hash test")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	sum, err := hashFileContext(context.Background(), path)
	if err != nil {
		t.Fatalf("hashFileContext: %v", err)
	}
	if len(sum) != 64 {
		t.Errorf("expected 64-char hex digest, got %d chars", len(sum))
	}
	if sum != sha256HexOf(data) {
		t.Errorf("hash mismatch: got %s, want %s", sum, sha256HexOf(data))
	}

	sum2, _ := hashFileContext(context.Background(), path)
	if sum != sum2 {
		t.Error("hash not deterministic")
	}
}

func TestHashFileContext_Missing(t *testing.T) {
	_, err := hashFileContext(context.Background(), "/nonexistent/path/file.bin")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---- handleFile ----

func makeBS(t *testing.T, db *sql.DB) *BlobSync {
	t.Helper()
	bs, err := New(Config{
		Node:             "testnode",
		DB:               db,
		BindAddress:      "127.0.0.1:0",
		AdvertiseAddress: "10.0.0.1:9090",
		StoragePath:      t.TempDir(),
		HTTPClient:       &http.Client{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return bs
}

func TestHandleFile_BadID(t *testing.T) {
	db, _ := newMockDB(t)
	bs := makeBS(t, db)

	for _, path := range []string{"/", "/abc", "/-1", "/0"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		bs.handleFile(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("path=%q: expected 400, got %d", path, rr.Code)
		}
	}
}

func TestHandleFile_NotFound(t *testing.T) {
	db, mock := newMockDB(t)
	bs := makeBS(t, db)

	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id = ?`).
		WithArgs(int64(42)).
		WillReturnError(sql.ErrNoRows)

	req := httptest.NewRequest(http.MethodGet, "/42", nil)
	rr := httptest.NewRecorder()
	bs.handleFile(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleFile_InternalErrorIsGeneric(t *testing.T) {
	db, mock := newMockDB(t)
	logger := &testLogger{}
	bs := makeBS(t, db)
	bs.cfg.Logger = logger

	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id = ?`).
		WithArgs(int64(42)).
		WillReturnError(errors.New("db password leaked in error"))

	req := httptest.NewRequest(http.MethodGet, "/42", nil)
	rr := httptest.NewRecorder()
	bs.handleFile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "db password") {
		t.Fatalf("response leaked internal error: %q", rr.Body.String())
	}
	if !strings.Contains(logger.String(), "db password leaked in error") {
		t.Fatalf("expected internal error to be logged, got %q", logger.String())
	}
}

func TestHandleFile_DeletedFile(t *testing.T) {
	db, mock := newMockDB(t)
	bs := makeBS(t, db)

	rows := sqlmock.NewRows([]string{"id", "filename", "size", "sha256", "datedeleted"}).
		AddRow(int64(7), "/some/file.bin", int64(100), "aabbcc", time.Now())

	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id = ?`).
		WithArgs(int64(7)).
		WillReturnRows(rows)

	req := httptest.NewRequest(http.MethodGet, "/7", nil)
	rr := httptest.NewRecorder()
	bs.handleFile(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for deleted file, got %d", rr.Code)
	}
}

func TestHandleFile_ServesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	content := []byte("hello from blobsync")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rows := sqlmock.NewRows([]string{"id", "filename", "size", "sha256", "datedeleted"}).
		AddRow(int64(1), "hello.txt", int64(len(content)), sha256HexOf(content), nil)

	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id = ?`).
		WithArgs(int64(1)).
		WillReturnRows(rows)

	req := httptest.NewRequest(http.MethodGet, "/1", nil)
	rr := httptest.NewRecorder()
	bs.handleFile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Equal(rr.Body.Bytes(), content) {
		t.Errorf("body mismatch")
	}
}

func TestHandleFile_UnsafeFilenameIsGeneric(t *testing.T) {
	db, mock := newMockDB(t)
	logger := &testLogger{}
	bs := makeBS(t, db)
	bs.cfg.Logger = logger

	rows := sqlmock.NewRows([]string{"id", "filename", "size", "sha256", "datedeleted"}).
		AddRow(int64(7), "../secret.bin", int64(100), "aabbcc", nil)

	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id = ?`).
		WithArgs(int64(7)).
		WillReturnRows(rows)

	req := httptest.NewRequest(http.MethodGet, "/7", nil)
	rr := httptest.NewRecorder()
	bs.handleFile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "unsafe filename") || strings.Contains(rr.Body.String(), "../secret.bin") {
		t.Fatalf("response leaked internal error: %q", rr.Body.String())
	}
	if !strings.Contains(logger.String(), "unsafe filename") {
		t.Fatalf("expected internal error to be logged, got %q", logger.String())
	}
}

func TestHandleFile_WithStoragePathAndHTTPPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	content := []byte("hello from storage")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = dir
	cfg.HTTPPrefix = "/files"
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rows := sqlmock.NewRows([]string{"id", "filename", "size", "sha256", "datedeleted"}).
		AddRow(int64(1), "hello.txt", int64(len(content)), sha256HexOf(content), nil)

	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id = ?`).
		WithArgs(int64(1)).
		WillReturnRows(rows)

	req := httptest.NewRequest(http.MethodGet, "/files/1", nil)
	rr := httptest.NewRecorder()
	bs.handleFile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Equal(rr.Body.Bytes(), content) {
		t.Errorf("body mismatch")
	}
}

// ---- downloadFrom ----

func TestDownloadFrom_Success(t *testing.T) {
	dir := t.TempDir()
	content := []byte("downloaded content")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/objects/1" {
			t.Errorf("request path = %q, want /objects/1", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs.cfg.HTTPClient = srv.Client()
	bs.cfg.HTTPPrefix = "/objects"

	rec := fileRecord{
		ID:       1,
		Filename: "out.bin",
		Size:     int64(len(content)),
		SHA256:   sha256HexOf(content),
	}
	node := nodeAddress{Node: "peer", Address: strings.TrimPrefix(srv.URL, "http://")}
	if err := bs.downloadFrom(context.Background(), node, rec); err != nil {
		t.Fatalf("downloadFrom: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "out.bin"))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch")
	}
}

func TestDownloadFrom_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	db, _ := newMockDB(t)
	dir := t.TempDir()
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs.cfg.HTTPClient = srv.Client()

	rec := fileRecord{ID: 2, Filename: "f.bin", Size: 10, SHA256: "x"}
	node := nodeAddress{Node: "peer", Address: strings.TrimPrefix(srv.URL, "http://")}
	err = bs.downloadFrom(context.Background(), node, rec)
	if err == nil || !strings.Contains(err.Error(), "410") {
		t.Errorf("expected 410 error, got: %v", err)
	}
}

func TestDownloadFrom_SizeMismatch(t *testing.T) {
	content := []byte("short")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	db, _ := newMockDB(t)
	dir := t.TempDir()
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs.cfg.HTTPClient = srv.Client()

	rec := fileRecord{ID: 3, Filename: "f.bin", Size: 999, SHA256: sha256HexOf(content)}
	node := nodeAddress{Node: "peer", Address: strings.TrimPrefix(srv.URL, "http://")}
	err = bs.downloadFrom(context.Background(), node, rec)
	if err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Errorf("expected size mismatch error, got: %v", err)
	}
}

func TestDownloadFrom_SHA256Mismatch(t *testing.T) {
	content := []byte("real content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	db, _ := newMockDB(t)
	dir := t.TempDir()
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs.cfg.HTTPClient = srv.Client()

	rec := fileRecord{ID: 4, Filename: "f.bin", Size: int64(len(content)), SHA256: strings.Repeat("0", 64)}
	node := nodeAddress{Node: "peer", Address: strings.TrimPrefix(srv.URL, "http://")}
	err = bs.downloadFrom(context.Background(), node, rec)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("expected sha256 mismatch error, got: %v", err)
	}
}

// ---- applyEvents ----

func TestApplyEvents_SkipsOwnEvents(t *testing.T) {
	db, mock := newMockDB(t)
	bs := makeBS(t, db)

	mock.ExpectQuery(`SELECT lasteventid FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnRows(sqlmock.NewRows([]string{"lasteventid"}).AddRow(int64(0)))

	mock.ExpectQuery(`SELECT id, node, eventtype, fileid FROM bsevents WHERE id > ?`).
		WithArgs(int64(0), applyEventsBatch).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node", "eventtype", "fileid"}).
			AddRow(int64(1), "testnode", "add", int64(10)))

	mock.ExpectExec(`UPDATE bsnodes SET lasteventid`).
		WithArgs(int64(1), sqlmock.AnyArg(), "testnode").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := bs.applyEvents(context.Background()); err != nil {
		t.Fatalf("applyEvents: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestApplyEvents_RemoveDeletesLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "todelete.bin")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mock.ExpectQuery(`SELECT lasteventid FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnRows(sqlmock.NewRows([]string{"lasteventid"}).AddRow(int64(0)))

	mock.ExpectQuery(`SELECT id, node, eventtype, fileid FROM bsevents WHERE id > ?`).
		WithArgs(int64(0), applyEventsBatch).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node", "eventtype", "fileid"}).
			AddRow(int64(5), "othernode", "remove", int64(99)))

	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id IN \(\?\)`).
		WithArgs(int64(99)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "filename", "size", "sha256", "datedeleted"}).
			AddRow(int64(99), "todelete.bin", int64(4), "abc", nil))

	mock.ExpectExec(`UPDATE bsnodes SET lasteventid`).
		WithArgs(int64(5), sqlmock.AnyArg(), "testnode").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := bs.applyEvents(context.Background()); err != nil {
		t.Fatalf("applyEvents: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("expected file to be removed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestApplyEvents_LoadsEventFilesInOneQuery(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.bin")
	secondPath := filepath.Join(dir, "second.bin")
	if err := os.WriteFile(firstPath, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mock.ExpectQuery(`SELECT lasteventid FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnRows(sqlmock.NewRows([]string{"lasteventid"}).AddRow(int64(0)))
	mock.ExpectQuery(`SELECT id, node, eventtype, fileid FROM bsevents WHERE id > ?`).
		WithArgs(int64(0), applyEventsBatch).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node", "eventtype", "fileid"}).
			AddRow(int64(5), "othernode", "remove", int64(99)).
			AddRow(int64(6), "othernode", "remove", int64(100)))
	mock.ExpectQuery(`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id IN \(\?,\?\)`).
		WithArgs(int64(99), int64(100)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "filename", "size", "sha256", "datedeleted"}).
			AddRow(int64(99), "first.bin", int64(5), "abc", nil).
			AddRow(int64(100), "second.bin", int64(6), "def", nil))
	mock.ExpectExec(`UPDATE bsnodes SET lasteventid`).
		WithArgs(int64(6), sqlmock.AnyArg(), "testnode").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := bs.applyEvents(context.Background()); err != nil {
		t.Fatalf("applyEvents: %v", err)
	}
	if _, err := os.Stat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected first file to be removed")
	}
	if _, err := os.Stat(secondPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected second file to be removed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyEvents_UnknownEventType(t *testing.T) {
	db, mock := newMockDB(t)
	bs := makeBS(t, db)

	mock.ExpectQuery(`SELECT lasteventid FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnRows(sqlmock.NewRows([]string{"lasteventid"}).AddRow(int64(0)))

	mock.ExpectQuery(`SELECT id, node, eventtype, fileid FROM bsevents WHERE id > ?`).
		WithArgs(int64(0), applyEventsBatch).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node", "eventtype", "fileid"}).
			AddRow(int64(3), "othernode", "bogus", int64(1)))

	err := bs.applyEvents(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown event type") {
		t.Errorf("expected unknown event type error, got: %v", err)
	}
}

func TestApplyEvents_NoEvents(t *testing.T) {
	db, mock := newMockDB(t)
	bs := makeBS(t, db)

	mock.ExpectQuery(`SELECT lasteventid FROM bsnodes WHERE node = ?`).
		WithArgs("testnode").
		WillReturnRows(sqlmock.NewRows([]string{"lasteventid"}).AddRow(int64(100)))

	mock.ExpectQuery(`SELECT id, node, eventtype, fileid FROM bsevents WHERE id > ?`).
		WithArgs(int64(100), applyEventsBatch).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node", "eventtype", "fileid"}))

	if err := bs.applyEvents(context.Background()); err != nil {
		t.Fatalf("applyEvents with no events: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---- resyncOne ----

func TestResyncOne_DeletedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deleted.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := fileRecord{
		ID:          1,
		Filename:    "deleted.bin",
		DateDeleted: sql.NullTime{Time: time.Now(), Valid: true},
	}
	if err := bs.resyncOne(context.Background(), rec, 0); err != nil {
		t.Fatalf("resyncOne: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("expected file to be removed")
	}
}

func TestResyncOne_LocalFileOK(t *testing.T) {
	dir := t.TempDir()
	content := []byte("matching content")
	path := filepath.Join(dir, "ok.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := fileRecord{
		ID:       2,
		Filename: "ok.bin",
		Size:     int64(len(content)),
		SHA256:   sha256HexOf(content),
	}
	if err := bs.resyncOne(context.Background(), rec, 0); err != nil {
		t.Fatalf("resyncOne: %v", err)
	}
}

func TestResyncOne_DeletedFile_AlreadyGone(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = t.TempDir()
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := fileRecord{
		ID:          3,
		Filename:    "nonexistent/file.bin",
		DateDeleted: sql.NullTime{Time: time.Now(), Valid: true},
	}
	// ErrNotExist should be tolerated.
	if err := bs.resyncOne(context.Background(), rec, 0); err != nil {
		t.Fatalf("resyncOne on already-gone file: %v", err)
	}
}

func TestResyncOne_DeniedByACLRemovesLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private", "nested", "secret.bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.Node = "testnode"
	cfg.StoragePath = dir
	bs, err := New(cfg, WithACL(ACL{Whitelist: []string{"public/"}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := fileRecord{
		ID:       10,
		Filename: "private/nested/secret.bin",
		Size:     int64(len("secret")),
		SHA256:   sha256HexOf([]byte("secret")),
	}
	if err := bs.resyncOne(context.Background(), rec, 0); err != nil {
		t.Fatalf("resyncOne: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected denied file to be removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "private")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected empty parent directories to be removed, got %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("storage root should remain: %v", err)
	}
}

func TestRemoveLocalFile_RejectsPathTraversalFromDB(t *testing.T) {
	dir := t.TempDir()
	outsidePath := filepath.Join(filepath.Dir(dir), "outside.bin")
	if err := os.WriteFile(outsidePath, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = bs.removeLocalFile(fileRecord{Filename: "../outside.bin"})
	if err == nil || !strings.Contains(err.Error(), "unsafe filename") {
		t.Fatalf("expected unsafe filename error, got %v", err)
	}
	if _, err := os.Stat(outsidePath); err != nil {
		t.Fatalf("outside file should remain: %v", err)
	}
}

func TestLocalPath_RejectsAbsoluteFilenameFromDB(t *testing.T) {
	db, _ := newMockDB(t)
	cfg := validConfig(db)
	cfg.StoragePath = t.TempDir()
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := bs.localPath("/etc/passwd"); err == nil || !strings.Contains(err.Error(), "unsafe filename") {
		t.Fatalf("expected unsafe filename error, got %v", err)
	}
}

func TestScan_AddsNewAllowedFilesWithoutNATS(t *testing.T) {
	dir := t.TempDir()
	existingPath := filepath.Join(dir, "allowed", "existing.bin")
	newPath := filepath.Join(dir, "allowed", "new.bin")
	deniedPath := filepath.Join(dir, "denied.bin")
	newContent := []byte("new file")
	if err := os.MkdirAll(filepath.Dir(existingPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existingPath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, newContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deniedPath, []byte("denied"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.StoragePath = dir
	cfg.NATS = &nats.Conn{}
	cfg.Subject = "events"
	bs, err := New(cfg, WithACL(ACL{Whitelist: []string{"allowed/"}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	oldPublish := publishNATS
	publishNATS = func(conn *nats.Conn, subject string, data []byte) error {
		t.Fatal("Scan must not publish to NATS")
		return nil
	}
	t.Cleanup(func() { publishNATS = oldPublish })

	mock.ExpectQuery(`SELECT id, datedeleted FROM bsfiles WHERE filename = \?`).
		WithArgs("allowed/existing.bin").
		WillReturnRows(sqlmock.NewRows([]string{"id", "datedeleted"}).AddRow(int64(10), nil))
	mock.ExpectQuery(`SELECT id, datedeleted FROM bsfiles WHERE filename = \?`).
		WithArgs("allowed/new.bin").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO bsfiles`).
		WithArgs("allowed/new.bin", int64(len(newContent)), sha256HexOf(newContent)).
		WillReturnResult(sqlmock.NewResult(11, 1))
	mock.ExpectExec(`INSERT INTO bsevents`).
		WithArgs("node1", "add", int64(11)).
		WillReturnResult(sqlmock.NewResult(100, 1))
	mock.ExpectCommit()

	if err := bs.Scan(context.Background()); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	select {
	case <-bs.reconcileKick:
	default:
		t.Fatal("Scan should kick reconcile after creating events")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestScan_ReaddsDeletedFileWithEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deleted.bin")
	content := []byte("restored")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mock.ExpectQuery(`SELECT id, datedeleted FROM bsfiles WHERE filename = \?`).
		WithArgs("deleted.bin").
		WillReturnRows(sqlmock.NewRows([]string{"id", "datedeleted"}).AddRow(int64(7), time.Now()))
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO bsfiles`).
		WithArgs("deleted.bin", int64(len(content)), sha256HexOf(content)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO bsevents`).
		WithArgs("node1", "add", int64(7)).
		WillReturnResult(sqlmock.NewResult(101, 1))
	mock.ExpectCommit()

	if err := bs.Scan(context.Background()); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCleanup_RemovesFilesMissingOrDeletedInDB(t *testing.T) {
	dir := t.TempDir()
	keepPath := filepath.Join(dir, "keep.bin")
	deletedPath := filepath.Join(dir, "deleted.bin")
	orphanPath := filepath.Join(dir, "nested", "orphan.bin")
	if err := os.WriteFile(keepPath, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deletedPath, []byte("deleted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(orphanPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphanPath, []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.StoragePath = dir
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rows := sqlmock.NewRows([]string{"filename", "datedeleted"}).
		AddRow("keep.bin", nil).
		AddRow("deleted.bin", time.Now())
	mock.ExpectQuery(`SELECT filename, datedeleted FROM bsfiles WHERE filename IN \(\?,\?,\?\)`).
		WithArgs("deleted.bin", "keep.bin", "nested/orphan.bin").
		WillReturnRows(rows)

	if err := bs.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(keepPath); err != nil {
		t.Fatalf("expected keep file to remain: %v", err)
	}
	if _, err := os.Stat(deletedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected deleted DB file to be removed, got %v", err)
	}
	if _, err := os.Stat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected orphan file to be removed, got %v", err)
	}
	if _, err := os.Stat(filepath.Dir(orphanPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected cleanup to remove empty directories, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCleanup_UsesDefaultStoragePath(t *testing.T) {
	db, _ := newMockDB(t)
	bs, err := New(validConfig(db))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if filepath.Base(bs.cfg.StoragePath) != DefaultStoragePath {
		t.Fatalf("StoragePath default = %q, want path ending in %q", bs.cfg.StoragePath, DefaultStoragePath)
	}
}

func TestCleanup_MissingStoragePathIsNoop(t *testing.T) {
	db, mock := newMockDB(t)
	cfg := validConfig(db)
	cfg.StoragePath = filepath.Join(t.TempDir(), "missing")
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := bs.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAddFile_PublishErrorAfterCommitIsLoggedOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.bin")
	content := []byte("content")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	db, mock := newMockDB(t)
	logger := &testLogger{}
	cfg := validConfig(db)
	cfg.StoragePath = dir
	cfg.NATS = &nats.Conn{}
	cfg.Subject = "events"
	cfg.Logger = logger
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	oldPublish := publishNATS
	publishNATS = func(conn *nats.Conn, subject string, data []byte) error {
		if subject != "events" {
			t.Fatalf("subject = %q, want events", subject)
		}
		var msg natsEventMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("unmarshal nats payload: %v", err)
		}
		if msg.EventID != 99 || msg.Filename != "file.bin" {
			t.Fatalf("nats payload = %+v, want event 99 file.bin", msg)
		}
		return errors.New("nats down")
	}
	t.Cleanup(func() { publishNATS = oldPublish })

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO bsfiles`).
		WithArgs("file.bin", int64(len(content)), sha256HexOf(content)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO bsevents`).
		WithArgs("node1", "add", int64(1)).
		WillReturnResult(sqlmock.NewResult(99, 1))
	mock.ExpectCommit()

	if err := bs.AddFile(context.Background(), "file.bin"); err != nil {
		t.Fatalf("AddFile returned publish error after commit: %v", err)
	}
	if !strings.Contains(logger.String(), "publish add event 99 failed") {
		t.Fatalf("expected publish error to be logged, got %q", logger.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRemoveFile_PublishErrorAfterCommitIsLoggedOnly(t *testing.T) {
	dir := t.TempDir()
	db, mock := newMockDB(t)
	logger := &testLogger{}
	cfg := validConfig(db)
	cfg.StoragePath = dir
	cfg.NATS = &nats.Conn{}
	cfg.Subject = "events"
	cfg.Logger = logger
	bs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	oldPublish := publishNATS
	publishNATS = func(conn *nats.Conn, subject string, data []byte) error {
		if subject != "events" {
			t.Fatalf("subject = %q, want events", subject)
		}
		var msg natsEventMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("unmarshal nats payload: %v", err)
		}
		if msg.EventID != 77 || msg.Filename != "file.bin" {
			t.Fatalf("nats payload = %+v, want event 77 file.bin", msg)
		}
		return errors.New("nats down")
	}
	t.Cleanup(func() { publishNATS = oldPublish })

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM bsfiles WHERE filename = \? AND datedeleted IS NULL`).
		WithArgs("file.bin").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(12)))
	mock.ExpectExec(`UPDATE bsfiles SET datedeleted = NOW\(\) WHERE id = ?`).
		WithArgs(int64(12)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO bsevents`).
		WithArgs("node1", "remove", int64(12)).
		WillReturnResult(sqlmock.NewResult(77, 1))
	mock.ExpectCommit()

	if err := bs.RemoveFile(context.Background(), "file.bin"); err != nil {
		t.Fatalf("RemoveFile returned publish error after commit: %v", err)
	}
	if !strings.Contains(logger.String(), "publish remove event 77 failed") {
		t.Fatalf("expected publish error to be logged, got %q", logger.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestHandleNATSMessage_SkipsDeniedFilename(t *testing.T) {
	db, _ := newMockDB(t)
	bs, err := New(validConfig(db), WithACL(ACL{Whitelist: []string{"public/"}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data, err := json.Marshal(natsEventMessage{EventID: 1, Filename: "private/file.bin"})
	if err != nil {
		t.Fatal(err)
	}
	bs.handleNATSMessage(&nats.Msg{Data: data})

	select {
	case <-bs.reconcileKick:
		t.Fatal("denied filename should not kick reconcile")
	default:
	}
}

func TestHandleNATSMessage_KicksAllowedOrLegacyMessage(t *testing.T) {
	db, _ := newMockDB(t)
	bs, err := New(validConfig(db), WithACL(ACL{Whitelist: []string{"public/"}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data, err := json.Marshal(natsEventMessage{EventID: 1, Filename: "public/file.bin"})
	if err != nil {
		t.Fatal(err)
	}
	bs.handleNATSMessage(&nats.Msg{Data: data})
	select {
	case <-bs.reconcileKick:
	default:
		t.Fatal("allowed filename should kick reconcile")
	}

	bs.handleNATSMessage(&nats.Msg{Data: []byte("1")})
	select {
	case <-bs.reconcileKick:
	default:
		t.Fatal("legacy message should kick reconcile")
	}
}

// ---- operationContext ----

func TestOperationContext_CancelledBlobSync(t *testing.T) {
	db, _ := newMockDB(t)
	bs := makeBS(t, db)
	bs.cancel() // simulate closed BlobSync

	ctx, cancel := bs.operationContext(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected context to be done when BlobSync is cancelled")
	}
}

func TestOperationContext_NilParent(t *testing.T) {
	db, _ := newMockDB(t)
	bs := makeBS(t, db)

	ctx, cancel := bs.operationContext(context.TODO())
	defer cancel()

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("context should not be cancelled yet: %v", err)
	}
}

// ---- io helpers ----

func TestCopyWithContext_WriterError(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 1024)
	_, err := copyWithContext(context.Background(), &errWriter{}, bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected write error")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type testLogger struct {
	lines []string
}

func (l *testLogger) Printf(format string, v ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, v...))
}

func (l *testLogger) String() string {
	return strings.Join(l.lines, "\n")
}
