package blobsync

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	DefaultResyncWorkers = 4
	DefaultResyncBatch   = 1000
	DefaultStoragePath   = "data"

	applyEventsBatch = 20

	reconcileEvery = 15 * time.Minute
	liveNodeAge    = 30 * 24 * time.Hour
	eventKeepAge   = 24 * time.Hour
)

var copyBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 256*1024)
		return &buf
	},
}

var publishNATS = func(conn *nats.Conn, subject string, data []byte) error {
	return conn.Publish(subject, data)
}

type Config struct {
	Node             string
	DB               *sql.DB
	NATS             *nats.Conn
	Subject          string
	BindAddress      string
	AdvertiseAddress string
	StoragePath      string
	HTTPPrefix       string
	ACL              ACL

	ResyncWorkers int
	HTTPClient    *http.Client
	Logger        Logger
}

type ACL struct {
	Whitelist []string
	Blacklist []string
}

type Option func(*Config)

type Logger interface {
	Printf(format string, v ...any)
}

func WithNats(conn *nats.Conn, subject string) Option {
	return func(cfg *Config) {
		cfg.NATS = conn
		cfg.Subject = subject
	}
}

func WithLogger(logger Logger) Option {
	return func(cfg *Config) {
		cfg.Logger = logger
	}
}

func WithACL(acl ACL) Option {
	return func(cfg *Config) {
		cfg.ACL = acl
	}
}

func validateAdvertiseAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("blobsync: advertise address must be host:port: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("blobsync: advertise address port must be numeric and in range 1..65535")
	}
	if host == "" {
		return errors.New("blobsync: advertise address host is required")
	}
	if strings.EqualFold(host, "localhost") {
		return errors.New("blobsync: advertise address must be reachable by peer nodes, not localhost")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return errors.New("blobsync: advertise address must not use a wildcard host")
		}
		if ip.IsLoopback() {
			return errors.New("blobsync: advertise address must be reachable by peer nodes, not loopback")
		}
	}
	return nil
}

type BlobSync struct {
	cfg Config

	bindAddress      string
	advertiseAddress string
	reconcileKick    chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	httpServer *http.Server
	sub        *nats.Subscription

	wg    sync.WaitGroup
	mu    sync.Mutex
	aclMu sync.RWMutex

	started bool
}

type fileRecord struct {
	ID          int64
	Filename    string
	Size        int64
	SHA256      string
	DateDeleted sql.NullTime
}

type eventRecord struct {
	ID        int64
	Node      string
	EventType string
	FileID    int64
}

type nodeRecord struct {
	Exists      bool
	ACLHash     sql.NullString
	LastEventID int64
}

type cleanupCandidate struct {
	Name string
	Path string
}

type natsEventMessage struct {
	EventID  int64  `json:"event_id"`
	Filename string `json:"filename"`
}

func New(cfg Config, opts ...Option) (*BlobSync, error) {
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.Node == "" {
		return nil, errors.New("blobsync: node is required")
	}
	if cfg.DB == nil {
		return nil, errors.New("blobsync: DB is required")
	}
	if cfg.NATS != nil && cfg.Subject == "" {
		return nil, errors.New("blobsync: nats subject is required")
	}
	if cfg.NATS == nil && cfg.Subject != "" {
		return nil, errors.New("blobsync: nats connection is required when subject is set")
	}
	if cfg.BindAddress == "" {
		return nil, errors.New("blobsync: bind address is required")
	}
	if _, _, err := net.SplitHostPort(cfg.BindAddress); err != nil {
		return nil, fmt.Errorf("blobsync: bind address must be host:port: %w", err)
	}
	if cfg.AdvertiseAddress == "" {
		return nil, errors.New("blobsync: advertise address is required")
	}
	if err := validateAdvertiseAddress(cfg.AdvertiseAddress); err != nil {
		return nil, err
	}
	if cfg.ResyncWorkers <= 0 {
		cfg.ResyncWorkers = DefaultResyncWorkers
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Minute}
	}
	if cfg.StoragePath == "" {
		cfg.StoragePath = DefaultStoragePath
	}
	if filepath.Clean(cfg.StoragePath) == "." {
		return nil, errors.New("blobsync: storage path must not be empty or .")
	}
	storagePath, err := filepath.Abs(cfg.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("blobsync: storage path: %w", err)
	}
	cfg.StoragePath = storagePath
	cfg.HTTPPrefix = normalizeHTTPPrefix(cfg.HTTPPrefix)
	acl, err := normalizeACL(cfg.ACL, true)
	if err != nil {
		return nil, err
	}
	cfg.ACL = acl

	ctx, cancel := context.WithCancel(context.Background())
	return &BlobSync{
		cfg:              cfg,
		bindAddress:      cfg.BindAddress,
		advertiseAddress: cfg.AdvertiseAddress,
		reconcileKick:    make(chan struct{}, 1),
		ctx:              ctx,
		cancel:           cancel,
	}, nil
}

func (b *BlobSync) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	startCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(b.ctx, cancel)
	defer stop()
	if err := startCtx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return errors.New("blobsync: already started")
	}
	b.started = true
	b.mu.Unlock()

	node, err := b.nodeRecord(startCtx)
	if err != nil {
		b.markStartFailed()
		return err
	}

	var cursor int64
	if !node.Exists {
		hasNodes, err := b.anyNodeExists(startCtx)
		if err != nil {
			b.markStartFailed()
			return err
		}
		if !hasNodes {
			b.logf("blobsync: first node, scanning local storage")
			if err := b.bootstrapStorage(startCtx); err != nil {
				b.markStartFailed()
				return err
			}
		} else {
			b.logf("blobsync: new node, syncing from peers")
		}
		cursor, err = b.resync(startCtx)
		if err != nil {
			b.markStartFailed()
			return err
		}
	}

	httpErr, err := b.startHTTP()
	if err != nil {
		b.markStartFailed()
		return err
	}
	checkHTTP := func() error {
		select {
		case err := <-httpErr:
			return err
		default:
			return nil
		}
	}
	if err := checkHTTP(); err != nil {
		b.cleanupFailedStart()
		return err
	}

	if !node.Exists {
		b.logf("blobsync: registering node %s", b.cfg.Node)
		if err := b.insertNode(startCtx, cursor); err != nil {
			b.cleanupFailedStart()
			return err
		}
	} else if !node.ACLHash.Valid || node.ACLHash.String != b.aclHash() {
		b.logf("blobsync: ACL changed, resyncing")
		cursor, err = b.resync(startCtx)
		if err != nil {
			b.cleanupFailedStart()
			return err
		}
		if err := b.updateNodeState(startCtx, cursor); err != nil {
			b.cleanupFailedStart()
			return err
		}
	} else if err := b.updateNodeAddress(startCtx); err != nil {
		b.cleanupFailedStart()
		return err
	}

	b.wg.Add(1)
	go b.reconcileWorker()

	if b.natsEnabled() {
		sub, err := b.cfg.NATS.Subscribe(b.cfg.Subject, func(msg *nats.Msg) {
			b.handleNATSMessage(msg)
		})
		if err != nil {
			b.cleanupFailedStart()
			return fmt.Errorf("blobsync: subscribe nats: %w", err)
		}
		b.sub = sub
	}

	if err := startCtx.Err(); err != nil {
		b.cleanupFailedStart()
		return err
	}

	b.wg.Add(1)
	go b.periodic()

	if err := checkHTTP(); err != nil {
		b.cleanupFailedStart()
		return err
	}

	return nil
}

func (b *BlobSync) markStartFailed() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = false
}

func (b *BlobSync) cleanupFailedStart() {
	_ = b.Close()

	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	b.ctx = ctx
	b.cancel = cancel
	b.bindAddress = b.cfg.BindAddress
	b.advertiseAddress = b.cfg.AdvertiseAddress
	b.reconcileKick = make(chan struct{}, 1)
	b.httpServer = nil
	b.sub = nil
	b.started = false
}

func (b *BlobSync) Close() error {
	b.cancel()
	if b.sub != nil {
		_ = b.sub.Unsubscribe()
	}

	var err error
	if b.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = b.httpServer.Shutdown(ctx)
	}
	b.wg.Wait()
	return err
}

func (b *BlobSync) Reconcile() {
	b.kickReconcile()
}

func (b *BlobSync) AddFile(ctx context.Context, filename string) error {
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	name, path, err := b.resolveInputFilename(filename)
	if err != nil {
		return err
	}
	if !b.allowedFilename(name) {
		return fmt.Errorf("blobsync: file %s is denied by ACL", name)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("blobsync: stat file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("blobsync: %s is a directory", filename)
	}

	sum, err := hashFileContext(ctx, path)
	if err != nil {
		return err
	}

	tx, err := b.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(
		ctx,
		`INSERT INTO bsfiles
		 SET filename = ?, size = ?, sha256 = ?, dateadded = NOW(), datedeleted = NULL
		 ON DUPLICATE KEY UPDATE size = VALUES(size), sha256 = VALUES(sha256), dateadded = NOW(), datedeleted = NULL`,
		name, info.Size(), sum,
	)
	if err != nil {
		return fmt.Errorf("blobsync: upsert bsfiles: %w", err)
	}

	fileID, err := res.LastInsertId()
	if err != nil || fileID == 0 {
		if err := tx.QueryRowContext(ctx, `SELECT id FROM bsfiles WHERE filename = ?`, name).Scan(&fileID); err != nil {
			return fmt.Errorf("blobsync: select file id: %w", err)
		}
	}

	eventID, err := insertEvent(ctx, tx, b.cfg.Node, "add", fileID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := b.publishEventContext(ctx, eventID, name); err != nil {
		b.logf("blobsync: publish add event %d failed: %v", eventID, err)
	}
	b.kickReconcile()
	return nil
}

func (b *BlobSync) Scan(ctx context.Context) error {
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	if _, err := os.Stat(b.cfg.StoragePath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("blobsync: stat storage: %w", err)
	}

	var added bool
	if err := filepath.WalkDir(b.cfg.StoragePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("blobsync: walk storage: %w", err)
		}
		if path == b.cfg.StoragePath || d.IsDir() {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		name, err := filepath.Rel(b.cfg.StoragePath, path)
		if err != nil {
			return fmt.Errorf("blobsync: scan path: %w", err)
		}
		name = filepath.ToSlash(name)
		if !b.allowedFilename(name) {
			return nil
		}
		fileAdded, err := b.scanFile(ctx, name, path)
		if err != nil {
			return err
		}
		added = added || fileAdded
		return nil
	}); err != nil {
		return err
	}
	if added {
		b.kickReconcile()
	}
	return nil
}

func (b *BlobSync) RemoveFile(ctx context.Context, filename string) error {
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	name, _, err := b.resolveInputFilename(filename)
	if err != nil {
		return err
	}

	tx, err := b.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var fileID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM bsfiles WHERE filename = ? AND datedeleted IS NULL`, name).Scan(&fileID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("blobsync: select file: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE bsfiles SET datedeleted = NOW() WHERE id = ?`, fileID); err != nil {
		return fmt.Errorf("blobsync: mark file deleted: %w", err)
	}
	eventID, err := insertEvent(ctx, tx, b.cfg.Node, "remove", fileID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := b.publishEventContext(ctx, eventID, name); err != nil {
		b.logf("blobsync: publish remove event %d failed: %v", eventID, err)
	}
	b.kickReconcile()
	return nil
}

func (b *BlobSync) Resync(ctx context.Context) error {
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	cursor, err := b.resync(ctx)
	if err != nil {
		return err
	}
	return b.updateCursor(ctx, cursor)
}

func (b *BlobSync) Cleanup(ctx context.Context) error {
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	if _, err := os.Stat(b.cfg.StoragePath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("blobsync: stat storage: %w", err)
	}

	batch := make([]cleanupCandidate, 0, DefaultResyncBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := b.cleanupBatch(ctx, batch)
		batch = batch[:0]
		return err
	}

	if err := filepath.WalkDir(b.cfg.StoragePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("blobsync: walk storage: %w", err)
		}
		if path == b.cfg.StoragePath || d.IsDir() {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		name, err := filepath.Rel(b.cfg.StoragePath, path)
		if err != nil {
			return fmt.Errorf("blobsync: cleanup path: %w", err)
		}
		name = filepath.ToSlash(name)
		batch = append(batch, cleanupCandidate{Name: name, Path: path})
		if len(batch) >= DefaultResyncBatch {
			return flush()
		}
		return nil
	}); err != nil {
		return err
	}
	return flush()
}

func (b *BlobSync) resync(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	highWater, err := b.maxEventID(ctx)
	if err != nil {
		return 0, err
	}
	maxFileID, err := b.maxFileID(ctx)
	if err != nil {
		return 0, err
	}

	jobs := make(chan fileRecord)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup

	workers := b.cfg.ResyncWorkers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for rec := range jobs {
				if err := b.resyncOne(ctx, rec, workerID); err != nil {
					select {
					case errCh <- err:
						cancel()
					default:
					}
					return
				}
			}
		}(i)
	}

	var lastFileID int64
	for lastFileID < maxFileID {
		batch, err := b.resyncBatch(ctx, lastFileID, maxFileID)
		if err != nil {
			cancel()
			close(jobs)
			wg.Wait()
			return 0, err
		}
		if len(batch) == 0 {
			break
		}
		lastFileID = batch[len(batch)-1].ID

		for _, rec := range batch {
			select {
			case jobs <- rec:
			case err := <-errCh:
				cancel()
				close(jobs)
				wg.Wait()
				return 0, err
			case <-ctx.Done():
				cancel()
				close(jobs)
				wg.Wait()
				return 0, ctx.Err()
			}
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		cancel()
		return 0, err
	default:
	}

	return highWater, nil
}

func (b *BlobSync) bootstrapStorage(ctx context.Context) error {
	if _, err := os.Stat(b.cfg.StoragePath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("blobsync: stat storage: %w", err)
	}

	return filepath.WalkDir(b.cfg.StoragePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("blobsync: walk storage: %w", err)
		}
		if path == b.cfg.StoragePath || d.IsDir() {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		name, err := filepath.Rel(b.cfg.StoragePath, path)
		if err != nil {
			return fmt.Errorf("blobsync: bootstrap path: %w", err)
		}
		name = filepath.ToSlash(name)
		if !b.allowedFilename(name) {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("blobsync: stat bootstrap file %s: %w", name, err)
		}
		if info.IsDir() {
			return nil
		}
		sum, err := hashFileContext(ctx, path)
		if err != nil {
			return err
		}
		if err := b.upsertFileRecord(ctx, name, info.Size(), sum); err != nil {
			return err
		}
		b.logf("blobsync: bootstrap: registered %s", name)
		return nil
	})
}

func (b *BlobSync) resyncBatch(ctx context.Context, afterID, maxID int64) ([]fileRecord, error) {
	rows, err := b.cfg.DB.QueryContext(
		ctx,
		`SELECT id, filename, size, sha256, datedeleted
		 FROM bsfiles
		 WHERE id > ? AND id <= ?
		 ORDER BY id
		 LIMIT ?`,
		afterID, maxID, DefaultResyncBatch,
	)
	if err != nil {
		return nil, fmt.Errorf("blobsync: list files: %w", err)
	}
	defer rows.Close()

	batch := make([]fileRecord, 0, DefaultResyncBatch)
	for rows.Next() {
		var rec fileRecord
		if err := rows.Scan(&rec.ID, &rec.Filename, &rec.Size, &rec.SHA256, &rec.DateDeleted); err != nil {
			return nil, fmt.Errorf("blobsync: scan file: %w", err)
		}
		batch = append(batch, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("blobsync: list files: %w", err)
	}
	return batch, nil
}

func (b *BlobSync) reconcileWorker() {
	defer b.wg.Done()
	for {
		select {
		case <-b.reconcileKick:
			if err := b.applyEvents(b.ctx); err != nil {
				b.logf("blobsync: reconcile failed: %v", err)
			}
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *BlobSync) periodic() {
	defer b.wg.Done()
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := b.touchLastSeen(b.ctx); err != nil {
				b.logf("blobsync: touch lastseen failed: %v", err)
			}
			b.kickReconcile()
			if err := b.cleanupEvents(b.ctx); err != nil {
				b.logf("blobsync: cleanup events failed: %v", err)
			}
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *BlobSync) kickReconcile() {
	select {
	case b.reconcileKick <- struct{}{}:
	default:
	}
}

func (b *BlobSync) handleNATSMessage(msg *nats.Msg) {
	var event natsEventMessage
	if err := json.Unmarshal(msg.Data, &event); err != nil || event.Filename == "" {
		b.kickReconcile()
		return
	}
	if !b.allowedFilename(event.Filename) {
		return
	}
	b.kickReconcile()
}

func (b *BlobSync) applyEvents(ctx context.Context) error {
	cursor, err := b.cursor(ctx)
	if err != nil {
		return err
	}

	events, err := b.eventBatch(ctx, cursor)
	if err != nil {
		return err
	}
	files, err := b.eventFileRecords(ctx, events)
	if err != nil {
		return err
	}

	var lastEventID int64
	for _, ev := range events {
		if ev.Node != b.cfg.Node {
			switch ev.EventType {
			case "add":
				rec, ok := files[ev.FileID]
				if !ok {
					break
				}
				if !b.allowedFilename(rec.Filename) {
					if err := b.removeLocalFile(rec); err != nil {
						return err
					}
					break
				}
				if err := b.downloadRecord(ctx, rec, ev.Node, 0); err != nil {
					return err
				}
			case "remove":
				rec, ok := files[ev.FileID]
				if !ok {
					break
				}
				if err := b.removeLocalFile(rec); err != nil {
					return err
				}
			default:
				return fmt.Errorf("blobsync: unknown event type %q", ev.EventType)
			}
		}
		lastEventID = ev.ID
	}
	if lastEventID > 0 {
		if err := b.updateCursor(ctx, lastEventID); err != nil {
			return err
		}
	}
	if len(events) == applyEventsBatch {
		b.kickReconcile()
	}
	return nil
}

func (b *BlobSync) eventFileRecords(ctx context.Context, events []eventRecord) (map[int64]fileRecord, error) {
	ids := make([]int64, 0, len(events))
	seen := make(map[int64]struct{}, len(events))
	for _, ev := range events {
		if ev.Node == b.cfg.Node {
			continue
		}
		switch ev.EventType {
		case "add", "remove":
		default:
			return nil, fmt.Errorf("blobsync: unknown event type %q", ev.EventType)
		}
		if _, ok := seen[ev.FileID]; ok {
			continue
		}
		seen[ev.FileID] = struct{}{}
		ids = append(ids, ev.FileID)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := b.cfg.DB.QueryContext(
		ctx,
		`SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("blobsync: list event files: %w", err)
	}
	defer rows.Close()

	files := make(map[int64]fileRecord, len(ids))
	for rows.Next() {
		var rec fileRecord
		if err := rows.Scan(&rec.ID, &rec.Filename, &rec.Size, &rec.SHA256, &rec.DateDeleted); err != nil {
			return nil, fmt.Errorf("blobsync: scan event file: %w", err)
		}
		files[rec.ID] = rec
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("blobsync: list event files: %w", err)
	}
	return files, nil
}

func (b *BlobSync) eventBatch(ctx context.Context, cursor int64) ([]eventRecord, error) {
	rows, err := b.cfg.DB.QueryContext(ctx, `SELECT id, node, eventtype, fileid FROM bsevents WHERE id > ? ORDER BY id LIMIT ?`, cursor, applyEventsBatch)
	if err != nil {
		return nil, fmt.Errorf("blobsync: list events: %w", err)
	}
	defer rows.Close()

	events := make([]eventRecord, 0, applyEventsBatch)
	for rows.Next() {
		var ev eventRecord
		if err := rows.Scan(&ev.ID, &ev.Node, &ev.EventType, &ev.FileID); err != nil {
			return nil, fmt.Errorf("blobsync: scan event: %w", err)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (b *BlobSync) startHTTP() (<-chan error, error) {
	mux := http.NewServeMux()
	mux.HandleFunc(b.cfg.HTTPPrefix+"/", b.handleFile)

	b.httpServer = &http.Server{
		Addr:    b.bindAddress,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", b.bindAddress)
	if err != nil {
		return nil, fmt.Errorf("blobsync: listen http: %w", err)
	}

	errCh := make(chan error, 1)
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		if err := b.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			err = fmt.Errorf("blobsync: http server stopped: %w", err)
			b.logf("%v", err)
			errCh <- err
			b.cancel()
		}
	}()
	return errCh, nil
}

func (b *BlobSync) logf(format string, v ...any) {
	if b.cfg.Logger != nil {
		b.cfg.Logger.Printf(format, v...)
	}
}

func (b *BlobSync) handleFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, b.cfg.HTTPPrefix)
	idText := strings.TrimPrefix(path, "/")
	fileID, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || fileID <= 0 {
		http.Error(w, "bad file id", http.StatusBadRequest)
		return
	}

	rec, err := b.fileByID(r.Context(), fileID)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		b.logf("blobsync: http file lookup %d failed: %v", fileID, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if rec.DateDeleted.Valid {
		http.NotFound(w, r)
		return
	}
	if !b.allowedFilename(rec.Filename) {
		http.NotFound(w, r)
		return
	}

	path, err = b.localPath(rec.Filename)
	if err != nil {
		b.logf("blobsync: http file path %d failed: %v", fileID, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	b.logf("blobsync: serving %s to %s", rec.Filename, r.RemoteAddr)
	http.ServeFile(w, r, path)
}

func (b *BlobSync) resyncOne(ctx context.Context, rec fileRecord, workerID int) error {
	if rec.DateDeleted.Valid || !b.allowedFilename(rec.Filename) {
		if err := b.removeLocalFile(rec); err != nil {
			return err
		}
		return nil
	}

	path, err := b.localPath(rec.Filename)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return b.downloadFile(ctx, rec.ID, "", workerID)
	}
	if err != nil {
		return fmt.Errorf("blobsync: stat local file %s: %w", rec.Filename, err)
	}
	if info.IsDir() || info.Size() != rec.Size {
		return b.downloadFile(ctx, rec.ID, "", workerID)
	}
	sum, err := hashFileContext(ctx, path)
	if err != nil {
		return err
	}
	if sum != rec.SHA256 {
		return b.downloadFile(ctx, rec.ID, "", workerID)
	}
	return nil
}

func (b *BlobSync) downloadFile(ctx context.Context, fileID int64, preferredNode string, workerID int) error {
	rec, err := b.fileByID(ctx, fileID)
	if err != nil {
		return err
	}
	return b.downloadRecord(ctx, rec, preferredNode, workerID)
}

func (b *BlobSync) downloadRecord(ctx context.Context, rec fileRecord, preferredNode string, workerID int) error {
	if rec.DateDeleted.Valid || !b.allowedFilename(rec.Filename) {
		return b.removeLocalFile(rec)
	}
	nodes, err := b.sourceNodes(ctx, preferredNode)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("blobsync: no source nodes for file %d", rec.ID)
	}

	var lastErr error
	start := workerID % len(nodes)
	for i := 0; i < len(nodes); i++ {
		node := nodes[(start+i)%len(nodes)]
		if err := b.downloadFrom(ctx, node, rec); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func (b *BlobSync) downloadFrom(ctx context.Context, node nodeAddress, rec fileRecord) error {
	u := url.URL{
		Scheme: "http",
		Host:   node.Address,
		Path:   fmt.Sprintf("%s/%d", b.cfg.HTTPPrefix, rec.ID),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("blobsync: download %s from %s: %w", rec.Filename, node.Node, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("blobsync: download %s from %s: status %s", rec.Filename, node.Node, resp.Status)
	}

	path, err := b.localPath(rec.Filename)
	if err != nil {
		return err
	}
	parentDir := filepath.Dir(path)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("blobsync: create parent dir: %w", err)
	}

	f, err := os.CreateTemp(parentDir, ".blobsync-*.tmp")
	if err != nil {
		return fmt.Errorf("blobsync: create temp file: %w", err)
	}
	tmp := f.Name()
	h := sha256.New()
	w := io.MultiWriter(f, h)
	n, copyErr := copyWithContext(ctx, w, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("blobsync: save temp file: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("blobsync: close temp file: %w", closeErr)
	}
	if n != rec.Size {
		_ = os.Remove(tmp)
		return fmt.Errorf("blobsync: downloaded size mismatch for %s", rec.Filename)
	}
	if hex.EncodeToString(h.Sum(nil)) != rec.SHA256 {
		_ = os.Remove(tmp)
		return fmt.Errorf("blobsync: downloaded sha256 mismatch for %s", rec.Filename)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("blobsync: replace file: %w", err)
	}
	b.logf("blobsync: downloaded %s from %s", rec.Filename, node.Node)
	return nil
}

type nodeAddress struct {
	Node    string
	Address string
}

func (b *BlobSync) sourceNodes(ctx context.Context, preferredNode string) ([]nodeAddress, error) {
	if preferredNode != "" {
		preferred, err := b.querySourceNodes(ctx, `SELECT node, address FROM bsnodes WHERE node = ? AND node <> ? AND address <> ''`, preferredNode, b.cfg.Node)
		if err != nil {
			return nil, err
		}
		fallback, err := b.querySourceNodes(ctx, `SELECT node, address FROM bsnodes WHERE node <> ? AND node <> ? AND address <> '' AND lastseen > ? ORDER BY node`, b.cfg.Node, preferredNode, time.Now().Add(-liveNodeAge))
		if err != nil {
			return nil, err
		}
		return append(preferred, fallback...), nil
	}

	return b.querySourceNodes(ctx, `SELECT node, address FROM bsnodes WHERE node <> ? AND address <> '' AND lastseen > ? ORDER BY node`, b.cfg.Node, time.Now().Add(-liveNodeAge))
}

func (b *BlobSync) querySourceNodes(ctx context.Context, query string, args ...any) ([]nodeAddress, error) {
	rows, err := b.cfg.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("blobsync: list source nodes: %w", err)
	}
	defer rows.Close()

	var nodes []nodeAddress
	for rows.Next() {
		var n nodeAddress
		if err := rows.Scan(&n.Node, &n.Address); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func (b *BlobSync) nodeRecord(ctx context.Context) (nodeRecord, error) {
	var rec nodeRecord
	err := b.cfg.DB.QueryRowContext(ctx, `SELECT lasteventid, aclsha256 FROM bsnodes WHERE node = ?`, b.cfg.Node).Scan(&rec.LastEventID, &rec.ACLHash)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, nil
	}
	if err != nil {
		return rec, err
	}
	rec.Exists = true
	return rec, nil
}

func (b *BlobSync) anyNodeExists(ctx context.Context) (bool, error) {
	var count int64
	if err := b.cfg.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM bsnodes`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (b *BlobSync) insertNode(ctx context.Context, cursor int64) error {
	_, err := b.cfg.DB.ExecContext(ctx, `INSERT INTO bsnodes SET node = ?, address = ?, lasteventid = ?, aclsha256 = ?, lastseen = NOW()`, b.cfg.Node, b.advertiseAddress, cursor, b.aclHash())
	return err
}

func (b *BlobSync) updateNodeAddress(ctx context.Context) error {
	_, err := b.cfg.DB.ExecContext(ctx, `UPDATE bsnodes SET address = ?, aclsha256 = ?, lastseen = NOW() WHERE node = ?`, b.advertiseAddress, b.aclHash(), b.cfg.Node)
	return err
}

func (b *BlobSync) cursor(ctx context.Context) (int64, error) {
	var cursor int64
	err := b.cfg.DB.QueryRowContext(ctx, `SELECT lasteventid FROM bsnodes WHERE node = ?`, b.cfg.Node).Scan(&cursor)
	return cursor, err
}

func (b *BlobSync) updateCursor(ctx context.Context, eventID int64) error {
	_, err := b.cfg.DB.ExecContext(ctx, `UPDATE bsnodes SET lasteventid = ?, aclsha256 = ?, lastseen = NOW() WHERE node = ?`, eventID, b.aclHash(), b.cfg.Node)
	return err
}

func (b *BlobSync) updateNodeState(ctx context.Context, eventID int64) error {
	_, err := b.cfg.DB.ExecContext(ctx, `UPDATE bsnodes SET address = ?, lasteventid = ?, aclsha256 = ?, lastseen = NOW() WHERE node = ?`, b.advertiseAddress, eventID, b.aclHash(), b.cfg.Node)
	return err
}

func (b *BlobSync) touchLastSeen(ctx context.Context) error {
	_, err := b.cfg.DB.ExecContext(ctx, `UPDATE bsnodes SET lastseen = NOW(), address = ?, aclsha256 = ? WHERE node = ?`, b.advertiseAddress, b.aclHash(), b.cfg.Node)
	return err
}

func (b *BlobSync) maxEventID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	err := b.cfg.DB.QueryRowContext(ctx, `SELECT MAX(id) FROM bsevents`).Scan(&id)
	if err != nil {
		return 0, err
	}
	if !id.Valid {
		return 0, nil
	}
	return id.Int64, nil
}

func (b *BlobSync) maxFileID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	err := b.cfg.DB.QueryRowContext(ctx, `SELECT MAX(id) FROM bsfiles`).Scan(&id)
	if err != nil {
		return 0, err
	}
	if !id.Valid {
		return 0, nil
	}
	return id.Int64, nil
}

func (b *BlobSync) cleanupEvents(ctx context.Context) error {
	var minCursor sql.NullInt64
	err := b.cfg.DB.QueryRowContext(ctx, `SELECT MIN(lasteventid) FROM bsnodes WHERE lastseen > ?`, time.Now().Add(-liveNodeAge)).Scan(&minCursor)
	if err != nil {
		return err
	}
	if !minCursor.Valid {
		return nil
	}
	_, err = b.cfg.DB.ExecContext(ctx, `DELETE FROM bsevents WHERE dateadded < ? AND id <= ?`, time.Now().Add(-eventKeepAge), minCursor.Int64)
	return err
}

func (b *BlobSync) cleanupBatch(ctx context.Context, batch []cleanupCandidate) error {
	placeholders := strings.TrimRight(strings.Repeat("?,", len(batch)), ",")
	args := make([]any, len(batch))
	for i, f := range batch {
		args[i] = f.Name
	}

	rows, err := b.cfg.DB.QueryContext(ctx, `SELECT filename, datedeleted FROM bsfiles WHERE filename IN (`+placeholders+`)`, args...)
	if err != nil {
		return fmt.Errorf("blobsync: list cleanup files: %w", err)
	}
	defer rows.Close()

	keep := make(map[string]bool, len(batch))
	for rows.Next() {
		var filename string
		var dateDeleted sql.NullTime
		if err := rows.Scan(&filename, &dateDeleted); err != nil {
			return fmt.Errorf("blobsync: scan cleanup file: %w", err)
		}
		if !dateDeleted.Valid {
			keep[filename] = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("blobsync: list cleanup files: %w", err)
	}

	for _, f := range batch {
		if keep[f.Name] {
			continue
		}
		if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("blobsync: cleanup remove %s: %w", f.Name, err)
		}
		b.pruneEmptyDirs(filepath.Dir(f.Path))
	}
	return nil
}

func (b *BlobSync) scanFile(ctx context.Context, name, path string) (bool, error) {
	var fileID int64
	var dateDeleted sql.NullTime
	err := b.cfg.DB.QueryRowContext(ctx, `SELECT id, datedeleted FROM bsfiles WHERE filename = ?`, name).Scan(&fileID, &dateDeleted)
	if err == nil && !dateDeleted.Valid {
		return false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("blobsync: select scan file: %w", err)
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		return false, fmt.Errorf("blobsync: stat scan file %s: %w", name, statErr)
	}
	if info.IsDir() {
		return false, nil
	}
	sum, err := hashFileContext(ctx, path)
	if err != nil {
		return false, err
	}

	tx, err := b.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(
		ctx,
		`INSERT INTO bsfiles
		 SET filename = ?, size = ?, sha256 = ?, dateadded = NOW(), datedeleted = NULL
		 ON DUPLICATE KEY UPDATE size = VALUES(size), sha256 = VALUES(sha256), dateadded = NOW(), datedeleted = NULL`,
		name, info.Size(), sum,
	)
	if err != nil {
		return false, fmt.Errorf("blobsync: upsert bsfiles: %w", err)
	}
	if fileID == 0 {
		fileID, err = res.LastInsertId()
		if err != nil || fileID == 0 {
			if err := tx.QueryRowContext(ctx, `SELECT id FROM bsfiles WHERE filename = ?`, name).Scan(&fileID); err != nil {
				return false, fmt.Errorf("blobsync: select file id: %w", err)
			}
		}
	}

	if _, err := insertEvent(ctx, tx, b.cfg.Node, "add", fileID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (b *BlobSync) upsertFileRecord(ctx context.Context, filename string, size int64, sha256 string) error {
	_, err := b.cfg.DB.ExecContext(
		ctx,
		`INSERT INTO bsfiles
		 SET filename = ?, size = ?, sha256 = ?, dateadded = NOW(), datedeleted = NULL
		 ON DUPLICATE KEY UPDATE size = VALUES(size), sha256 = VALUES(sha256), dateadded = NOW(), datedeleted = NULL`,
		filename, size, sha256,
	)
	if err != nil {
		return fmt.Errorf("blobsync: upsert bsfiles: %w", err)
	}
	return nil
}

func (b *BlobSync) fileByID(ctx context.Context, fileID int64) (fileRecord, error) {
	var rec fileRecord
	err := b.cfg.DB.QueryRowContext(ctx, `SELECT id, filename, size, sha256, datedeleted FROM bsfiles WHERE id = ?`, fileID).
		Scan(&rec.ID, &rec.Filename, &rec.Size, &rec.SHA256, &rec.DateDeleted)
	return rec, err
}

func insertEvent(ctx context.Context, tx *sql.Tx, node, eventType string, fileID int64) (int64, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO bsevents SET node = ?, eventtype = ?, fileid = ?, dateadded = NOW()`, node, eventType, fileID)
	if err != nil {
		return 0, fmt.Errorf("blobsync: insert event: %w", err)
	}
	return res.LastInsertId()
}

func (b *BlobSync) publishEventContext(ctx context.Context, eventID int64, filename string) error {
	if !b.natsEnabled() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(natsEventMessage{EventID: eventID, Filename: filename})
	if err != nil {
		return err
	}
	return publishNATS(b.cfg.NATS, b.cfg.Subject, data)
}

func (b *BlobSync) natsEnabled() bool {
	return b.cfg.NATS != nil && b.cfg.Subject != ""
}

func normalizeHTTPPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return "/" + strings.Trim(strings.TrimSuffix(prefix, "/"), "/")
}

func normalizeACL(acl ACL, storageRoot bool) (ACL, error) {
	var err error
	acl.Whitelist, err = normalizePrefixes(acl.Whitelist, storageRoot)
	if err != nil {
		return ACL{}, err
	}
	acl.Blacklist, err = normalizePrefixes(acl.Blacklist, storageRoot)
	if err != nil {
		return ACL{}, err
	}
	return acl, nil
}

func normalizePrefixes(prefixes []string, storageRoot bool) ([]string, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		normalized, err := normalizePrefix(prefix, storageRoot)
		if err != nil {
			return nil, fmt.Errorf("blobsync: bad ACL prefix %q: %w", prefix, err)
		}
		if normalized == "." {
			normalized = ""
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeName(name string, storageRoot bool) (string, error) {
	if name == "" {
		return "", errors.New("empty filename")
	}
	name = filepath.Clean(name)
	if storageRoot && filepath.IsAbs(name) {
		return "", errors.New("absolute paths are not allowed with StoragePath")
	}
	if storageRoot && (name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator))) {
		return "", errors.New("path escapes StoragePath")
	}
	return filepath.ToSlash(name), nil
}

func normalizePrefix(prefix string, storageRoot bool) (string, error) {
	if prefix == "" {
		return "", errors.New("empty prefix")
	}
	trailingSlash := strings.HasSuffix(prefix, "/") || strings.HasSuffix(prefix, string(filepath.Separator))
	normalized, err := normalizeName(prefix, storageRoot)
	if err != nil {
		return "", err
	}
	if trailingSlash && normalized != "." && normalized != "" && !strings.HasSuffix(normalized, "/") {
		normalized += "/"
	}
	return normalized, nil
}

func (b *BlobSync) resolveInputFilename(filename string) (string, string, error) {
	var name string
	if filepath.IsAbs(filename) {
		abs, err := filepath.Abs(filename)
		if err != nil {
			return "", "", fmt.Errorf("blobsync: filename: %w", err)
		}
		rel, err := filepath.Rel(b.cfg.StoragePath, abs)
		if err != nil {
			return "", "", fmt.Errorf("blobsync: filename: %w", err)
		}
		name, err = normalizeName(rel, true)
		if err != nil {
			return "", "", fmt.Errorf("blobsync: filename: %w", err)
		}
	} else {
		var err error
		name, err = normalizeName(filename, true)
		if err != nil {
			return "", "", fmt.Errorf("blobsync: filename: %w", err)
		}
	}
	path, err := b.localPath(name)
	if err != nil {
		return "", "", err
	}
	return name, path, nil
}

func (b *BlobSync) localPath(filename string) (string, error) {
	name, err := normalizeName(filepath.FromSlash(filename), true)
	if err != nil {
		return "", fmt.Errorf("blobsync: unsafe filename %q: %w", filename, err)
	}
	path := filepath.Join(b.cfg.StoragePath, filepath.FromSlash(name))
	rel, err := filepath.Rel(b.cfg.StoragePath, path)
	if err != nil {
		return "", fmt.Errorf("blobsync: unsafe filename %q: %w", filename, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("blobsync: unsafe filename %q: path escapes StoragePath", filename)
	}
	return path, nil
}

func (b *BlobSync) allowedFilename(filename string) bool {
	b.aclMu.RLock()
	acl := b.cfg.ACL
	b.aclMu.RUnlock()

	if len(acl.Whitelist) > 0 && !matchesAnyPrefix(filename, acl.Whitelist) {
		return false
	}
	if len(acl.Blacklist) > 0 && matchesAnyPrefix(filename, acl.Blacklist) {
		return false
	}
	return true
}

func matchesAnyPrefix(filename string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(filename, prefix) {
			return true
		}
	}
	return false
}

func (b *BlobSync) removeLocalFile(rec fileRecord) error {
	path, err := b.localPath(rec.Filename)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blobsync: remove local file %s: %w", rec.Filename, err)
	}
	b.pruneEmptyDirs(filepath.Dir(path))
	return nil
}

func (b *BlobSync) pruneEmptyDirs(dir string) {
	for {
		rel, err := filepath.Rel(b.cfg.StoragePath, dir)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return
		}
		if err := syscall.Rmdir(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

func (b *BlobSync) aclHash() string {
	b.aclMu.RLock()
	acl := b.cfg.ACL
	b.aclMu.RUnlock()

	data, err := json.Marshal(acl)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashFileContext(ctx context.Context, filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("blobsync: open file for hash: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := copyWithContext(ctx, h, f); err != nil {
		return "", fmt.Errorf("blobsync: hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)

	buf := *bufPtr
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return written, nil
			}
			return written, er
		}
	}
}

func (b *BlobSync) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	if b.ctx.Err() != nil {
		cancel()
		return ctx, cancel
	}
	stop := context.AfterFunc(b.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}
