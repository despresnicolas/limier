// Package storage stores SBOM documents in the database (sbom_blobs). The "pg://" URI prefix is a legacy name: the GC query in queries/scans.sql matches it.
// Documents are gzip-compressed. The returned URI is persisted in sboms.storage_uri.
package storage

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"limier/internal/db/dbq"
)

const maxDocument = 256 << 20

type Store interface {
	Put(ctx context.Context, key string, doc []byte) (uri string, err error)
	Get(ctx context.Context, uri string) ([]byte, error)
	Delete(ctx context.Context, uri string) error
}

func New(q *dbq.Queries) Store { return &pgStore{q: q} }

type pgStore struct{ q *dbq.Queries }

func (s *pgStore) Put(ctx context.Context, _ string, doc []byte) (string, error) {
	z, err := compress(doc)
	if err != nil {
		return "", err
	}
	id, err := s.q.InsertSBOMBlob(ctx, z)
	if err != nil {
		return "", err
	}
	return "pg://" + strconv.FormatInt(id, 10), nil
}

func (s *pgStore) Get(ctx context.Context, uri string) ([]byte, error) {
	id, err := pgID(uri)
	if err != nil {
		return nil, err
	}
	z, err := s.q.GetSBOMBlob(ctx, id)
	if err != nil {
		return nil, err
	}
	return decompress(bytes.NewReader(z))
}

func (s *pgStore) Delete(ctx context.Context, uri string) error {
	id, err := pgID(uri)
	if err != nil {
		return err
	}
	return s.q.DeleteSBOMBlob(ctx, id)
}

func pgID(uri string) (int64, error) {
	rest, ok := strings.CutPrefix(uri, "pg://")
	if !ok {
		return 0, fmt.Errorf("storage: not a pg:// uri: %q", uri)
	}
	return strconv.ParseInt(rest, 10, 64)
}

func compress(doc []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(doc); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(r io.Reader) ([]byte, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("storage: gunzip: %w", err)
	}
	defer zr.Close()
	b, err := io.ReadAll(io.LimitReader(zr, maxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDocument {
		return nil, fmt.Errorf("storage: document exceeds %d bytes", maxDocument)
	}
	return b, nil
}
