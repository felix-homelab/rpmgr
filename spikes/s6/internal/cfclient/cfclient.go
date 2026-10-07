// SPDX-License-Identifier: Apache-2.0

// Package cfclient is a minimal Cloudflare v4 API client for what DNS-01 needs: list zones (all
// pages), list, create and delete TXT records. It stands in for rpmgr's own client in
// internal/dns/cloudflare (docs/08-software-stack.md, "Networking"). The token is read from a
// file, never from argv or the environment.
package cfclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultBaseURL is the compiled-in API URL. The spike's tests point the client at the fake.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// Client talks to the Cloudflare API with one API token.
type Client struct {
	BaseURL string
	token   string
	HTTP    *http.Client
}

// New returns a client for baseURL with the given token.
func New(baseURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), token: token, HTTP: hc}
}

// NewFromTokenFile reads the token from a file that must not be readable by group or others.
func NewFromTokenFile(baseURL, path string, hc *http.Client) (*Client, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("cfclient: token file %s is readable by group or others (mode %v)", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return nil, errors.New("cfclient: token file is empty")
	}
	return New(baseURL, tok, hc), nil
}

// APIError is an unsuccessful API response.
type APIError struct {
	Status int
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
}

func (e *APIError) Error() string {
	var parts []string
	for _, x := range e.Errors {
		parts = append(parts, fmt.Sprintf("%d %s", x.Code, x.Message))
	}
	return fmt.Sprintf("cloudflare API: HTTP %d: %s", e.Status, strings.Join(parts, "; "))
}

// Zone is a Cloudflare zone.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

// Record is a Cloudflare DNS record.
type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment,omitempty"`
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     json.RawMessage `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) (*envelope, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var env envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		return nil, fmt.Errorf("cloudflare API: HTTP %d: decoding response: %w", resp.StatusCode, err)
	}
	if resp.StatusCode/100 != 2 || !env.Success {
		e := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(env.Errors, &e.Errors)
		return nil, e
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, err
		}
	}
	return &env, nil
}

// ListZones returns every zone of the account, following all pages (at most 50 per page).
func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	var all []Zone
	for page := 1; ; page++ {
		var zs []Zone
		env, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/zones?page=%d&per_page=50", page), nil, &zs)
		if err != nil {
			return nil, err
		}
		all = append(all, zs...)
		if env.ResultInfo == nil || page >= env.ResultInfo.TotalPages || len(zs) == 0 {
			return all, nil
		}
	}
}

// ListTXT returns the TXT records at name (an FQDN without trailing dot).
func (c *Client) ListTXT(ctx context.Context, zoneID, name string) ([]Record, error) {
	var all []Record
	for page := 1; ; page++ {
		var rs []Record
		q := url.Values{"type": {"TXT"}, "name": {name}, "page": {fmt.Sprint(page)}, "per_page": {"50"}}
		env, err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records?"+q.Encode(), nil, &rs)
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
		if env.ResultInfo == nil || page >= env.ResultInfo.TotalPages || len(rs) == 0 {
			return all, nil
		}
	}
}

// CreateRecord creates a record and returns it with its ID.
func (c *Client) CreateRecord(ctx context.Context, zoneID string, r Record) (Record, error) {
	var out Record
	_, err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", r, &out)
	return out, err
}

// DeleteRecord deletes a record by ID.
func (c *Client) DeleteRecord(ctx context.Context, zoneID, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), nil, nil)
	return err
}
