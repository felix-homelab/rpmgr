// SPDX-License-Identifier: Apache-2.0

package store

import (
	"strings"
	"testing"
)

// TestSummarizeDSN_NoSecret: no part of a DSN that SummarizeDSN returns holds the password, however
// the password is quoted, escaped or placed, in either DSN form.
func TestSummarizeDSN_NoSecret(t *testing.T) {
	t.Setenv("PGPASSFILE", "/nonexistent/pgpass")
	t.Setenv("PGPASSWORD", "")
	const c = "SECRETCANARY"
	for _, dsn := range []string{
		"host=db port=5432 dbname=rpmgr user=rpmgr password=" + c,
		"host=db password='a b " + c + "' user=rpmgr",
		"host=db password='x host=" + c + "' dbname=rpmgr",
		"password='x port=" + c + "' host=db",
		"password='x user=" + c + "'",
		"password='it\\'s dbname=" + c + "' host=db",
		"password='x sslmode=" + c + "'",
		"host=db sslpassword=" + c + " service=" + c,
		"host=a,b port=1,2 password=" + c,
		"host = db password = " + c,
		"host=db\tpassword=" + c + "\nuser=u",
		"postgres://rpmgr:" + c + "@db/rpmgr",
		"postgres://rpmgr:p%40" + c + "@db/rpmgr",
		"postgres://rpmgr:p@" + c + "@db/rpmgr",
		"postgres://rpmgr:" + c + "@[::1]:5432/rpmgr",
		"postgres://rpmgr:" + c + "@[fe80::1%25eth0]:5432/rpmgr",
		"postgres://rpmgr:" + c + "@a:1,b:2/rpmgr",
		"postgres://rpmgr:12/" + c + "@db/rpmgr",
		"postgres://rpmgr:12#" + c + "@db/rpmgr",
		"postgres://rpmgr:12?user=" + c + "@db/rpmgr",
		"postgres://db/rpmgr?user=u&password=" + c + "&sslpassword=" + c + "&service=" + c,
		"postgres://db/rpmgr?sslmode=" + c,
		"postgresql://u:" + c + "@db",
		"postgres://u:" + c + " x@db/rpmgr",
		"postgres://u:p%zz" + c + "@db/rpmgr",
		"", c,
	} {
		p, _ := SummarizeDSN(dsn)
		if got := strings.Join([]string{p.Host, p.Port, p.Database, p.User, p.SSLMode}, "|"); strings.Contains(got, c) {
			t.Errorf("%q gives %q", dsn, got)
		}
	}
}

// TestSummarizeDSN: the parts of a DSN, the first host of a list, and a refused DSN.
func TestSummarizeDSN(t *testing.T) {
	t.Setenv("PGPASSFILE", "/nonexistent/pgpass")
	t.Setenv("PGPASSWORD", "")
	p, ok := SummarizeDSN("postgres://u@a:1,b:2/db?sslmode=verify-full")
	if !ok || p != (DSNParts{Host: "a", Port: "1", Database: "db", User: "u", SSLMode: "verify-full"}) {
		t.Errorf("multi-host: %+v %v", p, ok)
	}
	if p, ok := SummarizeDSN("host=db user=u password=x"); !ok || !p.HasPassword {
		t.Errorf("a password: %+v %v", p, ok)
	}
	if _, ok := SummarizeDSN("host=db sslpassword=x"); ok {
		t.Error("a parameter that is not allowed")
	}
	if _, ok := SummarizeDSN("postgres://u:12/x@db/rpmgr"); ok {
		t.Error("an ambiguous URL")
	}
}
