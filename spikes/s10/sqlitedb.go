// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"

	_ "modernc.org/sqlite" // the driver rpmgr uses (store.OpenSQLite)
)

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, db.Ping()
}
