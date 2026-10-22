// SPDX-License-Identifier: Apache-2.0

// Command ready is the role service of the systemd host of the OTA tests: it answers /readyz so
// that the root updater counts the role as ready, without a controller.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7384", "the admin address to listen on")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
