// SPDX-License-Identifier: Apache-2.0

// Command ready is the role service of the systemd host of the OTA tests: it answers /readyz so
// that the root updater counts the role as ready, without a controller.
package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7384", "the admin address to listen on")
	flag.Parse()
	http.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	log.Fatal(http.ListenAndServe(*addr, nil))
}
