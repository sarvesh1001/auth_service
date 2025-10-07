package main

import (
    "crypto/tls"
    "log"
    "net/http"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })

    // HTTPS-only
    server := &http.Server{
        Addr: ":8443",
        Handler: mux,
        TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS13,
        },
    }

    log.Println("🚀 Starting HTTPS Auth Service on port 8443...")
    log.Fatal(server.ListenAndServeTLS("certs/dev.crt", "certs/dev.key"))
}
