package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
)

var port = 3000

func getRemoteIP(r *http.Request) string {
	remoteIP := ""
	// the default is the originating ip. but we try to find better options because this is almost
	// never the right IP
	if parts := strings.Split(r.RemoteAddr, ":"); len(parts) == 2 {
		remoteIP = parts[0]
	}
	// If we have a forwarded-for header, take the address from there
	if xff := strings.Trim(r.Header.Get("X-Forwarded-For"), ","); len(xff) > 0 {
		addrs := strings.Split(xff, ",")
		lastFwd := addrs[len(addrs)-1]
		if ip := net.ParseIP(lastFwd); ip != nil {
			remoteIP = ip.String()
		}
		// parse X-Real-Ip header
	} else if xri := r.Header.Get("X-Real-Ip"); len(xri) > 0 {
		if ip := net.ParseIP(xri); ip != nil {
			remoteIP = ip.String()
		}
	}

	return remoteIP
}

func clientRestrictMiddleware(allowedIp string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP := getRemoteIP(r)

			if remoteIP != allowedIp {
				log.Printf("remote IP %s not allowed (%s)", remoteIP, allowedIp)
				http.Error(w, "Blocked", 401)
				return
			}
		})
	}
}

func service(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("service response text!"))
}

func main() {
	router := chi.NewRouter()

	router.With(clientRestrictMiddleware("1.2.3.4")).HandleFunc("/", service)

	log.Printf("Serving on HTTP port: %d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
