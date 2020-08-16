package clnrestrict

import (
	"log"
	"net"
	"net/http"
	"strings"
)

// ClientRestrictMiddleware is the middleware for access restriction to service based on IP address.
func ClientRestrictMiddleware(allowedIP string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP := GetRemoteIP(r)

			if remoteIP != allowedIP {
				log.Printf("remote IP %s not allowed (%s)", remoteIP, allowedIP)
				http.Error(w, "not allowed", 401)
				return
			}

			log.Printf("remote IP %s", remoteIP)
			next.ServeHTTP(w, r)
		})
	}
}

// GetRemoteIP returns host's IP address
func GetRemoteIP(r *http.Request) string {
	remoteIP := ""
	if parts := strings.Split(r.RemoteAddr, ":"); len(parts) == 2 {
		remoteIP = parts[0]
	}

	if xff := strings.Trim(r.Header.Get("X-Forwarded-For"), ","); len(xff) > 0 {
		addrs := strings.Split(xff, ",")
		lastFwd := addrs[len(addrs)-1]
		if ip := net.ParseIP(lastFwd); ip != nil {
			remoteIP = ip.String()
		}
	} else if xri := r.Header.Get("X-Real-Ip"); len(xri) > 0 {
		if ip := net.ParseIP(xri); ip != nil {
			remoteIP = ip.String()
		}
	}

	return remoteIP
}
