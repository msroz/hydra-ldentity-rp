package httputil

import (
	"log/slog"
	"net/http"
)

// HandleError logs the error and sends an HTTP error response to the client.
// For 5xx status codes, logs at Error level; for 4xx, at Warn level.
// If err is non-nil, it is included in the log output.
func HandleError(w http.ResponseWriter, msg string, status int, err error) {
	if err != nil {
		if status >= 500 {
			slog.Error(msg, "err", err)
		} else {
			slog.Warn(msg, "err", err)
		}
	} else {
		if status >= 500 {
			slog.Error(msg)
		} else {
			slog.Warn(msg)
		}
	}
	http.Error(w, msg, status)
}
