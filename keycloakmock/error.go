package main

import (
	"fmt"
	"net/http"
)

func errorString(err error) []byte {
	return []byte(fmt.Sprintf(`{"error":"%s"}`, err.Error()))
}

func writeError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(errorString(err))
}
