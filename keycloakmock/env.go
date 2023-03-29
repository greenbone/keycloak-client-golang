package main

import (
	"os"
	"strconv"
)

func getEnvOrDefaultString(key string, defaultValue string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultValue
}

func getEnvOrDefaultInt(key string, defaultValue int) int {
	if val, ok := os.LookupEnv(key); ok {
		if v, err := strconv.ParseInt(val, 10, 32); err == nil {
			return int(v)
		}
	}
	return defaultValue
}
