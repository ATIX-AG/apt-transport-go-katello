package main

import (
	"log"
	"os"
)

var debugLogger = log.New(os.Stderr, "katello-debug: ", log.LstdFlags|log.Lmicroseconds)

func debugf(format string, args ...interface{}) {
	if !buildDebug {
		return
	}
	debugLogger.Printf(format, args...)
}
