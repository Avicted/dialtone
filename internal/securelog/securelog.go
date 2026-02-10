package securelog

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"
)

// Error logs an error without including user-provided data.
// It records the caller location and error type chain.
func Error(context string, err error) {
	if err == nil {
		return
	}
	loc := callerLocation(2)
	types := strings.Join(errorTypes(err), "->")
	if context == "" {
		log.Printf("error at %s types=%s", loc, types)
		return
	}
	log.Printf("error at %s context=%s types=%s", loc, context, types)
}

func callerLocation(skip int) string {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	name := "unknown"
	if fn != nil {
		name = fn.Name()
	}
	return fmt.Sprintf("%s:%d %s", file, line, name)
}

func errorTypes(err error) []string {
	types := []string{}
	seen := map[string]struct{}{}
	for err != nil {
		name := fmt.Sprintf("%T", err)
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			types = append(types, name)
		}
		err = errors.Unwrap(err)
	}
	return types
}
