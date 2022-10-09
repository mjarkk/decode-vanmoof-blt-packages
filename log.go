package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/muesli/termenv"
)

var style *termenv.Output

func init() {
	style = termenv.NewOutput(os.Stdout)
}

func printErr(err string) {
	fmt.Println(style.String(err).Foreground(termenv.ANSIBrightRed))
}

func fatal(err string) {
	printErr(err)
	os.Exit(1)
}

func fatalf(err string, args ...any) {
	fatal(fmt.Sprintf(err, args...))
}

func warn(msg string) {
	fmt.Println(style.String("warning: " + msg).Foreground(termenv.ANSIYellow))
}

func applyMeta(s string) termenv.Style {
	return style.String(s).Italic()
}

type hexStyleFlags int

const (
	hexStyleDecrypted     hexStyleFlags = 1
	hexStyleContainsNonce hexStyleFlags = 1 << 1
)

var nonceColor = termenv.ANSIYellow

func hexStyle(b []byte, flags hexStyleFlags) string {
	bytesString := ""
	for i, bt := range b {
		btAsString := hex.EncodeToString([]byte{bt})
		if i != 0 {
			bytesString += " "
		}
		if flags&hexStyleContainsNonce == hexStyleContainsNonce && i <= 1 {
			bytesString += style.String(btAsString).Foreground(nonceColor).String()
		} else {
			bytesString += style.String(btAsString).Foreground(termenv.ANSIGreen).String()
		}
	}

	resp := fmt.Sprintf("[%s]", bytesString)

	if flags&hexStyleDecrypted == hexStyleDecrypted {
		resp += style.String(" Decrypted").Foreground(termenv.ANSIBrightBlack).String()
	}

	return resp
}

func humanHandle(handle uint16) string {
	handleUUID, ok := handleToUUID[handle]
	if !ok {
		return fmt.Sprintf("(HANDLE uint16(%d))", handle)
	}

	hint, ok := knownProperties[handleUUID]
	hintText := ""
	if ok {
		hintText = fmt.Sprintf(" (%s)", hint)
	}

	uuidParts := strings.Split(handleUUID, "-")
	uuidParts[0] = style.String(uuidParts[0]).Foreground(termenv.ANSIBrightCyan).String()
	styledHandleUuid := strings.Join(uuidParts, "-")

	return styledHandleUuid + hintText
}
