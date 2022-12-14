package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
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
	hexStyleUnDecrypted   hexStyleFlags = 1 << 1
	hexStyleContainsNonce hexStyleFlags = 1 << 2
)

var nonceColor = termenv.ANSIYellow
var nonEssentialColor = termenv.ANSIBrightBlack

func hexStyle(b []byte, flags hexStyleFlags) string {
	bytesString := ""
	for i, bt := range b {
		btAsString := hex.EncodeToString([]byte{bt})
		if bytesString != "" {
			bytesString += " "
		}
		if flags&hexStyleContainsNonce == hexStyleContainsNonce && i <= 1 {
			if hideChallenges {
				continue
			}
			bytesString += style.String(btAsString).Foreground(nonceColor).String()
		} else {
			bytesString += style.String(btAsString).Foreground(termenv.ANSIGreen).String()
		}
	}

	resp := fmt.Sprintf("%s[%s]", style.String(strconv.Itoa(len(b))).Italic(), bytesString)

	if flags&hexStyleDecrypted == hexStyleDecrypted {
		resp += style.String(" Decrypted").Foreground(nonEssentialColor).String()
	}

	if flags&hexStyleUnDecrypted == hexStyleUnDecrypted {
		resp += style.String(" Seems encrypted").Foreground(nonEssentialColor).String()
	}

	return resp
}

func humanHandle(handle uint16) string {
	handleUUID, ok := handleToUUID[handle]
	if !ok {
		return fmt.Sprintf("(HANDLE uint16(%d))", handle)
	}

	hint, ok := knownProperties[handleUUID.UUID]
	hintText := ""
	if ok {
		hintText = fmt.Sprintf(" (%s)", hint)
	}

	uuidParts := strings.Split(handleUUID.UUID, "-")
	uuidParts[0] = style.String(uuidParts[0]).Foreground(termenv.ANSIBrightCyan).String()
	if showOnlyFirstPartOfUUID {
		return uuidParts[0] + hintText
	}
	styledHandleUUID := strings.Join(uuidParts, "-")

	return styledHandleUUID + hintText
}
