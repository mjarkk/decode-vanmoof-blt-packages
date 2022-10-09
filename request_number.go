package main

import (
	"fmt"

	"github.com/muesli/termenv"
)

type Nr uint

func (nr Nr) String() string {
	return style.String(fmt.Sprintf("#%d", nr)).Italic().Foreground(termenv.ANSIBrightBlack).String()
}
