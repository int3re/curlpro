// Command curlpro — инструменты сопровождения профилей.
//
//	curlpro validate   прогнать профили через оракула и сверить отпечаток
//	curlpro diff       сравнить два профиля по составу
//	curlpro list       перечислить профили
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "capture":
		err = runCapture(os.Args[2:])
	case "collapse":
		err = runCollapse(os.Args[2:])
	case "validate":
		err = runValidate(os.Args[2:])
	case "diff":
		err = runDiff(os.Args[2:])
	case "list":
		err = runList(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `curlpro — инструменты сопровождения профилей

  capture    снять отпечаток браузера и собрать профиль
  collapse   свести профили в цепочки based_on, оставив только различия
  validate   прогнать профили через оракула и сверить отпечаток с эталоном
  diff       сравнить два профиля по составу расширений и настроек
  list       перечислить профили

Подробности: curlpro <команда> -h
`)
}

// newFlagSet создаёт набор флагов с описанием команды в справке.
func newFlagSet(name, description string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, description)
		fs.PrintDefaults()
	}
	return fs
}
