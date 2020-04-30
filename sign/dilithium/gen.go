// +build ignore

package main

import (
	"os"
	"strings"
	"text/template"
)

func main() {
	const fileName = "./impl.go.txt"
	tl, err := template.ParseFiles(fileName)
	if err != nil {
		panic(err)
	}
	for _, s := range []string{
		"Mode1", "Mode1AES",
		"Mode2", "Mode2AES",
		"Mode3", "Mode3AES",
		"Mode4", "Mode4AES",
	} {
		low := strings.ToLower(s)
		off, err := os.Create("impl_" + low + ".go")
		if err != nil {
			panic(err)
		}
		err = tl.Execute(off, struct{ Name, Rcv, Package string }{s, low + "Impl", low})
		if err != nil {
			panic(err)
		}
		err = off.Close()
		if err != nil {
			panic(err)
		}
	}
}
