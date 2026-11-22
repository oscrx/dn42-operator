// Command render prints the BIRD snippet dn42-operator renders for peer
// files, or writes them to a directory (-out), for checking a bird.conf:
//
//	go run ./hack/render -out /tmp/peers ../dn42-peers/peers/*.yaml
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oscrx/dn42-operator/internal/autopeer"
	"github.com/oscrx/dn42-operator/internal/bird"
	"github.com/oscrx/dn42-operator/internal/peer"
)

func main() {
	out := flag.String("out", "", "write <name>.conf files here instead of printing")
	tmpl := flag.String("template", "dnpeers", "BIRD template")
	flag.Parse()
	for _, f := range flag.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			fail(err)
		}
		o, err := autopeer.ParsePeerFile(b)
		if err != nil {
			fail(fmt.Errorf("%s: %w", f, err))
		}
		p, verr := peer.FromObject(o)
		if verr != nil {
			fail(fmt.Errorf("%s: %s", f, verr.Message))
		}
		s, err := bird.Renderer{Template: *tmpl}.Render(p)
		if err != nil {
			fail(err)
		}
		if *out == "" {
			fmt.Print(s)
			continue
		}
		if err := os.WriteFile(filepath.Join(*out, p.Name+".conf"), []byte(s), 0o644); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
