// Command peercheck is the CI gate for the DN42 peers repository.
//
// Tree check (push to main, local runs):
//
//	peercheck --repo . --asn-list asns.txt
//
// PR check (in CI, PR head checked out, base fetched):
//
//	peercheck --repo pr --base origin/main --author "$AUTHOR" \
//	  --app-login 'dn42-autopeer[bot]' --registry-dir registry
//
// Exit status 1 when the gate fails. With GITHUB_OUTPUT set it writes
// auto-mergeable=true|false; under GitHub Actions errors are also emitted
// as annotations.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/oscrx/dn42-operator/internal/peercheck"
	"github.com/oscrx/dn42-operator/internal/registry"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		repo         = flag.String("repo", ".", "peers repository checkout")
		base         = flag.String("base", "", "base ref of the PR (empty: tree check only)")
		head         = flag.String("head", "HEAD", "head revision to check")
		worktree     = flag.Bool("worktree", false, "read the peers dir from disk instead of git (local runs)")
		author       = flag.String("author", "", "PR author login")
		appLogins    = flag.String("app-login", "", "comma-separated logins of the autopeer GitHub App bot")
		registryDir  = flag.String("registry-dir", "", "DN42 registry clone (data/aut-num)")
		asnList      = flag.String("asn-list", "", "file with one ASN per line, instead of a registry clone")
		skipRegistry = flag.Bool("skip-registry", false, "don't check ASNs against the registry (local runs only)")
		peersDir     = flag.String("peers-dir", "peers", "directory with the peer files")
		namespace    = flag.String("namespace", "dn42", "namespace the peers are synced to")
		localASN     = flag.Int64("local-asn", 0, "the router's own ASN, rejected as a peer")
	)
	flag.Parse()

	opt := peercheck.Options{PeersDir: *peersDir, Namespace: *namespace, SkipRegistry: *skipRegistry, LocalASN: *localASN}
	for _, l := range strings.Split(*appLogins, ",") {
		if l = strings.TrimSpace(l); l != "" {
			opt.AppLogins = append(opt.AppLogins, l)
		}
	}
	switch {
	case *registryDir != "" && *asnList != "":
		return fail("use --registry-dir or --asn-list, not both")
	case *registryDir != "":
		r := &registry.Registry{Path: *registryDir}
		if err := r.Load(); err != nil {
			return fail("%v", err)
		}
		opt.Registry = r
	case *asnList != "":
		s, err := registry.LoadList(*asnList)
		if err != nil {
			return fail("%v", err)
		}
		opt.Registry = s
	case !*skipRegistry:
		return fail("set --registry-dir or --asn-list (or --skip-registry for a local run)")
	}

	var in peercheck.Input
	var err error
	if *worktree {
		if *base != "" {
			return fail("--worktree is a tree check; it can't be combined with --base")
		}
		in, err = peercheck.FromDir(*repo, &opt)
	} else {
		in, err = peercheck.FromGit(*repo, *base, *head, *author, &opt)
	}
	if err != nil {
		return fail("%v", err)
	}

	res := peercheck.Check(in, &opt)
	gha := os.Getenv("GITHUB_ACTIONS") == "true"
	for _, f := range res.Errors {
		fmt.Println("ERROR", f)
		if gha {
			if f.File != "" {
				fmt.Printf("::error file=%s::%s\n", escapeProp(f.File), escapeData(f.Message))
			} else {
				fmt.Printf("::error::%s\n", escapeData(f.Message))
			}
		}
	}
	fmt.Printf("%d peer file(s) checked, %d error(s)\n", res.Peers, len(res.Errors))
	if in.PR != nil {
		if res.AutoMergeable {
			fmt.Println("auto-mergeable: yes")
		} else {
			fmt.Println("auto-mergeable: no")
			for _, r := range res.NotAutoMergeable {
				fmt.Println("  -", r)
			}
		}
		if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
			f, err := os.OpenFile(out, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return fail("%v", err)
			}
			_, werr := fmt.Fprintf(f, "auto-mergeable=%v\n", res.AutoMergeable)
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				return fail("write %s: %v", out, werr)
			}
		}
	}
	if !res.OK() {
		return 1
	}
	return 0
}

func fail(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "peercheck: "+format+"\n", args...)
	return 2
}

// Workflow command escaping: data (the message) and properties (file=).
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
