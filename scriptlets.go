package main

import (
	"bytes"
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"

	roc "github.com/james-antill/rename-on-close"
	//	"github.com/james-antill/repos"
)

var transactionFlag bool

func cmd2string(p string, s ...string) string {
	cmd := exec.Command(p, s...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		panic(fmt.Errorf("Failed Prog: %s %s: %s", p, s, err))
	}
	return out.String()
}

func data2hash(data string) string {
	h := md5.New()
	io.WriteString(h, data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func scriptlet(pkg, T string) (cmd string, data string, hash string) {
	qc := fmt.Sprintf("%s{%sprog}", "%", T)
	qd := fmt.Sprintf("%s{%s}", "%", T)

	rc := cmd2string("rpm", "--nodigest", "--nosignature", "-q",
		"--qf", qc, pkg)
	if rc == "(none)" {
		return "", "", ""
	}

	rd := cmd2string("rpm", "--nodigest", "--nosignature", "-q",
		"--qf", qd, pkg)
	// People do this for Eg. /sbin/ldconfig
	if rd == "(none)" {
		rd = ""
	}
	rh := data2hash("#! " + rc + "\n" + rd)
	return rc, rd, rh
}

func printScriptlet(T, c, d, h string) {
	if c != "" {
		if len(d) == 0 {
			fmt.Printf(" %s: %s (%d)\n", T, c, len(d))
		} else {
			fmt.Printf(" %s: %s (%d:%s)\n", T, c, len(d), h)
		}
	}
}

// CSV is the container for CSV output files/data
type CSV struct {
	dir      string
	csvNevra io.Writer
	csvName  io.Writer
	stats    map[string]int
}

func csvScriptlet(csv *CSV, name, nevra string, T, c, d, h string) {
	if c == "" {
		return
	}
	csv.stats["/"]++
	csv.stats[c]++

	ofname := csv.dir + "/" + nevra + "." + T
	of, err := roc.Create(ofname)
	if err != nil {
		panic(fmt.Errorf("Create(%s): %s", ofname, err))
	}
	defer of.Close() // Ehh, errs
	if _, err := io.WriteString(of, "#! "); err != nil {
		panic(fmt.Errorf("Write(%s): %s", ofname, err))
	}
	if _, err := io.WriteString(of, c); err != nil {
		panic(fmt.Errorf("Write(%s): %s", ofname, err))
	}
	if _, err := io.WriteString(of, "\n"); err != nil {
		panic(fmt.Errorf("Write(%s): %s", ofname, err))
	}
	if _, err := io.WriteString(of, d); err != nil {
		panic(fmt.Errorf("Write(%s): %s", ofname, err))
	}
	if d, _ := of.IsDifferent(); d {
		if err := of.CloseRename(); err != nil {
			panic(fmt.Errorf("Close(%s): %s", ofname, err))
		}
	}

	csvline := fmt.Sprintf("%s,%s,%s,%d,%s\n", nevra, T, c, len(d), h)
	if _, err := io.WriteString(csv.csvNevra, csvline); err != nil {
		panic(fmt.Errorf("Write: pkg=%s: %s", nevra, err))
	}
	csvline = fmt.Sprintf("%s,%s,%s,%d,%s\n", name, T, c, len(d), h)
	if _, err := io.WriteString(csv.csvName, csvline); err != nil {
		panic(fmt.Errorf("Write: pkg=%s: %s", nevra, err))
	}
}

type pkg struct {
	name    string
	epoch   string
	version string
	release string
	arch    string

	nevra string

	preinc string
	preind string
	preinh string

	preunc string
	preund string
	preunh string

	postinc string
	postind string
	postinh string

	postunc string
	postund string
	postunh string

	pretransc string
	pretransd string
	pretransh string

	posttransc string
	posttransd string
	posttransh string
}

func init() {
	flag.BoolVar(&transactionFlag, "transaction", false, "Dump transaction scriptlets too")
}

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) <= 0 {
		panic("Format: <output-dir>")
	}
	ofname := flag.Arg(0)

	irpmsd := cmd2string("rpm", "--nodigest", "--nosignature", "-qa",
		"--qf", "%{name} %{epochnum} %{version} %{release} %{arch}\\n")

	irpmsp := strings.Split(irpmsd, "\n")
	// Remove blank after last \n
	irpms := irpmsp[:len(irpmsp)-1]
	sort.Strings(irpms)
	var pkgs []*pkg
	for _, line := range irpms {
		nevra := strings.Split(line, " ")
		if len(nevra) != 5 {
			fmt.Fprintf(os.Stderr, "Bad line: %s\n", line)
			continue
		}
		p := &pkg{}
		p.name = nevra[0]
		p.epoch = nevra[1]
		p.version = nevra[2]
		p.release = nevra[3]
		p.arch = nevra[4]

		if p.name == "gpg-pubkey" {
			continue
		}

		p.nevra = fmt.Sprintf("%s-%s:%s-%s.%s", p.name,
			p.epoch, p.version, p.release,
			p.arch)

		pkgs = append(pkgs, p)
	}
	fmt.Println("Pkgs:", len(pkgs))
	var wg sync.WaitGroup
	for i := range pkgs {
		p := pkgs[i]
		wg.Add(1)

		go func() {
			defer wg.Done()
			p.preinc, p.preind, p.preinh = scriptlet(p.nevra, "prein")
			p.preunc, p.preund, p.preunh = scriptlet(p.nevra, "preun")
			p.postinc, p.postind, p.postinh = scriptlet(p.nevra, "postin")
			p.postunc, p.postund, p.postunh = scriptlet(p.nevra, "postun")

			if transactionFlag {
				p.pretransc, p.pretransd, p.pretransh = scriptlet(p.nevra, "pretrans")
				p.posttransc, p.posttransd, p.posttransh = scriptlet(p.nevra, "posttrans")
			}
		}()
	}
	wg.Wait()

	if err := os.MkdirAll(ofname+".d", 0755); err != nil {
		panic(fmt.Errorf("Mkdir(%s.d): %s", ofname, err))
	}
	ofV, err := roc.Create(ofname + ".nevra")
	if err != nil {
		panic(fmt.Errorf("Create(%s): %s", ofname+".nevra", err))
	}
	defer ofV.Close() // Ehh, errs
	ofU, err := roc.Create(ofname + ".name")
	if err != nil {
		panic(fmt.Errorf("Create(%s): %s", ofname+".name", err))
	}
	defer ofU.Close() // Ehh, errs

	stats := make(map[string]int)
	csv := &CSV{dir: ofname + ".d", csvNevra: ofV, csvName: ofU, stats: stats}
	for _, p := range pkgs {
		stats["."]++
		op := stats["/"]

		csvScriptlet(csv, p.name, p.nevra,
			"POSTIN", p.postinc, p.postind, p.postinh)
		if transactionFlag {
			csvScriptlet(csv, p.name, p.nevra,
				"POSTTRANS", p.posttransc, p.posttransd, p.posttransh)
		}
		csvScriptlet(csv, p.name, p.nevra,
			"POSTUN", p.postunc, p.postund, p.postunh)
		csvScriptlet(csv, p.name, p.nevra,
			"PREIN", p.preinc, p.preind, p.preinh)
		if transactionFlag {
			csvScriptlet(csv, p.name, p.nevra,
				"PRETRANS", p.pretransc, p.pretransd, p.pretransh)
		}
		csvScriptlet(csv, p.name, p.nevra,
			"PREUN", p.preunc, p.preund, p.preunh)

		// No added scriptlets, so good pkg.
		if op == stats["/"] {
			stats[" "]++
		}

		fmt.Printf("%s (%s)\n", p.name, p.nevra)
		printScriptlet("PREIN", p.preinc, p.preind, p.preinh)
		printScriptlet("PREUN", p.preunc, p.preund, p.preunh)
		printScriptlet("POSTIN", p.postinc, p.postind, p.postinh)
		printScriptlet("POSTUN", p.postunc, p.postund, p.postunh)
		if transactionFlag {
			printScriptlet("PRETRANS", p.pretransc, p.pretransd, p.pretransh)
			printScriptlet("POSTTRANS", p.posttransc, p.posttransd, p.posttransh)
		}
	}

	if d, _ := ofU.IsDifferent(); d {
		name := ofU.Name()
		if err := ofU.CloseRename(); err != nil {
			panic(fmt.Errorf("Close(%s): %s", name, err))
		}
	}
	if d, _ := ofV.IsDifferent(); d {
		name := ofV.Name()
		if err := ofV.CloseRename(); err != nil {
			panic(fmt.Errorf("Close(%s): %s", name, err))
		}
	}

	fmt.Printf("STATS:\n"+
		"  All-Pkgs: %d\n  Good-Pkgs: %d\n  Scripts: %d\n",
		csv.stats["."], csv.stats[" "], csv.stats["/"])
	for k, v := range csv.stats {
		switch k {
		case ".":
			continue
		case " ":
			continue
		case "/":
			continue
		default:
			fmt.Printf("    T[%s]: %d\n", k, v)
		}
	}
}
