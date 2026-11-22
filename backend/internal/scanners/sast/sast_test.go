package sast

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"limier/internal/scanners/source"
)

func file(path, src string) source.File {
	lang := source.Lang(path)
	return source.File{Path: path, Lang: lang, Src: []byte(src), Code: source.Strip([]byte(src), lang)}
}

func TestRules(t *testing.T) {
	cp := "const cp = require('child_process');\n"
	cases := []struct {
		name, rule, src string // rule "" means no issue expected
	}{
		{"eval", "sast.eval", "eval(userCode)"},
		{"new Function", "sast.eval", "const f = new Function('a', body)"},
		{"setTimeout string", "sast.eval", "setTimeout('run(' + x + ')', 10)"},
		{"setTimeout fn", "", "setTimeout(() => run(x), 10); setTimeout(run, 5)"},
		{"method eval", "", "await page.eval(script); // eval(x)"},

		{"exec concat", "sast.command-injection", cp + "cp.exec('git log ' + branch)"},
		{"exec destructured template", "sast.command-injection", "const { execSync } = require('child_process');\nexecSync(`ls ${dir}`)"},
		{"spawn shell", "sast.command-injection", cp + "cp.spawn(cmd, { shell: true })"},
		{"exec literal", "", cp + "cp.exec('git status')"},
		{"spawn no shell", "", cp + "cp.spawn(cmd, ['a'])"},
		{"regexp exec", "", cp + "const m = re.exec(line)"},
		{"exec without child_process", "", "db.exec(sql)"},

		{"sql template", "sast.sql-injection", "db.query(`SELECT * FROM t WHERE id = ${id}`)"},
		{"sql concat", "sast.sql-injection", "await pool.query('DELETE FROM t WHERE id = ' + id)"},
		{"prisma unsafe", "sast.sql-injection", "prisma.$queryRawUnsafe(`SELECT * FROM t WHERE a = ${a}`)"},
		{"sql params", "", "db.query('SELECT * FROM t WHERE id = $1', [id])"},
		{"sql tagged", "", "db.query(sql`SELECT * FROM t WHERE id = ${id}`)"},
		{"non sql template", "", "router.query(`/users/${id}`)"},

		{"innerHTML", "sast.xss", "el.innerHTML = html"},
		{"insertAdjacentHTML", "sast.xss", "el.insertAdjacentHTML('beforeend', row)"},
		{"document.write", "sast.xss", "document.write(msg)"},
		{"document.write literal", "", "document.write('<p>hi</p>')"},
		{"react", "sast.xss", "return <div dangerouslySetInnerHTML={{ __html: html }} />"},
		{"innerHTML literal", "", "el.innerHTML = ''; if (el.innerHTML == x) {}"},
		{"textContent", "", "el.textContent = html"},

		{"rejectUnauthorized", "sast.tls-disabled", "new https.Agent({ rejectUnauthorized: false })"},
		{"tls env", "sast.tls-disabled", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"},
		{"tls env bracket", "sast.tls-disabled", "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0"},
		{"tls ok", "", "new https.Agent({ rejectUnauthorized: true })\n// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"},
		{"insecure no agent", "", "const opts = { insecure: true }"},

		{"md5", "sast.weak-hash", "crypto.createHash('md5').update(x)"},
		{"crypto-js", "sast.weak-hash", "import CryptoJS from 'crypto-js'\nCryptoJS.SHA1(x)"},
		{"sha256", "", "crypto.createHash('sha256').update(x)"},

		{"random token", "sast.weak-random", "const resetToken = Math.random().toString(36)"},
		{"random ui", "", "const angle = Math.random() * 360"},

		{"readFile req", "sast.path-traversal", "fs.readFile(path.join(root, req.params.name), cb)"},
		{"sendFile query", "sast.path-traversal", "res.sendFile(req.query.f)"},
		{"readFile const", "", "fs.readFileSync(path.join(__dirname, 'a.txt'))"},

		{"redirect", "sast.open-redirect", "res.redirect(req.query.next)"},
		{"location", "sast.open-redirect", "window.location.href = url.searchParams.get('next')"},
		{"redirect const", "", "res.redirect('/login'); location.href = '/home'"},

		{"regexp input", "sast.regex-injection", "new RegExp(req.query.q)"},
		{"regexp escaped", "", "new RegExp(escapeRegExp(req.query.q))"},
		{"regexp literal", "", "new RegExp('^a+$')"},

		{"assign body", "sast.prototype-pollution", "Object.assign(user, req.body)"},
		{"merge body", "sast.prototype-pollution", "_.merge(config, req.body)"},
		{"proto set", "sast.prototype-pollution", "obj.__proto__.isAdmin = true"},
		{"nested key", "sast.prototype-pollution", "target[key][sub] = value"},
		{"assign safe", "", "Object.assign({}, defaults); const o = { __proto__: null }; if (k === '__proto__') {}"},

		{"cors pkg", "sast.cors-wildcard", "app.use(cors({\n  origin: true,\n  credentials: true,\n}))"},
		{"cors header", "sast.cors-wildcard", "res.setHeader('Access-Control-Allow-Origin', '*')\nres.setHeader('Access-Control-Allow-Credentials', 'true')"},
		{"cors no creds", "", "app.use(cors({ origin: '*' }))\nres.setHeader('Access-Control-Allow-Origin', '*')"},

		{"cookie httpOnly", "sast.insecure-cookie", "res.cookie('sid', v, { httpOnly: false })"},
		{"cookie secure", "sast.insecure-cookie", "cookie: {\n  secure: false,\n  sameSite: 'lax' }"},
		{"smtp secure", "", "nodemailer.createTransport({ host, port: 587, secure: false })"},

		{"jwt none", "sast.jwt-none", "jwt.verify(t, k, { algorithms: ['none'] })"},
		{"jwt ignoreExpiration", "sast.jwt-none", "jwt.verify(t, k, { ignoreExpiration: true })"},
		{"jwt ok", "", "jwt.verify(t, k, { algorithms: ['HS256'] })"},

		{"node-serialize", "sast.unsafe-deserialization", "const s = require('node-serialize')\ns.unserialize(data)"},
		{"js-yaml load", "sast.unsafe-deserialization", "const yaml = require('js-yaml')\nyaml.load(txt)"},
		{"js-yaml safe", "", "const yaml = require('js-yaml')\nyaml.load(txt, { schema: yaml.JSON_SCHEMA })"},
		{"unserialize other", "", "php.unserialize(data)"},
	}
	for _, c := range cases {
		got := Analyze([]source.File{file("src/a.jsx", c.src)})
		if c.rule == "" {
			if len(got) != 0 {
				t.Errorf("%s: want nothing, got %+v", c.name, got)
			}
			continue
		}
		if len(got) == 0 || got[0].Rule != c.rule {
			t.Errorf("%s: want %s, got %+v", c.name, c.rule, got)
		}
	}
}

func TestDetailAndTestPaths(t *testing.T) {
	src := "eval(aVeryLongVariableNameThatKeepsGoingOnAndOnAndOnUntilItIsWayTooLong + more)"
	got := Analyze([]source.File{file("src/a.js", src), file("src/a.test.ts", src)})
	if len(got) != 2 || got[0].Severity != source.High || got[1].Severity != source.Medium {
		t.Fatalf("got %+v", got)
	}
	d := got[0].Detail
	if !strings.HasPrefix(d, "CWE-95 · eval(") || len([]rune(strings.TrimPrefix(d, "CWE-95 · "))) > 60 {
		t.Errorf("detail %q", d)
	}
}

func TestFixture(t *testing.T) {
	files, err := source.Walk("testdata/app")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range Analyze(files) {
		got = append(got, fmt.Sprintf("%s %s:%d %s", i.Severity, i.File, i.Line, i.Rule))
	}
	want := []string{
		"high src/server.js:6 sast.command-injection",
		"high src/server.js:8 sast.sql-injection",
		"medium src/lib/Post.svelte:6 sast.xss",
		"medium src/lib/Post.vue:2 sast.xss",
		"medium src/server.js:10 sast.path-traversal",
		"medium src/server.js:11 sast.open-redirect",
		"medium test/helper.test.js:2 sast.eval",
		"info test/helper.test.js:1 sast.weak-random",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSpeed(t *testing.T) {
	block := "const { exec } = require('child_process')\nfunction f(req, res) {\n  const x = req.query.a + 'b' // comment\n  db.query('SELECT 1', [x])\n  el.textContent = `${x}`\n  return Math.max(1, 2)\n}\n"
	src := strings.Repeat(block, 100000/7)
	f := file("src/big.js", src)
	start := time.Now()
	Analyze([]source.File{f})
	if d := time.Since(start); d > time.Second {
		t.Errorf("100k lines took %v", d)
	}
}

func TestTwoOnOneLine(t *testing.T) {
	got := Analyze([]source.File{file("a.js", "const cp = require('child_process')\ncp.exec('ls'); cp.exec('rm ' + f)")})
	if len(got) != 1 || got[0].Line != 2 {
		t.Errorf("got %+v", got)
	}
}
