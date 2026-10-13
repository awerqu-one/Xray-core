package raywire

import (
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validatePrevKey returns 32 copies of b.
func validatePrevKey(b byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = b
	}
	return key
}

// previousPskRow is one case of the table of ValidatePreviousPsk. wantErr is the exact message,
// or empty when the case is valid.
type previousPskRow struct {
	name    string
	psk     []byte
	prev    []byte
	until   time.Time
	wantErr string
}

// previousPskRows is the table of TestValidatePreviousPsk. The load time is fixed, so the
// 14-day limit is exact. Each error branch of the function has at least one row, and the
// rows give its message exactly.
func previousPskRows(now time.Time) []previousPskRow {
	psk := validatePrevKey(0x03)
	prev := validatePrevKey(0x04)
	zero := make([]byte, 32)
	future := now.Add(48 * time.Hour)
	limit := now.Add(MaxPreviousPskOverlap)
	return []previousPskRow{
		{"unset", psk, nil, time.Time{}, ""},
		{"unset with an empty slice", psk, []byte{}, time.Time{}, ""},
		{"unset with no psk", nil, nil, time.Time{}, ""},
		{"valid", psk, prev, future, ""},
		{"expiry in the past is accepted", psk, prev, now.Add(-time.Second), ""},
		{"expiry at the limit", psk, prev, limit, ""},
		{"expiry one second past the limit", psk, prev, limit.Add(time.Second),
			"raywire: previousPskUntil is more than 14 days ahead"},
		{"expiry without previousPsk", psk, nil, future,
			"raywire: previousPskUntil is set without previousPsk"},
		{"previousPsk without expiry", psk, prev, time.Time{},
			"raywire: previousPskUntil must be set with previousPsk"},
		{"previousPsk of 31 bytes", psk, prev[:31], future,
			"raywire: previousPsk must be 32 bytes"},
		{"previousPsk of 33 bytes", psk, append(validatePrevKey(0x04), 0), future,
			"raywire: previousPsk must be 32 bytes"},
		{"previousPsk all zero", psk, zero, future,
			"raywire: previousPsk must not be all zero"},
		{"previousPsk equal to psk", psk, validatePrevKey(0x03), future,
			"raywire: previousPsk must differ from psk"},
		{"psk missing", nil, prev, future,
			"raywire: previousPsk requires a valid psk"},
		{"psk of 31 bytes", psk[:31], prev, future,
			"raywire: previousPsk requires a valid psk"},
		{"psk all zero", zero, prev, future,
			"raywire: previousPsk requires a valid psk"},
	}
}

// TestValidatePreviousPsk checks each row of the table against the single validator, with the
// server's names, and checks that the table covers every error branch of the function once: the
// distinct messages of the table are as many as the error returns of ValidatePreviousPsk.
func TestValidatePreviousPsk(t *testing.T) {
	if MaxPreviousPskOverlap != 14*24*time.Hour {
		t.Fatalf("MaxPreviousPskOverlap = %v, want 14 days", MaxPreviousPskOverlap)
	}
	now := time.Unix(1_800_000_000, 0)
	rows := previousPskRows(now)
	prev := validatePrevKey(0x04)
	messages := map[string]bool{}
	for _, tc := range rows {
		if tc.wantErr != "" {
			messages[tc.wantErr] = true
		}
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePreviousPsk(tc.psk, tc.prev, tc.until, now, serverPreviousPskNames)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("error = %v, want none", err)
				}
				return
			}
			if err == nil || messageOf(err) != tc.wantErr {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), base64.RawURLEncoding.EncodeToString(prev)) {
				t.Fatalf("error %q echoes the previous psk", err)
			}
		})
	}
	if branches := previousPskErrorReturns(t); branches != len(messages) {
		t.Fatalf("ValidatePreviousPsk has %d error branches, the table covers %d distinct messages", branches, len(messages))
	}
}

// previousPskErrorReturns counts the return statements of ValidatePreviousPsk that return an
// error made by errors.New. Each is one message of the function, so it is one branch.
func previousPskErrorReturns(t *testing.T) int {
	t.Helper()
	fn := findFuncDecl(t, parseGoFile(t, "validate.go"), "ValidatePreviousPsk")
	count := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		call, ok := ret.Results[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "New" {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "errors" {
				count++
			}
		}
		return true
	})
	if count == 0 {
		t.Fatal("found no error returns in ValidatePreviousPsk")
	}
	return count
}

// TestSinglePreviousPskValidator checks that there is one validator of previousPsk, and that
// the server and the typed config use it. Among the package's exported functions, only
// ValidatePreviousPsk has a name about previousPsk. newHeadKeys calls it before any key is
// derived. The typed config in infra/conf calls it too, and spells no message of its own.
func TestSinglePreviousPskValidator(t *testing.T) {
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	for _, name := range matches {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, decl := range parseGoFile(t, name).Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !ast.IsExported(fn.Name.Name) {
				continue
			}
			lower := strings.ToLower(fn.Name.Name)
			if strings.Contains(lower, "previous") || strings.Contains(lower, "psk") {
				exported = append(exported, fn.Name.Name)
			}
		}
	}
	if len(exported) != 1 || exported[0] != "ValidatePreviousPsk" {
		t.Fatalf("exported previousPsk functions %v, want only ValidatePreviousPsk", exported)
	}
	if !callsName(findFuncDecl(t, parseGoFile(t, "keys.go"), "newHeadKeys"), "ValidatePreviousPsk") {
		t.Fatal("newHeadKeys does not call ValidatePreviousPsk before it derives a key")
	}

	conf := parseGoFile(t, filepath.Join("..", "..", "infra", "conf", "raywire.go"))
	if !callsSelector(conf, "raywire", "ValidatePreviousPsk") {
		t.Fatal("infra/conf/raywire.go does not call raywire.ValidatePreviousPsk")
	}
	ast.Inspect(conf, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "differ from") {
			t.Fatalf("infra/conf/raywire.go spells a previousPsk message of its own: %s", lit.Value)
		}
		return true
	})
}

// parseGoFile parses one Go file, with its comments dropped. It fails the test when the file
// does not parse.
func parseGoFile(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// findFuncDecl returns the declaration of the function name in f. It fails the test when there is none.
func findFuncDecl(t *testing.T, f *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("no function %s in the file", name)
	return nil
}

// callsName reports whether the body of fn calls the function name directly.
func callsName(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// callsSelector reports whether the file calls pkg.name anywhere.
func callsSelector(f *ast.File, pkg, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == pkg {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
