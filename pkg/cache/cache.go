// Package cache implementa o cache local de saídas com TTL, persistido em
// /tmp/antigravity-gate-cache-<uid> (0700, dono = uid efetivo). Toda escrita é
// atômica (flock + tmp + rename) e a leitura valida TTL e integridade.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nickarab/bash-sudo-agents/pkg/policy"
	"github.com/nickarab/bash-sudo-agents/pkg/shparse"
)

// FormatVersion invalida globalmente o cache quando o layout muda.
const FormatVersion = 1

// Dir devolve o diretório de cache por uid.
func Dir(uid int) string {
	return filepath.Join("/tmp", "antigravity-gate-cache-"+strconv.Itoa(uid))
}

// DirFor devolve o diretório de cache, respeitando o override de ambiente
// ANTIGRAVITY_GATE_CACHE_DIR (usado em testes e ambientes isolados).
func DirFor(uid int) string {
	if d := os.Getenv("ANTIGRAVITY_GATE_CACHE_DIR"); d != "" {
		return d
	}
	return Dir(uid)
}

// EnsureDir cria/valida o diretório de cache. Retorna ok=false quando o
// diretório pré-existente não pertence ao uid ou não está em 0700 (cache é
// desabilitado, nunca "consertado").
func EnsureDir(dir string, uid int) bool {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return false
	}
	fi, err := os.Lstat(dir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return false
	}
	if fi.Mode().Perm() != 0o700 {
		_ = os.Chmod(dir, 0o700)
		if fi2, err := os.Lstat(dir); err != nil || fi2.Mode().Perm() != 0o700 {
			return false
		}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != uid {
		return false
	}
	return true
}

var (
	ttlLiteral = regexp.MustCompile(`^(lscpu|uname(\s+-[a-zA-Z]+)?|lspci|lsusb|cat\s+/etc/os-release|cat\s+/proc/cpuinfo)$`)
	ttlSearch  = regexp.MustCompile(`^(pacman|yay|paru)\s+-Ss\s+`)
)

// TTL devolve o TTL em segundos para o comando (0 = não cacheável).
func TTL(cmd string) int {
	if ttlLiteral.MatchString(cmd) {
		return 3600
	}
	if ttlSearch.MatchString(cmd) {
		return 600
	}
	return 0
}

// IsSearch informa se o comando é uma busca de pacote (`-Ss`).
func IsSearch(cmd string) bool { return ttlSearch.MatchString(cmd) }

// Cacheable informa se o comando pode ser wrapado para cache.
func Cacheable(cmd string) bool {
	p := shparse.Parse(cmd, "")
	if len(p.Simples) != 1 || p.HasPipe || p.HasRedirect || p.Background {
		return false
	}
	args := p.Simples[0].ArgsString()
	if len(args) == 0 {
		return false
	}
	if _, ok := policy.CacheableBins[args[0]]; ok {
		for _, a := range args[1:] {
			if policy.Has(policy.DangerousArgs, a) {
				return false
			}
		}
		return true
	}
	if args[0] == "cat" && len(args) == 2 {
		if _, ok := policy.StaticCatPaths[args[1]]; ok {
			return true
		}
	}
	return false
}

// Key calcula a chave do cache (com salt de versão e de locale).
func Key(cmd, cwd, lang, lcall string) string {
	h := sha256.New()
	h.Write([]byte("v" + strconv.Itoa(FormatVersion)))
	h.Write([]byte{0})
	h.Write([]byte(normalizeCmd(cmd)))
	h.Write([]byte{0})
	h.Write([]byte(cwd))
	h.Write([]byte{0})
	h.Write([]byte(lang))
	h.Write([]byte{0})
	h.Write([]byte(lcall))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// normalizeCmd reconstrói o comando a partir da AST (colapsa espaços).
func normalizeCmd(cmd string) string {
	p := shparse.Parse(cmd, "")
	if len(p.Simples) == 1 {
		return strings.Join(p.Simples[0].ArgsString(), " ")
	}
	return strings.Join(strings.Fields(cmd), " ")
}

// OutPath devolve o caminho do arquivo de cache para a chave.
func OutPath(dir, key string) string { return filepath.Join(dir, key+".out") }

// LockPath devolve o caminho do lock para a chave.
func LockPath(dir, key string) string { return filepath.Join(dir, key+".lock") }

// HitCommand devolve o comando de leitura do cache.
func HitCommand(cacheFile string) string { return "cat " + Quote(cacheFile) }

// Wrap devolve o wrapper de escrita do cache. A segunda fase (gravação) é feita
// pelo próprio binário via o subcomando `cache-write`, com rename atômico —
// substitui o `tee` não atômico do motor legado.
func Wrap(cmd, cacheFile, gateBin, key string, ttl int, pipeSuffix string) string {
	p := shparse.Parse(cmd, "")
	if len(p.Simples) != 1 {
		return cmd
	}
	args := p.Simples[0].ArgsString()
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = Quote(a)
	}
	inner := strings.Join(parts, " ")
	if pipeSuffix != "" {
		inner += " | " + pipeSuffix
	}
	return "( " + inner + " ) | " + Quote(gateBin) +
		" cache-write --file " + Quote(cacheFile) + " --ttl " + strconv.Itoa(ttl)
}

type header struct {
	V       int    `json:"v"`
	Created int64  `json:"created"`
	TTL     int    `json:"ttl"`
	Hash    string `json:"sha256"`
}

// Read devolve o conteúdo do cache se válido (TTL + integridade).
func Read(dir, key string, now time.Time) ([]byte, bool) {
	path := OutPath(dir, key)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	nl := strings.IndexByte(string(data), '\n')
	if nl < 0 {
		return nil, false
	}
	var h header
	if err := json.Unmarshal(data[:nl], &h); err != nil {
		return nil, false
	}
	if h.V != FormatVersion || h.TTL <= 0 {
		return nil, false
	}
	if now.Unix() >= h.Created+int64(h.TTL) {
		return nil, false
	}
	body := data[nl+1:]
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != h.Hash {
		return nil, false
	}
	return body, true
}

// Write grava o conteúdo de forma atômica (flock + tmp + fsync + rename).
func Write(dir, key string, now time.Time, ttl int, body []byte) error {
	lockPath := LockPath(dir, key)
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck

	sum := sha256.Sum256(body)
	h := header{V: FormatVersion, Created: now.Unix(), TTL: ttl, Hash: hex.EncodeToString(sum[:])}
	hb, _ := json.Marshal(h)
	tmp := filepath.Join(dir, key+"."+strconv.Itoa(os.Getpid())+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(append(hb, '\n'), body...)); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, OutPath(dir, key))
}

// Quote aplica aspas POSIX seguras.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\"'\\$&|;<>()*?[]{}~`#!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
