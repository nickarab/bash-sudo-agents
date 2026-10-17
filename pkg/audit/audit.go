// Package audit escreve o log estruturado (JSONL) da auditoria. Metadados de
// auditoria (regra, hash do comando, latência) ficam exclusivamente aqui — fora
// do contrato de saída do hook.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// MaxBytes é o limite de rotação do log no boot.
const MaxBytes int64 = 8 << 20 // 8 MiB

// Entry é uma linha do audit.log.
type Entry struct {
	TS        string `json:"ts"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	Rule      any    `json:"rule"`
	CmdHash   string `json:"cmd_hash"`
	LatencyMs int    `json:"latency_ms"`
}

// Logger grava entradas em audit.log.
type Logger struct {
	path string
}

// New cria o Logger e roda a rotação por tamanho no boot.
func New(dir string) *Logger {
	l := &Logger{path: filepath.Join(dir, "audit.log")}
	if fi, err := os.Stat(l.path); err == nil && fi.Size() > MaxBytes {
		_ = os.Rename(l.path, l.path+".1")
	}
	return l
}

// Log grava uma entrada. Nunca falha o gate por causa de logging.
func (l *Logger) Log(decision, reason, rule, cmd, cwd string, latencyMs int) {
	entry := Entry{
		TS:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Decision:  decision,
		Reason:    reason,
		Rule:      rule,
		CmdHash:   Hash(cwd, cmd),
		LatencyMs: latencyMs,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

// Hash calcula sha256(cwd+":"+cmd)[:16].
func Hash(cwd, cmd string) string {
	h := sha256.Sum256([]byte(cwd + ":" + cmd))
	return hex.EncodeToString(h[:])[:16]
}
