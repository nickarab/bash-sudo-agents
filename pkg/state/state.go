// Package state implementa o contador de recusas consecutivas (RULE-10) com
// read-modify-write inteiro sob flock e escrita atômica (tmp + rename).
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// TTLSeconds é o TTL de inatividade do contador (24 h).
const TTLSeconds int64 = 86400

// Schema é a versão do formato.
const Schema = 1

// State é o conteúdo persistido.
type State struct {
	Count      int    `json:"count"`
	LastReject int64  `json:"last_reject"`
	LastCmd    string `json:"last_cmd"`
	Schema     int    `json:"schema"`
}

// Store persiste o State em um arquivo protegido por lock.
type Store struct {
	path string
	lock string
	now  func() time.Time
}

// New cria um Store para o arquivo rejection.json dentro de dir.
func New(dir string) *Store {
	return &Store{
		path: filepath.Join(dir, "rejection.json"),
		lock: filepath.Join(dir, "rejection.lock"),
		now:  time.Now,
	}
}

// Record atualiza o contador e devolve o número de recusas consecutivas.
// `deny` incrementa; qualquer outra decisão zera. Falha de leitura é tratada
// como estado suspeito (count>=1), nunca como zero — o oposto do fail-open
// legado.
func (s *Store) Record(decision, cmd string) (int, error) {
	lock, err := os.OpenFile(s.lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return 0, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck

	prev, corrupt := s.loadLocked()
	if decision == "deny" {
		base := prev.Count
		if corrupt || base < 0 {
			base = 1 // suspeito -> mantém fricção
		}
		count := base + 1
		st := State{Count: count, LastReject: s.now().Unix(), LastCmd: normalizeCmd(cmd), Schema: Schema}
		if err := s.saveLocked(st); err != nil {
			return count, err
		}
		return count, nil
	}
	if prev.Count != 0 || corrupt {
		st := State{Count: 0, LastReject: 0, LastCmd: "", Schema: Schema}
		_ = s.saveLocked(st)
	}
	return 0, nil
}

// Count devolve o contador atual (aplicando TTL).
func (s *Store) Count() int {
	lock, err := os.OpenFile(s.lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
		return 0
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck
	st, _ := s.loadLocked()
	return st.Count
}

// loadLocked lê o estado sob lock. corrupt=true quando o arquivo existe mas é
// ilegível/inválido.
func (s *Store) loadLocked() (State, bool) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, false
		}
		return State{}, true
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, true
	}
	if st.Schema != Schema || st.Count < 0 {
		return State{}, true
	}
	if s.now().Unix()-st.LastReject >= TTLSeconds {
		return State{}, false
	}
	return st, false
}

func (s *Store) saveLocked(st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
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
	return os.Rename(tmp, s.path)
}

func normalizeCmd(cmd string) string {
	fields := make([]byte, 0, len(cmd))
	space := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if !space {
				fields = append(fields, ' ')
				space = true
			}
			continue
		}
		space = false
		fields = append(fields, c)
	}
	out := string(fields)
	for len(out) > 0 && out[len(out)-1] == ' ' {
		out = out[:len(out)-1]
	}
	for len(out) > 0 && out[0] == ' ' {
		out = out[1:]
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}
