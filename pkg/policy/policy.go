// Package policy carrega as listas de caminhos vitais e os conjuntos de
// ferramentas/binários usados pela auditoria constitucional. As listas de
// caminhos ficam em vitals.json (embutida via go:embed) para que a política
// seja versionada junto com o binário.
package policy

import (
	_ "embed"
	"encoding/json"
	"log"
	"sync"
)

//go:embed vitals.json
var vitalsJSON []byte

type vitals struct {
	TopDirs         []string `json:"top_dirs"`
	Files           []string `json:"files"`
	RedirectSafeDev []string `json:"redirect_safe_dev"`
}

var (
	once      sync.Once
	topDirs   map[string]struct{}
	vitalFile map[string]struct{}
	safeDev   map[string]struct{}
)

func load() {
	once.Do(func() {
		var v vitals
		if err := json.Unmarshal(vitalsJSON, &v); err != nil {
			log.Fatalf("policy: vitals.json inválido: %v", err)
		}
		topDirs = toSet(v.TopDirs)
		vitalFile = toSet(v.Files)
		safeDev = toSet(v.RedirectSafeDev)
	})
}

func toSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

// Has informa se a chave pertence ao conjunto.
func Has(set map[string]struct{}, k string) bool {
	_, ok := set[k]
	return ok
}

// Vitals acessores (carregam o JSON uma única vez).
func TopDirs() map[string]struct{}    { load(); return topDirs }
func VitalFiles() map[string]struct{} { load(); return vitalFile }
func SafeDev() map[string]struct{}    { load(); return safeDev }

// Conjuntos de ferramentas do contrato do host (Antigravity).
var (
	// READ_ONLY_TOOLS nunca violam RULE-01..15 -> auto_approve.
	ReadOnlyTools = toSet([]string{
		"view_file", "read_file", "list_dir", "list_files", "grep_search",
		"codebase_search", "search_files", "open_file", "find_by_name",
		"search_web", "read_url_content", "list_permissions",
	})

	// WRITE_TOOLS: escrita/orquestração -> allow (revisão de diff nativa).
	WriteTools = toSet([]string{
		"write_to_file", "create_file", "edit_file", "replace_file_content",
		"multi_replace_file_content", "apply_patch", "delete_file",
		"ask_question", "send_message", "manage_task", "schedule",
		"invoke_subagent", "define_subagent", "manage_subagents", "todo_write",
		"browser_action", "generate_image", "ask_permission",
	})

	// CacheableBins: binários estáticos/diagnósticos com saída cacheável.
	CacheableBins = toSet([]string{"lscpu", "uname", "lspci", "lsusb", "pacman", "yay", "paru"})

	// StaticCatPaths: arquivos estáticos permitidos para cache via `cat`.
	StaticCatPaths = toSet([]string{"/etc/os-release", "/proc/cpuinfo"})

	// DangerousArgs: argumentos que desqualificam qualquer cache.
	DangerousArgs = toSet([]string{
		"-exec", "-delete", "-ok", "-execdir",
		";", "&", "|", ">", "<", "`",
		"$(", "${", "rm", "dd", "mkfs", "shred",
	})

	// ShellBins: interpretadores de shell cujo `-c` é reanalisado.
	ShellBins = toSet([]string{"bash", "sh", "dash", "zsh", "ksh", "mksh", "busybox"})

	// InlineInterpreters: `-c`/`-e`/`--eval` carregam código executável.
	InlineInterpreters = toSet([]string{
		"python", "python2", "python3", "perl", "ruby", "node", "nodejs",
		"php", "lua", "osascript", "pwsh", "powershell", "Rscript",
	})

	// EvalFlags: flags que introduzem código em interpretadores inline.
	EvalFlags = toSet([]string{"-c", "-e", "-r", "--eval", "--print"})

	// UnresolvedOps: operações cujos operandos podem depender de estado do shell.
	UnresolvedOps = toSet([]string{
		"rm", "rmdir", "mv", "cp", "install", "truncate", "tee", "ln", "shred",
		"dd", "sed", "perl", "awk", "rsync", "tar", "chmod", "chown", "unlink",
		"find",
	})

	// MutationBins: mutação direta de arquivo (RULE-02 estendida).
	MutationBins = toSet([]string{"mv", "cp", "install", "truncate", "tee", "ln"})

	// InplaceBins: edição in-place (sed -i, perl -pi, gawk -i inplace).
	InplaceBins = toSet([]string{"sed", "perl", "awk"})

	// GovMutationBins: alvos de mutação relevantes para a governança (RULE-11/12).
	GovMutationBins = toSet([]string{
		"rm", "rmdir", "mv", "cp", "install", "truncate", "tee", "ln", "shred",
		"dd", "sed", "perl", "tar", "rsync", "chmod", "chown", "unlink",
	})

	// PowerVerbs: verbos de systemctl da classe de energia.
	PowerVerbs = toSet([]string{
		"reboot", "poweroff", "halt", "suspend-then-hibernate", "suspend",
		"hibernate", "hybrid-sleep", "kexec",
	})

	// LoginctlVerbs: verbos de loginctl da classe de energia/sessão.
	LoginctlVerbs = toSet([]string{
		"reboot", "poweroff", "suspend", "hibernate", "lock-session",
		"lock-sessions", "terminate-user", "kill-user",
	})

	// ServiceVerbs: verbos que derrubam serviços essenciais da sessão.
	ServiceVerbs = toSet([]string{"stop", "disable", "mask", "kill", "restart"})

	// CriticalServices: serviços cuja parada derruba a sessão.
	CriticalServices = toSet([]string{
		"sddm", "gdm", "ly", "lightdm", "display-manager", "hyprland",
		"gnome-shell", "sway",
	})

	// DiskBins: operações de disco/formatação (RULE-03, force_ask).
	DiskBins = toSet([]string{
		"mkfs", "fdisk", "parted", "umount", "wipefs", "losetup",
		"cryptsetup", "sgdisk", "gdisk", "cfdisk",
	})

	// PrivilegeBins: elevação de privilégio rotineira (RULE-15, ask).
	PrivilegeBins = toSet([]string{"sudo", "doas", "pkexec", "su", "run0"})

	// PackageBins: instaladores de pacote.
	PackageBins = toSet([]string{"pacman", "yay", "paru"})
)

// WorldWritableSymbolic: modos simbólicos que concedem escrita a "others".
var WorldWritableSymbolic = toSet([]string{
	"a+w", "o+w", "go+w", "ugo+w",
	"a=rwx", "a+rwx", "ugo+rwx", "ugo=rwx", "o=rwx", "go=rwx",
})

// RsyncValueFlags: flags do rsync que consomem o próximo token (não é caminho).
var RsyncValueFlags = toSet([]string{
	"-e", "--rsh", "-f", "--filter", "-M", "--remote-option",
	"--exclude", "--include", "--exclude-from", "--include-from",
	"--backup-dir", "--suffix", "--files-from", "--temp-dir", "-T",
	"--link-dest", "--copy-dest", "--compare-dest", "--log-file",
	"--password-file", "--chmod", "--chown", "--out-format", "--log-format",
	"--bwlimit", "--timeout", "--contimeout", "--compress-level", "--partial-dir",
})
