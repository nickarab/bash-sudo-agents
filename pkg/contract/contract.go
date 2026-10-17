// Package contract define o contrato de entrada/saída do hook PreToolUse e as
// decisões da taxonomia anti-fadiga.
package contract

import (
	"encoding/json"
	"strings"
)

// Decision é a taxonomia de decisões. O valor ZERO é ForceAsk por construção:
// qualquer caminho que esqueça de atribuir uma decisão falha fechado.
type Decision int

const (
	ForceAsk Decision = iota // zero value -> fail-closed
	Deny
	Ask
	Allow
	AutoApprove
)

func (d Decision) String() string {
	switch d {
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	case Allow:
		return "allow"
	case AutoApprove:
		return "auto_approve"
	default:
		return "force_ask"
	}
}

// Output é o documento JSON emitido em stdout.
type Output struct {
	Decision  string          `json:"decision"`
	Reason    string          `json:"reason,omitempty"`
	Overwrite *OverwriteField `json:"overwrite,omitempty"`
}

// OverwriteField carrega o comando sintetizado pelo compressor/cache.
type OverwriteField struct {
	CommandLine string `json:"CommandLine"`
}

// Payload é a visão tolerante do JSON entregue pelo host.
type Payload struct {
	ToolName   string
	Cmd        string
	TargetRaw  string
	Cwd        string
	Workspaces []string
	Raw        []byte
}

// ParsePayload extrai os campos com a mesma tolerância de schema do motor
// legado: aceita `toolCall.args.{CommandLine|command}`, `TargetFile|file_path`,
// `Cwd|cwd`, `cwd` de topo e `workspacePaths`.
func ParsePayload(data []byte, home string) (Payload, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return Payload{}, err
	}
	toolCall, _ := root["toolCall"].(map[string]any)
	args, _ := toolCall["args"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}

	p := Payload{Raw: data}
	p.ToolName = strings.TrimSpace(firstString(toolCall["name"], root["tool"], root["toolName"]))
	p.Cmd = strings.TrimSpace(firstString(args["CommandLine"], args["command"], root["command"]))
	p.TargetRaw = strings.TrimSpace(firstString(args["TargetFile"], args["file_path"], root["target"], root["file_path"]))
	if cwd := firstString(root["cwd"], args["Cwd"], args["cwd"]); cwd != "" {
		p.Cwd = cwd
	} else {
		p.Cwd = home
	}
	if ws, ok := root["workspacePaths"].([]any); ok {
		for _, x := range ws {
			if s, ok := x.(string); ok && s != "" {
				p.Workspaces = append(p.Workspaces, s)
			}
		}
	}
	return p, nil
}

func firstString(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
