package main

import (
	"os"
	"testing"
)

// TestMain permite reexecutar o binário de teste como o próprio gate: quando
// GOVERNANCE_GATE_EXEC=1, o processo roda main() em vez da suíte. Assim os
// testes de integração exercitam o binário REAL sem depender do toolchain.
func TestMain(m *testing.M) {
	if os.Getenv("GOVERNANCE_GATE_EXEC") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}
