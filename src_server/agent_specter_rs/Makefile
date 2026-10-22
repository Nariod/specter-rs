# Build the specter-rs agent plugin against the exact AdaptixC2 v1.2 ABI:
# same Go version, same GOEXPERIMENT, same axc2 module version as the
# adaptixserver binary (go version -m shows go1.25.4 X:jsonv2,greenteagc).
#
# SPECTER_RS_DIR: beacon checkout used at payload generation time
# (defaults to ~/Documents/specter-rs).

GOEXPERIMENT ?= jsonv2,greenteagc

.PHONY: all plugin test clean

all: plugin

plugin:
	GOEXPERIMENT=$(GOEXPERIMENT) go build -buildmode=plugin -ldflags="-s -w" -o agent_specter_rs.so pl_main.go

# Integration harness: drives the plugin exactly the way the teamserver does
# (ExAgentGenerate: GenerateProfiles then BuildPayload) against the real
# beacon pipeline, without needing the UI. Requires a built plugin? No: it
# links the plugin package as a normal Go program.
test: harness
	./agent_specter_rs_harness

harness:
	go build -o agent_specter_rs_harness harness_main.go pl_main.go

clean:
	rm -f agent_specter_rs.so agent_specter_rs_harness
