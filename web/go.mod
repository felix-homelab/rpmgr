// The web UI is not Go code. This file makes web/ a module of its own, so that ./... of the rpmgr
// module stops here and never reaches the Go files some npm packages ship in node_modules.
module github.com/felix-homelab/rpmgr/web

go 1.26.0
