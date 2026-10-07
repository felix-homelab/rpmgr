A clean module used by `test-checks.sh` to test `.golangci.yml`: the tests copy it, add one file
that breaks a rule, and expect `check-golangci.sh` to fail. It has the same module path as rpmgr,
so the package-scoped rules apply to it.
