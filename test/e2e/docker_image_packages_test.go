package e2e

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDockerFixtureRejectsAdditionalSigningCertificates(t *testing.T) {
	python := requireCommand(t, atspiPython())
	requireCommand(t, "gpg")
	cmd := exec.Command(python, filepath.Join(repoRoot(t), "test", "e2e", "docker_image_packages_test.py"))
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Docker fixture signing-key regression failed: %v\n%s", err, out)
	}
}
