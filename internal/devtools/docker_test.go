package devtools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/projectbluefin/chairlift/internal/dryrun"
	"github.com/projectbluefin/chairlift/internal/journal"
	"github.com/projectbluefin/chairlift/internal/pkexec"
	"github.com/projectbluefin/chairlift/internal/ublue"
)

const (
	dockerServiceCall = "systemctl show docker.service --property=LoadState,ActiveState"
	dockerSocketCall  = "systemctl show docker.socket --property=LoadState,ActiveState"
)

func dockerReport(load, active string) string {
	return "LoadState=" + load + "\nActiveState=" + active + "\n"
}

// Every external command is a local fixture. In particular, neither systemctl
// nor a helper can reach the host, even when testing the exported functions.
func fakeSystemDocker(t *testing.T, service, socket string) (string, string) {
	t.Helper()
	dir := fakeSystemctl(t, "")
	calls := filepath.Join(dir, "calls")
	t.Setenv("DOCKER_TEST_CALLS", calls)
	t.Setenv("DOCKER_TEST_STATE", dir)
	t.Setenv("DOCKER_TEST_STATUS_ERROR", "")
	writeDockerReports(t, dir, service, socket)
	script := `#!/bin/sh
printf 'systemctl %s\n' "$*" >> "$DOCKER_TEST_CALLS"
case "$*" in
'show docker.service --property=LoadState,ActiveState') unit=service ;;
'show docker.socket --property=LoadState,ActiveState') unit=socket ;;
*) exit 99 ;;
esac
if [ "$DOCKER_TEST_STATUS_ERROR" = "$unit" ]; then
  echo 'system manager read denied' >&2
  exit 14
fi
while IFS= read -r line; do printf '%s\n' "$line"; done < "$DOCKER_TEST_STATE/$unit"
`
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := dryrun.Enabled()
	dryrun.Set(false)
	t.Cleanup(func() { dryrun.Set(previous) })
	return calls, dir
}

func writeDockerReports(t *testing.T, dir, service, socket string) {
	t.Helper()
	for name, report := range map[string]string{"service": service, "socket": socket} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(report), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func dockerTestDial(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	previous := dockerDial
	dockerDial = dial
	t.Cleanup(func() { dockerDial = previous })
}

func routeDockerSocket(t *testing.T, socket string) {
	t.Helper()
	dockerTestDial(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "unix" || address != "/var/run/docker.sock" {
			t.Errorf("Docker selected %s %s instead of the fixed system socket", network, address)
			return nil, errors.New("unexpected Docker socket address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, socket)
	})
}

func TestDockerPackagesDescribeOnlyImageProvidedRPMs(t *testing.T) {
	want := []string{"containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-compose-plugin"}
	if got := DockerPackages(); !reflect.DeepEqual(got, want) {
		t.Fatalf("system image inventory = %v, want %v", got, want)
	}
	packages := DockerPackages()
	packages[0] = "changed"
	if !reflect.DeepEqual(DockerPackages(), want) {
		t.Fatal("caller changed the image package inventory")
	}
}

func TestDockerSystemUnitCombinations(t *testing.T) {
	for _, service := range []string{"inactive", "active", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"} {
		for _, socketState := range []string{"inactive", "active", "failed"} {
			t.Run(service+"/"+socketState, func(t *testing.T) {
				calls, _ := fakeSystemDocker(t, dockerReport("loaded", service), dockerReport("loaded", socketState))
				socket, hits := pingServer(t, http.StatusOK, "OK")
				routeDockerSocket(t, socket)
				state, err := DockerStatus(context.Background())
				active := (service != "inactive" && service != "failed") || socketState == "active"
				if err != nil || !state.Available || state.Active != active || state.Ready != active || state.NeedsLogin || state.Unavailable != "" {
					t.Fatalf("system Docker = %+v %v, want active/ready %v", state, err, active)
				}
				if (hits.Load() == 1) != active {
					t.Fatalf("socket pings = %d, active %v", hits.Load(), active)
				}
				assertCalls(t, calls, dockerServiceCall, dockerSocketCall)
			})
		}
	}
}

func TestDockerReadinessUsesOnlyTheFixedSystemSocket(t *testing.T) {
	fakeSystemDocker(t, dockerReport("loaded", "inactive"), dockerReport("loaded", "active"))
	decoy, decoyHits := pingServer(t, http.StatusOK, "OK")
	t.Setenv("DOCKER_HOST", "unix://"+decoy)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Dir(decoy))
	socket, hits := pingServer(t, http.StatusOK, "OK\n")
	routeDockerSocket(t, socket)
	state, err := DockerStatus(context.Background())
	if err != nil || !state.Ready || !state.Active || hits.Load() != 1 || decoyHits.Load() != 0 {
		t.Fatalf("fixed socket readiness = %+v %v, pings %d/%d", state, err, hits.Load(), decoyHits.Load())
	}
}

func TestDockerMissingAndUnusableUnitsAreNotInstallable(t *testing.T) {
	for _, unit := range []string{"service", "socket"} {
		for _, load := range []string{"not-found", "masked", "error", "bad-setting", "merged", "stub"} {
			t.Run(unit+"/"+load, func(t *testing.T) {
				service, socket := dockerReport("loaded", "inactive"), dockerReport("loaded", "inactive")
				if unit == "service" {
					service = dockerReport(load, "inactive")
				} else {
					socket = dockerReport(load, "inactive")
				}
				calls, _ := fakeSystemDocker(t, service, socket)
				state, err := DockerStatus(context.Background())
				if err != nil || state.Available || state.Active || state.Ready || state.Unavailable == "" {
					t.Fatalf("unusable unit = %+v %v", state, err)
				}
				if load == "not-found" && !strings.Contains(state.Unavailable, "system image") {
					t.Fatalf("missing unit lacks image prerequisite: %q", state.Unavailable)
				}
				var prerequisite *PrerequisiteError
				if err := setDocker(context.Background(), true, nil, func(context.Context, bool) error {
					t.Fatal("unavailable image attempted a privileged mutation")
					return nil
				}); !errors.As(err, &prerequisite) {
					t.Fatalf("unusable image did not refuse activation: %v", err)
				}
				assertCalls(t, calls, dockerServiceCall, dockerSocketCall, dockerServiceCall, dockerSocketCall)
			})
		}
	}
}

func TestDockerReportsBothUnitReadAndParseFailures(t *testing.T) {
	for _, unit := range []string{"service", "socket"} {
		t.Run(unit+" read", func(t *testing.T) {
			fakeSystemDocker(t, dockerReport("loaded", "active"), dockerReport("loaded", "active"))
			t.Setenv("DOCKER_TEST_STATUS_ERROR", unit)
			state, err := DockerStatus(context.Background())
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 14 || !strings.Contains(err.Error(), "system manager read denied") {
				t.Fatalf("lost original systemctl read failure: %v", err)
			}
			if state != (DockerState{}) {
				t.Fatalf("partial %s unit read exposed unverified state: %+v", unit, state)
			}
			if err := setDocker(context.Background(), true, nil, func(context.Context, bool) error {
				t.Fatal("failed read allowed activation")
				return nil
			}); err == nil {
				t.Fatal("failed observation reported success")
			}
		})
		for _, report := range []string{"", "LoadState=loaded\n", "ActiveState=active\n", "LoadState=\nActiveState=active\n", "LoadState=garbage\nActiveState=active\n", "LoadState=loaded\nActiveState=garbage\n", "LoadState=loaded\nLoadState=loaded\nActiveState=active\n", "LoadState=loaded\nActiveState=active\nActiveState=active\n"} {
			t.Run(unit+" parse "+report, func(t *testing.T) {
				service, socket := dockerReport("loaded", "active"), dockerReport("loaded", "active")
				if unit == "service" {
					service = report
				} else {
					socket = report
				}
				fakeSystemDocker(t, service, socket)
				if state, err := DockerStatus(context.Background()); err == nil || state != (DockerState{}) {
					t.Fatalf("malformed %s exposed unverified state: %+v %v", unit, state, err)
				}
			})
		}
	}
}

func TestDockerSocketFailuresPreserveTheirCause(t *testing.T) {
	for _, failure := range []error{os.ErrPermission, os.ErrNotExist, context.Canceled, context.DeadlineExceeded, errors.New("connection refused")} {
		t.Run(failure.Error(), func(t *testing.T) {
			fakeSystemDocker(t, dockerReport("loaded", "inactive"), dockerReport("loaded", "active"))
			dockerTestDial(t, func(context.Context, string, string) (net.Conn, error) { return nil, failure })
			state, err := DockerStatus(context.Background())
			login := errors.Is(failure, os.ErrPermission)
			if !errors.Is(err, failure) || !state.Available || state.Ready || !state.Active || state.NeedsLogin != login || errors.Is(err, ErrDockerNewLogin) != login {
				t.Fatalf("socket failure lost state/cause: %+v %v", state, err)
			}
		})
	}
}

func TestDockerEnableRequiresObservedReadinessAfterTheHelper(t *testing.T) {
	for _, mode := range []string{"ready", "new login", "connection refused", "bad ping", "inactive", "failed", "post service read", "post socket read"} {
		t.Run(mode, func(t *testing.T) {
			calls, dir := fakeSystemDocker(t, dockerReport("loaded", "inactive"), dockerReport("loaded", "inactive"))
			socket, _ := pingServer(t, http.StatusOK, "OK")
			routeDockerSocket(t, socket)
			failure := errors.New("daemon connection refused")
			if mode == "new login" || mode == "connection refused" {
				if mode == "new login" {
					failure = os.ErrPermission
				}
				dockerTestDial(t, func(context.Context, string, string) (net.Conn, error) { return nil, failure })
			}
			if mode == "bad ping" {
				socket, _ = pingServer(t, http.StatusInternalServerError, "OK")
				routeDockerSocket(t, socket)
			}
			applied := 0
			var stages []string
			err := setDocker(context.Background(), true, func(stage string) { stages = append(stages, stage) }, func(_ context.Context, enabled bool) error {
				applied++
				if !enabled {
					t.Fatal("enable dispatched disable")
				}
				active := "active"
				if mode == "inactive" || mode == "failed" {
					active = mode
				}
				writeDockerReports(t, dir, dockerReport("loaded", active), dockerReport("loaded", active))
				if strings.HasPrefix(mode, "post ") {
					t.Setenv("DOCKER_TEST_STATUS_ERROR", strings.Fields(mode)[1])
				}
				return nil
			})
			if applied != 1 || len(stages) != 1 || (err == nil) != (mode == "ready") {
				t.Fatalf("activation %q = %v, mutations %d, stages %v", mode, err, applied, stages)
			}
			if mode == "new login" && (!errors.Is(err, ErrDockerNewLogin) || !errors.Is(err, os.ErrPermission) || errors.Is(err, ErrNewLogin)) {
				t.Fatalf("completed group grant lost its distinct new-login outcome: %v", err)
			}
			if mode == "connection refused" && !errors.Is(err, failure) {
				t.Fatalf("daemon failure was hidden as a login request: %v", err)
			}
			for _, call := range recordedCalls(t, calls) {
				if call != dockerServiceCall && call != dockerSocketCall {
					t.Fatalf("activation ran Homebrew or a user service mutation: %s", call)
				}
			}
		})
	}
}

func TestDockerHelperFailuresPreserveObservedStateAndOriginalErrors(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		for _, code := range []int{1, 126, 127} {
			failure := &ublue.Error{Message: "helper failed", Err: exec.Command("/bin/sh", "-c", "exit "+strconv.Itoa(code)).Run()}
			calls, _ := fakeSystemDocker(t, dockerReport("loaded", "active"), dockerReport("loaded", "active"))
			socket, _ := pingServer(t, http.StatusOK, "OK")
			routeDockerSocket(t, socket)
			if err := setDocker(context.Background(), enabled, nil, func(context.Context, bool) error { return failure }); err != failure {
				t.Fatalf("helper failure replaced: %v, want %v", err, failure)
			}
			assertCalls(t, calls, dockerServiceCall, dockerSocketCall)
			state, err := DockerStatus(context.Background())
			if err != nil || !state.Active || !state.Ready {
				t.Fatalf("failed/dismissed mutation changed observed state: %+v %v", state, err)
			}
		}
	}
}

func TestDockerDisableConfirmsBothUnitsStoppedAndRetainsFiles(t *testing.T) {
	for _, mode := range []string{"stopped", "service active", "socket active", "socket activating", "service deactivating", "post service read", "post socket read"} {
		t.Run(mode, func(t *testing.T) {
			calls, dir := fakeSystemDocker(t, dockerReport("loaded", "active"), dockerReport("loaded", "active"))
			paths := []string{filepath.Join(dir, "docker-data", "volumes", "project"), filepath.Join(dir, "docker.service"), filepath.Join(dir, "group"), filepath.Join(dir, "docker-ce")}
			for _, path := range paths {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("keep Docker files"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// Stopping never depends on this session's permission to ping Docker.
			dockerTestDial(t, func(context.Context, string, string) (net.Conn, error) {
				t.Error("disable pinged the socket, which could reactivate Docker")
				return nil, os.ErrPermission
			})
			err := setDocker(context.Background(), false, nil, func(_ context.Context, enabled bool) error {
				if enabled {
					t.Fatal("disable dispatched enable")
				}
				service, socket := "inactive", "inactive"
				switch mode {
				case "service active":
					service = "active"
				case "socket active":
					socket = "active"
				case "socket activating":
					socket = "activating"
				case "service deactivating":
					service = "deactivating"
				}
				writeDockerReports(t, dir, dockerReport("loaded", service), dockerReport("loaded", socket))
				if strings.HasPrefix(mode, "post ") {
					t.Setenv("DOCKER_TEST_STATUS_ERROR", strings.Fields(mode)[1])
				}
				return nil
			})
			if (err == nil) != (mode == "stopped") {
				t.Fatalf("disable mode %q = %v", mode, err)
			}
			for _, path := range paths {
				if data, err := os.ReadFile(path); err != nil || string(data) != "keep Docker files" {
					t.Fatalf("disable changed %s: %q %v", path, data, err)
				}
			}
			for _, call := range recordedCalls(t, calls) {
				if call != dockerServiceCall && call != dockerSocketCall {
					t.Fatalf("disable ran an install or user-systemctl mutation: %s", call)
				}
			}
		})
	}
}

func TestDockerCanStopAnActiveServiceWhenItsSocketIsMasked(t *testing.T) {
	_, dir := fakeSystemDocker(t, dockerReport("loaded", "active"), dockerReport("masked", "inactive"))
	if err := setDocker(context.Background(), false, nil, func(context.Context, bool) error {
		writeDockerReports(t, dir, dockerReport("loaded", "inactive"), dockerReport("masked", "inactive"))
		return nil
	}); err != nil {
		t.Fatalf("unavailable socket stranded running Docker: %v", err)
	}
}

func TestDockerDryRunJournalsOnlyTheFixedSystemHelper(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enable", false: "disable"}[enabled], func(t *testing.T) {
			calls, _ := fakeSystemDocker(t, dockerReport("loaded", "inactive"), dockerReport("loaded", "inactive"))
			path := filepath.Join(t.TempDir(), "journal.jsonl")
			t.Setenv(journal.PathEnv, path)
			journal.Reset()
			t.Cleanup(journal.Reset)
			dryrun.Set(true)
			if err := SetDocker(context.Background(), enabled, nil); err != nil {
				t.Fatalf("dry-run required live Docker: %v", err)
			}
			assertCalls(t, calls, dockerServiceCall, dockerSocketCall)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			command := "docker-disable"
			if enabled {
				command = "docker-enable"
			}
			var entries []journal.Entry
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var entry journal.Entry
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					t.Fatal(err)
				}
				entries = append(entries, entry)
			}
			want := []string{pkexec.Command, "/usr/bin/chairlift-helper", command, "--dry-run"}
			if len(entries) != 1 || !reflect.DeepEqual(entries[0].WouldRun, want) || entries[0].Suppressed != journal.SuppressedDryRun {
				t.Fatalf("preview did not remain at the journaled fixed-helper boundary: %+v", entries)
			}
			state, err := DockerStatus(context.Background())
			if err != nil || !state.Available || state.Active || state.Ready {
				t.Fatalf("preview invented Docker state: %+v %v", state, err)
			}
		})
	}
}

func TestDockerCancellationPreventsMutationAndSurvivesPostApplyRead(t *testing.T) {
	for _, afterApply := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			fakeSystemDocker(t, dockerReport("loaded", "inactive"), dockerReport("loaded", "inactive"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !afterApply {
				cancel()
			}
			applied := false
			err := setDocker(ctx, enabled, nil, func(context.Context, bool) error {
				applied = true
				cancel()
				return nil
			})
			if !errors.Is(err, context.Canceled) || applied != afterApply {
				t.Fatalf("canceled mutation = %v, applied %v, want %v", err, applied, afterApply)
			}
		}
	}
}

func TestDockerStatusTimeoutBoundsUnitReadsAndSocketPing(t *testing.T) {
	for _, stage := range []string{"units", "ping"} {
		t.Run(stage, func(t *testing.T) {
			_, dir := fakeSystemDocker(t, dockerReport("loaded", "active"), dockerReport("loaded", "active"))
			previous := statusTimeout
			statusTimeout = 50 * time.Millisecond
			t.Cleanup(func() { statusTimeout = previous })
			if stage == "units" {
				if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nexec /bin/sleep 10\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				dockerTestDial(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(100 * time.Millisecond):
						return nil, context.DeadlineExceeded
					}
				})
			}
			_, err := DockerStatus(context.Background())
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unbounded or lost %s timeout: %v", stage, err)
			}
		})
	}
}

func TestDockerPingBodyReadFailureRemainsAnError(t *testing.T) {
	fakeSystemDocker(t, dockerReport("loaded", "active"), dockerReport("loaded", "active"))
	dockerTestDial(t, func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
				return
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nOK")
		}()
		return client, nil
	})
	state, err := DockerStatus(context.Background())
	if !state.Active || state.Ready || state.NeedsLogin || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated ping body hid its cause: %+v %v", state, err)
	}
}
