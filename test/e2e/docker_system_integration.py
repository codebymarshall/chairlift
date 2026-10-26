"""Live system Docker and PolicyKit proof in the private Dakota fixture.

Real signed engine packages are an image-build prerequisite, never an app
download. The enclosing rootless Podman namespace owns both native managers,
HOME, the system Docker socket, and all daemon data; no host bus/socket is used.
"""

import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "features" / "lib"))
os.environ.pop("NO_AT_BRIDGE", None)

import chairlift_atspi as atspi  # noqa: E402
import wayland_remote  # noqa: E402

PACKAGES = {"containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-compose-plugin"}
READY = "System Docker is ready for this account."
NEEDS_LOGIN = "Log out and back in to use Docker with your new access."
INSTALLABLE = "Enables Developer Mode first if needed, then system Docker for all accounts. Administrator approval is required. No engine packages are installed."
FIXTURE_PASSWORD = b"chairlift-private-fixture-only\n"
SOCKET = Path("/var/run/docker.sock")
VOLUME = "chairlift-system-integration"


class AuthenticationAgent:
    """A real PolicyKit agent, bound to the actual GUI PID on a private PTY."""

    def __init__(self, pid, transcript):
        self.subject = pid
        self.path = transcript
        self.transcript = b""
        self.pending = b""
        self.prompts = 0

    def __enter__(self):
        ready, notify = os.pipe()
        os.set_inheritable(notify, True)
        self.pid, self.terminal = pty.fork()
        if self.pid == 0:
            os.close(ready)
            os.execvp("pkttyagent", ["pkttyagent", "--process", str(self.subject), "--notify-fd", str(notify)])
        os.close(notify)
        try:
            assert select.select([ready], [], [], 20)[0], "PolicyKit agent did not register"
            assert os.read(ready, 1) == b"", "unexpected agent readiness payload"
        except BaseException:
            self.__exit__(None, None, None)
            raise
        finally:
            os.close(ready)
        return self

    def pump(self, eof=False):
        if not select.select([self.terminal], [], [], 0.1)[0]:
            return False
        data = os.read(self.terminal, 4096)
        assert data, "authentication agent exited before the action settled"
        self.transcript += data
        self.pending += data
        prompt = re.search(rb"password:\s*", self.pending, re.IGNORECASE)
        if prompt is None:
            return False
        self.pending = self.pending[prompt.end():]
        self.prompts += 1
        # EOF uses the real agent; its observed exit may be refusal, not dismissal.
        os.write(self.terminal, b"\x04" if eof else FIXTURE_PASSWORD)
        return True

    def end_input(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.pump(eof=True):
                assert b"dx-enable" in self.transcript, self.transcript
                return
        raise AssertionError(f"real authentication prompt missing: {self.transcript!r}")

    def authenticate_until(self, done, timeout=120):
        # An inactive-session auth_admin action can prompt separately for both
        # dx-enable and docker-enable. Keep the agent alive and answer every
        # actual prompt until the entire helper chain has settled.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if done():
                return
            self.pump()
        raise AssertionError(f"authenticated action did not settle: {self.transcript!r}")

    def __exit__(self, *_):
        self.path.write_bytes(self.transcript.replace(FIXTURE_PASSWORD.strip(), b"[fixture password]"))
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.waitpid(self.pid, 0)
        os.close(self.terminal)


def helper_records(journal):
    return [json.loads(line) for line in journal.read_text().splitlines() if line.strip()]


def outcomes(journal):
    return [record for record in helper_records(journal) if "outcome" in record]


def assert_helpers(journal, actions):
    records = helper_records(journal)
    attempts = [record for record in records if "would_run" in record]
    results = outcomes(journal)
    assert len(records) == len(actions) * 2, records
    assert [record["action"] for record in attempts] == actions, records
    assert [record["action"] for record in results] == actions, records
    for record, action in zip(attempts, actions):
        assert record["would_run"] == ["pkexec", "/usr/bin/chairlift-helper", action], records
        assert not record.get("args"), record
    assert results[0]["outcome"] in {"cancelled", "refused"}, records
    assert all(record["outcome"] == "succeeded" for record in results[1:]), records
    account = pwd.getpwuid(os.getuid()).pw_name
    # The helper's reported execution is evidence, not independent process proof.
    for record in results:
        expected = []
        if record["outcome"] == "succeeded":
            if record["action"] == "dx-enable":
                expected = [["usermod", "-aG", group, account] for group in ("docker", "incus-admin", "libvirt", "dialout")]
            elif record["action"] == "docker-enable":
                expected = [["usermod", "-aG", "docker", account], ["systemctl", "enable", "--now", "docker.socket", "docker.service"]]
            elif record["action"] == "docker-disable":
                expected = [["systemctl", "disable", "--now", "docker.socket", "docker.service"]]
        assert record.get("executed", []) == expected, record


def run(*args, check=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    print(f"$ {' '.join(map(str, args))}\n{result.stdout}", flush=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args}:\n{result.stdout}")
    return result


def unit_states():
    return {unit: run("systemctl", "show", unit, "--property=LoadState,ActiveState").stdout
            for unit in ("docker.socket", "docker.service")}


def assert_units(active):
    states = unit_states()
    for state in states.values():
        assert "LoadState=loaded" in state and f"ActiveState={active}" in state, states


def installed_files():
    evidence = Path("/usr/share/chairlift-docker-fixture/packages.json")
    manifest = json.loads(evidence.read_text())
    paths = [Path(name) for package in manifest for name in package["Files"]]
    paths.append(evidence)
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


class DockerHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect(str(SOCKET))


def assert_old_session_denied():
    connection = DockerHTTP("docker", timeout=5)
    try:
        connection.request("GET", "/_ping")
    except PermissionError:
        return
    finally:
        connection.close()
    raise AssertionError("the old session unexpectedly gained Docker socket access")


def docker_request(path, payload=None):
    # This driver keeps its original groups. A real sg child acquires the same
    # new group as the relaunched GUI; no chmod, mock socket or sudo is involved.
    args = ["curl", "--silent", "--show-error", "--fail-with-body", "--unix-socket", str(SOCKET),
            "--write-out", "\n%{http_code}"]
    if payload is not None:
        args += ["--header", "Content-Type: application/json", "--data", json.dumps(payload)]
    args += ["http://docker" + path]
    result = run("sg", "docker", "-c", shlex.join(args)).stdout
    body, status = result.rsplit("\n", 1)
    assert status == ("201" if payload is not None else "200"), result
    return body


def assert_socket_stopped():
    # systemd may retain the socket pathname after closing its listener.
    # Probe from the new-group session, so permission denial cannot fake stop.
    probe = """import errno, socket, sys
try:
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(sys.argv[1])
except OSError as error:
    if error.errno not in (errno.ENOENT, errno.ECONNREFUSED):
        raise
    print(f"Disabled system socket rejects connections: {error}")
else:
    raise AssertionError("disabled Docker still accepts socket connections")
"""
    run("sg", "docker", "-c", shlex.join([sys.executable, "-c", probe, str(SOCKET)]))


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main(binary, output):
    output = Path(output)
    assert_units("inactive")
    assert not SOCKET.exists(), "fixture already has a Docker socket"
    docker_gid = grp.getgrnam("docker").gr_gid
    assert docker_gid not in os.getgroups() and docker_gid != os.getegid(), "fixture account already has Docker session access"
    assert shutil.which("code") is None, "this fixture explicitly covers missing native VS Code"
    assert shutil.which("brew") is None and not Path("/home/linuxbrew/.linuxbrew/bin/brew").exists(), "live system gate must not install unrelated Homebrew tools"
    manifest = json.loads(Path("/usr/share/chairlift-docker-fixture/packages.json").read_text())
    assert {entry["Package"] for entry in manifest} == PACKAGES, manifest
    (output / "packages.json").write_text(json.dumps(manifest, indent=2))
    initial_files = installed_files()
    staged = output / "chairlift"
    shutil.copy2(binary, staged)
    journal = output / "journal.jsonl"
    journal.write_text("")
    env = dict(os.environ)
    env.update(
        CHAIRLIFT_ACTION_JOURNAL=str(journal),
        XDG_CONFIG_HOME=str(Path(env["HOME"]) / ".config"),
        XDG_DATA_HOME=str(Path(env["HOME"]) / ".local" / "share"),
        XDG_CACHE_HOME=str(Path(env["HOME"]) / ".cache"),
    )
    if env.get("CHAIRLIFT_SCHEMA_DIR"):
        env["GSETTINGS_SCHEMA_DIR"] = env["CHAIRLIFT_SCHEMA_DIR"]
    log_path = output / "chairlift.log"
    log_path.write_text("")
    process = None
    subject = None
    app = None

    def launch(new_login=False):
        nonlocal process, subject, app
        offset = log_path.stat().st_size if log_path.exists() else 0
        pidfile = output / "new-login-app.pid"
        command = [str(staged)]
        if new_login:
            pidfile.unlink(missing_ok=True)
            command = ["sg", "docker", "-c", f"echo $$ > {shlex.quote(str(pidfile))}; exec {shlex.quote(str(staged))}"]
        with log_path.open("ab") as log:
            process = subprocess.Popen(command, cwd=output, env=env, stdout=log, stderr=subprocess.STDOUT)
        def started():
            assert process.poll() is None, f"ChairLift exited:\n{log_path.read_text()}"
            return "app: window presented" in log_path.read_text()[offset:]
        assert atspi.poll(started, timeout=60), "ChairLift never presented its window"
        log = log_path.read_text()[offset:]
        assert "Running in dry-run mode" not in log, "live integration accidentally ran in preview"
        assert f"Loaded config from {(output / 'config.dev.yml').resolve()}" in log
        subject = int(pidfile.read_text()) if new_login else process.pid
        if new_login:
            status = Path(f"/proc/{subject}/status").read_text()
            gids = [int(value) for line in status.splitlines() if line.startswith(("Gid:", "Groups:")) for value in line.split()[1:]]
            assert docker_gid in gids, "sg did not give the actual GUI Docker group access"
            (output / "new-login-process-status.txt").write_text(status)
        app = atspi.find_application(timeout=60)
        rows = atspi.poll(lambda: atspi.sidebar_rows(app))
        index = next(i for i, row in enumerate(rows, 1) if atspi.label_text(row) == "Features")
        atspi.press(f"<Alt>{index}")

    def docker_row():
        return atspi.row_containing(atspi.page_root(app), "Enable Docker", timeout=1)

    def toggle():
        return atspi.find(docker_row(), lambda node: atspi.role(node) == "switch", "Docker switch", timeout=1)

    def developer_toggle():
        row = atspi.row_containing(atspi.page_root(app), "Developer Mode", timeout=1)
        return atspi.find(row, lambda node: atspi.role(node) == "switch", "Developer Mode switch", timeout=1)

    def stage_has(title, text):
        group = atspi.find(atspi.page_root(app), lambda node: atspi.role(node) == "grouping" and atspi.name(node) == "Setup activity", "Setup activity", timeout=1)
        row = atspi.row_containing(group, title, timeout=1)
        return text in atspi.all_text_under(row)

    def feedback_has(expected):
        window = atspi.main_window(app)
        if expected in atspi.all_text_under(window):
            return True
        # Onboarding can fail to open a browser in this headless fixture.
        # Read and dismiss queued feedback as a person would; the requested
        # editor failure must still appear, rather than assuming it is first.
        for button in atspi.find_all(window, lambda node: atspi.is_button(node, "Dismiss") and atspi.showing(node)):
            if atspi.role(button.parent) == "alert":
                messages = atspi.all_text_under(button.parent)
                if expected in messages:
                    return True
                print(f"Read queued feedback: {messages!r}", flush=True)
                atspi.activate(button)
        return False

    try:
        launch()
        assert atspi.poll(lambda: atspi.sensitive(toggle()) and not atspi.checked(toggle()) and INSTALLABLE in atspi.all_text_under(docker_row())), "inactive system Docker was not offered"
        assert atspi.poll(lambda: atspi.sensitive(developer_toggle()) and not atspi.checked(developer_toggle())), "fixture must start with Developer Mode off"
        with AuthenticationAgent(subject, output / "auth-blocked.txt") as agent:
            atspi.activate(toggle())
            agent.end_input()
            assert atspi.poll(lambda: atspi.sensitive(toggle()) and not atspi.checked(toggle()) and atspi.sensitive(developer_toggle()) and not atspi.checked(developer_toggle()), timeout=45), "blocked promotion did not restore both controls"
        assert_helpers(journal, ["dx-enable"])
        assert_units("inactive")
        assert not SOCKET.exists(), "blocked promotion activated Docker"
        assert installed_files() == initial_files, "blocked authentication changed engine packages"
        refusal = outcomes(journal)[0]
        if refusal.get("exit_code") == 127:
            assert refusal["outcome"] == "refused" and "Not authorized" in log_path.read_text(), refusal
            expected_status = "Failed"
        else:
            assert refusal.get("exit_code") == 126 or "Request dismissed" in log_path.read_text(), refusal
            expected_status = "Canceled"
        assert atspi.poll(lambda: stage_has("Developer access", expected_status)), f"authentication refusal did not report {expected_status}"
        wayland_remote.screenshot(str(output / "docker-auth-blocked.png"))

        with AuthenticationAgent(subject, output / "auth-enabled.txt") as agent:
            atspi.activate(toggle())
            agent.authenticate_until(lambda: len(outcomes(journal)) == 3)
            assert agent.prompts >= 1, "enable never authenticated through the real agent"
        assert_helpers(journal, ["dx-enable", "dx-enable", "docker-enable"])
        assert atspi.poll(lambda: atspi.checked(toggle()) and atspi.sensitive(toggle()) and NEEDS_LOGIN in atspi.all_text_under(docker_row()), timeout=60), "new group grant was not shown as awaiting login"
        assert atspi.poll(lambda: stage_has("Verify readiness", "Awaiting new login")), "verification invented readiness for the old session"
        assert atspi.poll(lambda: stage_has("VS Code setup", "Failed")), "missing native code was not a separate optional failure"
        assert atspi.poll(lambda: feedback_has("Docker access is enabled, but VS Code setup couldn't finish. See the application log for details.")), "editor failure was hidden or mislabeled as Docker failure"
        assert_units("active")
        assert SOCKET.stat().st_uid == 0 and SOCKET.stat().st_gid == docker_gid, "socket is not system-owned Docker"
        assert_old_session_denied()
        assert atspi.checked(developer_toggle()), "confirmed parent promotion was lost on optional failure"
        assert installed_files() == initial_files, "live GUI installed engine packages"
        assert "native Microsoft VS Code (code) is not installed" in log_path.read_text(), "missing-editor cause was not reported"
        wayland_remote.screenshot(str(output / "docker-awaiting-login.png"))

        stop(process)
        assert atspi.poll(lambda: not any(atspi.name(node) in atspi.APPLICATION_NAMES for node in atspi.children(atspi._tree().root)), timeout=20), "old application remained after shutdown"
        launch(new_login=True)
        assert atspi.poll(lambda: atspi.checked(toggle()) and atspi.sensitive(toggle()) and READY in atspi.all_text_under(docker_row()), timeout=60), "new session did not observe real Docker readiness"
        assert docker_request("/_ping").strip() == "OK", "real system daemon did not answer HTTP 200 OK"
        info = json.loads(docker_request("/info"))
        assert not any(option.startswith("name=rootless") for option in info["SecurityOptions"]), info
        assert info["DockerRootDir"] == "/var/lib/docker", info
        (output / "docker-info.json").write_text(json.dumps(info, indent=2))
        volume = json.loads(docker_request("/volumes/create", {"Name": VOLUME}))
        assert volume["Name"] == VOLUME and volume["Mountpoint"] == f"/var/lib/docker/volumes/{VOLUME}/_data", volume
        (output / "docker-volume.json").write_text(json.dumps(volume, indent=2))
        assert atspi.checked(developer_toggle()), "new login lost Developer Mode"
        assert_helpers(journal, ["dx-enable", "dx-enable", "docker-enable"])
        wayland_remote.screenshot(str(output / "docker-ready.png"))

        with AuthenticationAgent(subject, output / "auth-disabled.txt") as agent:
            atspi.activate(toggle())
            agent.authenticate_until(lambda: len(outcomes(journal)) == 4)
        assert atspi.poll(lambda: not atspi.checked(toggle()) and atspi.sensitive(toggle()) and INSTALLABLE in atspi.all_text_under(docker_row()), timeout=60), "GUI did not observe system Docker disable"
        assert_units("inactive")
        assert_socket_stopped()
        assert_units("inactive")  # A connection must not socket-activate Docker.
        assert installed_files() == initial_files, "disable changed installed packages or native units"
        assert atspi.checked(developer_toggle()) and atspi.sensitive(developer_toggle()), "Docker disable demoted Developer Mode"
        assert_helpers(journal, ["dx-enable", "dx-enable", "docker-enable", "docker-disable"])
        assert pwd.getpwuid(os.getuid()).pw_name in grp.getgrnam("docker").gr_mem, "disable removed account access"
        wayland_remote.screenshot(str(output / "docker-disabled.png"))
        print(f"LIVE DOCKER PROOF: auth {refusal['outcome']} (exit {refusal['exit_code']}, setup {expected_status}) blocks child -> dx-enable then docker-enable -> awaiting new login and separate missing-editor failure -> real sg login observes HTTP 200 system Docker -> disable retains packages, access and parent; root fixture verifies retained volume", flush=True)
    except BaseException:
        if app is not None:
            try:
                with (output / "tree.txt").open("w") as dump:
                    atspi.dump(atspi.main_window(app), dump)
                wayland_remote.screenshot(str(output / "failure.png"))
            except Exception as error:
                print(f"failure accessibility/screenshot unavailable: {error}", flush=True)
        raise
    finally:
        run("journalctl", "--unit", "docker.service", "--unit", "docker.socket", "--no-pager", check=False)
        if process is not None:
            if subject is not None and subject != process.pid:
                try:
                    os.kill(subject, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            stop(process)


if __name__ == "__main__":
    main(*sys.argv[1:])
