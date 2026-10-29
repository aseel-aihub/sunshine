import os, subprocess, re, tempfile, shutil, uuid, ast, time
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

NEBIUS_API_KEY = os.getenv("NEBIUS_API_KEY")
MODEL = "nvidia/nemotron-3-super-120b-a12b"

client = None
if NEBIUS_API_KEY:
    client = OpenAI(
        base_url="https://api.tokenfactory.nebius.com/v1/",
        api_key=NEBIUS_API_KEY,
    )

ORIGINAL_CODE = '''# vulnerable_app.py
import subprocess

def ping_host(host):
    """Command Injection vulnerability"""
    result = subprocess.run(f"ping -c 1 {host}", shell=True,
                             capture_output=True, text=True)
    return result.stdout
'''

FUNCTIONAL_TEST_CODE = '''import pytest
from vulnerable_app import ping_host

def test_ping_returns_real_output_for_valid_host():
    result = ping_host("127.0.0.1")
    assert isinstance(result, str)
    assert len(result) > 20
    assert "127.0.0.1" in result
    assert "transmitted" in result.lower()

def test_ping_handles_unreachable_host_without_crashing():
    result = ping_host("10.255.255.1")
    assert isinstance(result, str)
'''

BASE_IMAGE_TAG = "sunshine-base:latest"

BASE_DOCKERFILE = """FROM python:3.11-slim
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*
RUN pip install pytest
WORKDIR /app
"""

DOCKERFILE_TEMPLATE = """FROM sunshine-base:latest
WORKDIR /app
COPY . .
CMD ["pytest", "-v"]
"""

SIMULATED_HONEYPOT_LOG = [
    "POST /login  username=admin&password=admin123",
    "POST /login  username=admin' OR '1'='1&password=x",
    "GET /login?debug=true&show_source=1",
    "POST /login  username=admin&password=' ; DROP TABLE users; --",
]

PATCH_VERIFIED = "PATCH_VERIFIED"
SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
INCONCLUSIVE = "INCONCLUSIVE"

ARTIFACT_PATH = "/app/hacked.txt"


class CycleResult:
    def __init__(self):
        self.original_code = ORIGINAL_CODE
        self.analysis = ""
        self.exploit_code = ""
        self.patched_code = ""
        self.pre_patch_log = ""
        self.pre_patch_exploit_confirmed = None
        self.post_patch_exploit_log = ""
        self.post_patch_exploit_blocked = None
        self.functional_log = ""
        self.functional_ok = None
        self.attempts = 0
        self.sandboxed = False
        self.durations = {}
        self.errors = []
        self.status = INCONCLUSIVE
        self.status_detail = "Not run"

    @property
    def patch_verified(self):
        return self.status == PATCH_VERIFIED


def _call_model(prompt, timeout=60):
    if client is None:
        raise RuntimeError("NEBIUS_API_KEY is missing. Add it to .env (local) or Secrets (cloud).")
    try:
        scoped_client = client.with_options(timeout=timeout)
        r = scoped_client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
        )
        return r.choices[0].message.content
    except Exception as e:
        raise RuntimeError(f"Model call failed: {e}")


def _strip_code_fences(text):
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\n", "", text)
    text = re.sub(r"\n```$", "", text)
    return text.strip()


def _check_syntax(code):
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, f"Invalid Python syntax: {e}"


def _docker_daemon_ready():
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _ensure_base_image(timeout=180):
    check = subprocess.run(
        ["docker", "image", "inspect", BASE_IMAGE_TAG],
        capture_output=True, timeout=10,
    )
    if check.returncode == 0:
        return True, ""
    tmp = tempfile.mkdtemp(prefix="sunshine_base_")
    try:
        with open(os.path.join(tmp, "Dockerfile"), "w") as f:
            f.write(BASE_DOCKERFILE)
        build = subprocess.run(
            ["docker", "build", "-t", BASE_IMAGE_TAG, tmp],
            capture_output=True, text=True, timeout=timeout,
        )
        if build.returncode != 0:
            return False, "Base image build failed:\n" + build.stdout[-800:] + build.stderr[-800:]
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Base image build timed out."
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _write_files(workdir, files):
    for name, content in files.items():
        with open(os.path.join(workdir, name), "w") as f:
            f.write(content)


def _to_text(x):
    if x is None:
        return ""
    return x.decode(errors="replace") if isinstance(x, bytes) else x


def _run_in_docker(workdir, tag, timeout=90, check_artifact=None):
    """
    Returns (verdict, log, status, artifact_present).
    verdict: True = pytest exit 0, False = pytest exit 1, None = inconclusive.
    artifact_present: True/False when check_artifact is inspected directly in
    the container filesystem (independent of pytest's own assert), else None.
    The final security verdict is cross-checked against this evidence so a
    misleading pytest exit code alone cannot flip it.
    """
    container_name = f"{tag}-{uuid.uuid4().hex[:6]}"
    try:
        build = subprocess.run(
            ["docker", "build", "-t", tag, workdir],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "Docker build timed out.", "error", None

    if build.returncode != 0:
        return None, "Docker build failed:\n" + build.stdout[-1000:] + build.stderr[-1000:], "error", None

    exit_code = None
    log = ""
    try:
        run = subprocess.run(
            ["docker", "run", "--name", container_name,
             "--network", "none", "--memory", "256m", "--cpus", "1",
             "--pids-limit", "64", tag],
            capture_output=True, text=True, timeout=timeout,
        )
        exit_code = run.returncode
        log = run.stdout + run.stderr
    except subprocess.TimeoutExpired as e:
        log = _to_text(e.stdout) + _to_text(e.stderr)
        exit_code = None
        # On timeout the container may still be alive; stop it before we
        # inspect its filesystem, so docker cp reads a settled state.
        subprocess.run(["docker", "stop", container_name], capture_output=True, timeout=15)

    artifact_present = None
    if check_artifact is not None:
        cp = subprocess.run(
            ["docker", "cp", f"{container_name}:{check_artifact}", "-"],
            capture_output=True, timeout=10,
        )
        artifact_present = (cp.returncode == 0)

    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=10)
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, timeout=10)

    if exit_code is None:
        return None, "Docker run timed out.\n" + log, "error", artifact_present
    if exit_code == 0:
        return True, log, "ok", artifact_present
    if exit_code == 1:
        return False, log, "ok", artifact_present
    return None, f"pytest exited with code {exit_code} (not a valid pass/fail result):\n{log}", "error", artifact_present


class SunShineAgent:
    def __init__(self):
        self.persona = (
            "You are SunShine, an autonomous security agent capable of thinking "
            "like an attacker, a defender, a reporting analyst, and a threat hunter."
        )

    def analyze_vulnerability(self, code):
        prompt = f"""{self.persona}

Role: ANALYST (initial triage).
Look at this code and identify: the exact vulnerable line/pattern, why it is
dangerous, and the vulnerability category (e.g. CWE-78 Command Injection).
Do not propose a fix yet. 2-4 sentences only.

Code:
{code}"""
        return _call_model(prompt)

    def write_exploit(self, code):
        prompt = f"""{self.persona}

Role: ATTACKER.
This Python code has a vulnerability:
{code}
Write a single pytest file named test_exploit.py that imports ping_host from
vulnerable_app, calls it with a malicious input that creates a file named
hacked.txt in the current directory, then asserts that hacked.txt exists.
Return only raw Python code. No explanations, no markdown fences."""
        return _call_model(prompt)

    def write_patch(self, code, previous_log=""):
        extra = f"\nA previous patch attempt's verification log to learn from:\n{previous_log[:800]}" if previous_log else ""
        prompt = f"""{self.persona}

Role: DEFENDER.
This code has a Command Injection vulnerability:
{code}
Fix it using subprocess.run with a list of arguments instead of shell=True,
keeping the exact function name ping_host. It must still successfully ping a
valid host and return the real command output as a string — do not return an
empty string or a placeholder.{extra}
Return only raw Python code. No explanations, no markdown fences."""
        return _call_model(prompt)

    def generate_report(self, result: "CycleResult"):
        prompt = f"""{self.persona}

Role: ANALYST (final report).
Build the report strictly from this evidence. If status is not {PATCH_VERIFIED},
say plainly in "Fix Applied" that the fix was not fully verified.

Status: {result.status}
Status detail: {result.status_detail}
Attempts used: {result.attempts}
Sandboxed execution (Docker): {result.sandboxed}
Exploit confirmed on original code: {result.pre_patch_exploit_confirmed}
Exploit blocked after patch: {result.post_patch_exploit_blocked}
Normal functionality preserved after patch: {result.functional_ok}
Errors encountered: {result.errors if result.errors else "none"}

Original code:
{result.original_code}

Exploit code:
{result.exploit_code or "(not generated)"}

Patched code:
{result.patched_code or "(no verified patch)"}

Write exactly 4 sections: Vulnerability Summary, Attack Evidence, Fix Applied, Recommendation.
1-3 sentences per section. No introductions, no markdown fences."""
        return _call_model(prompt)

    def honeypot_scan(self):
        log_text = "\n".join(SIMULATED_HONEYPOT_LOG)
        prompt = f"""{self.persona}

Role: THREAT HUNTER.
Below is SIMULATED honeypot traffic (fictional sample data, not real captured
traffic) from a decoy login endpoint.

{log_text}

For each line, identify the likely attack technique in one short line.
Then write a 2-3 sentence "Threat Profile" summarizing attacker skill and intent.
Under 120 words total. No introductions, no markdown fences."""
        return _call_model(prompt)

    def run_full_cycle(self):
        result = CycleResult()
        t0 = time.time()

        result.sandboxed = _docker_daemon_ready()
        if not result.sandboxed:
            result.status = SANDBOX_UNAVAILABLE
            result.status_detail = "Sandbox unavailable"
            result.errors.append(
                "No isolated execution sandbox (Docker) is available in this "
                "environment. Execution was skipped for safety."
            )
            return result

        base_ready, base_error = _ensure_base_image()
        if not base_ready:
            result.status = SANDBOX_UNAVAILABLE
            result.status_detail = "Sandbox unavailable"
            result.errors.append("Could not prepare the sandbox base image: " + base_error)
            return result

        try:
            t = time.time()
            result.analysis = self.analyze_vulnerability(result.original_code)
            result.durations["analysis"] = time.time() - t
        except RuntimeError as e:
            result.errors.append(str(e))

        try:
            t = time.time()
            exploit_code = _strip_code_fences(self.write_exploit(result.original_code))
            result.durations["attack_write"] = time.time() - t
        except RuntimeError as e:
            result.errors.append(str(e))
            result.status_detail = "Inconclusive — attacker role failed"
            return result

        ok, msg = _check_syntax(exploit_code)
        if not ok:
            result.errors.append("Exploit code: " + msg)
            result.status_detail = "Inconclusive — exploit code invalid"
            return result
        result.exploit_code = exploit_code

        run_id = uuid.uuid4().hex[:8]
        pre_dir = tempfile.mkdtemp(prefix=f"sunshine_{run_id}_pre_")
        try:
            _write_files(pre_dir, {
                "vulnerable_app.py": result.original_code,
                "test_exploit.py": exploit_code,
                "Dockerfile": DOCKERFILE_TEMPLATE,
            })
            t = time.time()
            exploit_passed, log, status, artifact_present = _run_in_docker(
                pre_dir, f"sunshine-{run_id}-pre", check_artifact=ARTIFACT_PATH)
            result.durations["pre_patch_test"] = time.time() - t
        finally:
            shutil.rmtree(pre_dir, ignore_errors=True)

        result.pre_patch_log = log
        if status == "error" or exploit_passed is None:
            result.errors.append("Pre-patch test run was inconclusive: " + log[:500])
            result.status_detail = "Inconclusive — could not reliably run the pre-patch test"
            return result

        # Require BOTH signals to agree: pytest said the exploit succeeded,
        # AND the attack artifact genuinely exists inside the container.
        if exploit_passed and artifact_present:
            result.pre_patch_exploit_confirmed = True
        else:
            result.pre_patch_exploit_confirmed = False
            if exploit_passed != artifact_present:
                result.errors.append(
                    f"Pre-patch test result ({exploit_passed}) disagreed with "
                    f"artifact evidence ({artifact_present}) — not trusting this run."
                )
            result.status_detail = "Inconclusive — exploit did not reproduce the vulnerability"
            return result

        current_code = result.original_code
        previous_log = result.pre_patch_log

        for attempt in range(1, 4):
            result.attempts = attempt
            try:
                t = time.time()
                patched_code = _strip_code_fences(self.write_patch(current_code, previous_log))
                result.durations[f"patch_write_{attempt}"] = time.time() - t
            except RuntimeError as e:
                result.errors.append(str(e))
                break

            ok, msg = _check_syntax(patched_code)
            if not ok:
                result.errors.append(f"Attempt {attempt} patch: {msg}")
                previous_log = msg
                continue

            attempt_dir = tempfile.mkdtemp(prefix=f"sunshine_{run_id}_a{attempt}_")
            try:
                _write_files(attempt_dir, {
                    "vulnerable_app.py": patched_code,
                    "test_exploit.py": exploit_code,
                    "Dockerfile": DOCKERFILE_TEMPLATE,
                })
                t = time.time()
                exp_passed, exp_log, exp_status, exp_artifact_present = _run_in_docker(
                    attempt_dir, f"sunshine-{run_id}-a{attempt}-exp", check_artifact=ARTIFACT_PATH)
                result.durations[f"verify_exploit_{attempt}"] = time.time() - t

                _write_files(attempt_dir, {"test_functional.py": FUNCTIONAL_TEST_CODE})
                os.remove(os.path.join(attempt_dir, "test_exploit.py"))
                t = time.time()
                func_passed, func_log, func_status, _ = _run_in_docker(
                    attempt_dir, f"sunshine-{run_id}-a{attempt}-func")
                result.durations[f"verify_functional_{attempt}"] = time.time() - t
            finally:
                shutil.rmtree(attempt_dir, ignore_errors=True)

            result.post_patch_exploit_log = exp_log
            result.functional_log = func_log

            if exp_status == "error" or func_status == "error" or exp_passed is None or func_passed is None:
                result.errors.append(f"Verification on attempt {attempt} was inconclusive (infrastructure error)")
                previous_log = exp_log + "\n" + func_log
                continue

            # Trust "blocked" only when pytest result and artifact evidence agree.
            if (not exp_passed) and (not exp_artifact_present):
                blocked = True
            elif exp_passed and exp_artifact_present:
                blocked = False
            else:
                result.errors.append(
                    f"Attempt {attempt}: exploit test result ({exp_passed}) disagreed "
                    f"with artifact evidence ({exp_artifact_present}) — not trusting this attempt."
                )
                blocked = None

            result.post_patch_exploit_blocked = blocked
            result.functional_ok = func_passed

            if blocked and func_passed:
                result.patched_code = patched_code
                result.status = PATCH_VERIFIED
                result.status_detail = f"Patch verified after {attempt} attempt(s)"
                break
            else:
                previous_log = exp_log + "\n" + func_log
                current_code = patched_code

        if result.status != PATCH_VERIFIED:
            result.status_detail = "Inconclusive — patch not verified after 3 attempts"

        result.durations["total"] = time.time() - t0
        return result
