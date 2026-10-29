# SunShine

A single autonomous AI agent that switches between four security roles — Attacker, Defender, Analyst, and Threat Hunter — to detect, exploit, patch, and report a vulnerability in one continuous loop.

Live Demo: https://sunshine-3fcbk46ykmypixc8fut8lb.streamlit.app/

## What it does

Most static scanners just flag suspicious code and leave the developer to verify it. SunShine proves the vulnerability is real by actually exploiting it, then patches the code and re-runs the same exploit to prove the fix works — all driven by one agent.

1. **Attacker role** — writes a working exploit (pytest) against a vulnerable Command Injection function.
2. **Defender role** — patches the code and re-tests until the exploit fails, retrying up to 3 times.
   Verification distinguishes a genuine security result (pytest exit code 0 or 1) from an inconclusive run (build failure, timeout, or test collection error) — an infrastructure error is never reported as a successful patch. The functional test checks real ping output (not just "is it a string"), so a stubbed-out function cannot pass as a valid fix.
3. **Analyst role** — writes a short security report (summary, evidence, fix, recommendation).
4. **Threat Hunter role** — analyzes simulated honeypot traffic to profile attacker behavior.

This is a proof of concept built in under 48 hours, focused on one vulnerability class (Command Injection) to demonstrate the full attack-patch-verify loop end to end.

## Tech stack

- **Nebius AI Cloud (Token Factory)** — model inference endpoint (required track condition)
- **NVIDIA Nemotron-3-Super (120B)** — open-weight reasoning model (required track condition)
- **Docker** — isolated, sandboxed execution of exploit/patch tests
- **Streamlit** — interface
- **pytest** — automated verification

## Running locally

```bash
git clone https://github.com/aseel-aihub/sunshine
cd sunshine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "NEBIUS_API_KEY=your_key_here" > .env
streamlit run app.py
```

Docker must be running locally, since exploit and patch tests execute inside an isolated container.

## Notes on scope

- The honeypot traffic log is fictional sample data created for this demo, not real captured traffic.
- The current version targets one vulnerability class. Extending to multiple vulnerability types and real GitHub repositories is the natural next step.

## License

MIT — see LICENSE file.

## Author

Aseel Alqahtani — [github.com/aseel-aihub](https://github.com/aseel-aihub)
