# Publishing `pqc-aero-bench` to GitHub - first-time guide

This walks you, step by step, through getting this repository onto GitHub
for the first time. It assumes Windows + PowerShell + Git for Windows
(already installed if you got this far). No prior GitHub experience needed.

The whole thing takes about 10 minutes.

---

## Step 1 - Tell git who you are (one-time, done once per machine)

```powershell
git config --global user.name  "Your Full Name"
git config --global user.email "you@example.com"
```

Use the **same email** you will register on GitHub with - that links your
commits to your GitHub profile so they appear on your contribution graph
(the green-square wall on your profile - it matters for credibility).

Verify:

```powershell
git config --global --get user.name
git config --global --get user.email
```

---

## Step 2 - Create your GitHub account

1. Go to <https://github.com/signup>.
2. Use the **same email** you put into git config above.
3. Pick a username you are comfortable putting on a CV. Lower-case, no
   underscores, no numbers if you can avoid them. Examples:
   `thiruv`, `tharani-cyber`, `t-aviation-sec`.
4. Verify your email when prompted.
5. (Optional but recommended) Enable two-factor authentication under
   _Settings / Password and authentication_.

---

## Step 3 - Create the empty remote repository

1. Click the **+** icon top-right -> **New repository**.
2. **Repository name**: `pqc-aero-bench`
3. **Description**: _Benchmark NIST post-quantum primitives (ML-KEM, ML-DSA,
   SLH-DSA, Falcon) against civil-aviation datalink constraints (ACARS,
   VDL-2, ADS-B, LDACS, SATCOM, AeroMACS)._
4. Visibility: **Public** (you want supervisors to see it).
5. **Do NOT** initialise with README, .gitignore or licence - we already
   have them locally. If you tick any of those, GitHub will create a
   conflicting first commit.
6. Click **Create repository**. You will land on an empty repo page with
   instructions.

GitHub will show two URLs:

- HTTPS: `https://github.com/<your-username>/pqc-aero-bench.git`
- SSH:   `git@github.com:<your-username>/pqc-aero-bench.git`

Use **HTTPS** unless you already have SSH keys set up. On Windows, the
Git Credential Manager will open a browser the first time you push, and
remember the credential afterwards. No password prompts in the terminal.

---

## Step 4 - Wire the local repo to the remote and push

From inside `C:\Users\thiru\OneDrive\Desktop\PQC_Benchmarking`:

```powershell
git remote add origin https://github.com/<your-username>/pqc-aero-bench.git
git remote -v                          # sanity check; should print 'origin' twice
git push -u origin main
```

The first push opens a browser window once for the Credential Manager
sign-in. After that, future pushes are silent.

---

## Step 5 - Confirm the upload

1. Refresh the GitHub page. You should now see the README rendered as
   the project landing page, with the headline fit matrix image embedded.
2. Click the **Actions** tab. A "ci" workflow should be running (or
   already passed) - this proves the CI matrix works on Ubuntu and
   Windows, which is a credibility multiplier.
3. After CI passes, add a **status badge** to your README - GitHub shows
   the badge URL on the Actions page. Drop it under the title and push.

---

## Step 6 - The bits that make it look professional

These are small, fast, and matter disproportionately on a research CV:

1. **About box** (top-right on the repo page): paste the project
   description and add the topics: `post-quantum`, `cryptography`,
   `aviation`, `cybersecurity`, `ml-kem`, `ml-dsa`, `falcon`, `sphincs`,
   `acars`, `ads-b`, `ldacs`, `avionics`, `benchmark`. Topics make the
   project discoverable and signal that you know what it's about.
2. **Pin the repository** on your GitHub profile (_Profile -> Customize your
   pins_). Profile-pinned repos are the first thing a supervisor clicking
   your CV link sees.
3. **Write a short profile README**: create a repo named exactly your
   username (e.g. `thiruv/thiruv`) with a README inside; GitHub will
   render it at the top of your profile. A 5-line summary of who you are
   and what you are looking to research is plenty.
4. **Create a v0.1.0 release** (_Releases -> Draft a new release_, tag
   `v0.1.0`, title "Initial public release"). Releases get DOIs via
   Zenodo (free) - useful if your supervisor wants something citable.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `fatal: remote origin already exists` | `git remote remove origin` then re-add |
| Push asks for a password and rejects it | GitHub disabled password auth in 2021. The Credential Manager browser flow is the supported route on Windows. If you see the password prompt, you are on an old git - reinstall <https://git-scm.com/> |
| `error: failed to push some refs` | Run `git pull --rebase origin main` then push again. Happens if you initialised the GitHub repo with a README. |
| Commits show under an "unverified" name | You used a different email in `git config` than on GitHub. Fix with `git config --global user.email` and the next commit will appear under your verified identity. Past commits are cosmetic; do not rewrite history just for this. |
