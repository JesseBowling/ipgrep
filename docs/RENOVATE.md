# Dependency updates (Renovate)

Self-hosted Renovate runs in GitHub Actions (`renovatebot/github-action`). It runs every
Saturday at 03:00 UTC and on manual dispatch. It updates `pyproject.toml` dependencies
(the `pep621` manager, with `uv.lock` updated alongside them), updates GitHub Actions
versions (grouped into one PR), and refreshes `uv.lock` once a week (lock file
maintenance). Config files: `.github/workflows/renovate.yaml` and
`.github/renovate.json5`.

## Why not GITHUB_TOKEN

A PR made with the default `GITHUB_TOKEN` does not trigger other workflows, so CI would
not run on Renovate's PRs. `GITHUB_TOKEN` also cannot change files under
`.github/workflows`, so it cannot update action versions. Renovate needs its own token:
a GitHub App token (primary) or a fine-grained personal access token (fallback). The
workflow sets `permissions: {}` because it does not use `GITHUB_TOKEN`.

## Setup: GitHub App (recommended)

### 1. Create the App

1. Go to GitHub > Settings > Developer settings > GitHub Apps > New GitHub App
   (<https://github.com/settings/apps/new>).
2. Set a name, for example `ipgrep-renovate`. The name must be globally unique.
3. Set Homepage URL to the repo URL.
4. Clear the Webhook "Active" checkbox. The webhook is not needed.
5. Under "Where can this GitHub App be installed?", choose "Only on this account".

### 2. Set repository permissions

Set these repository permissions on the App:

| Permission | Access | Why |
|---|---|---|
| Contents | Read and write | Create branches and commits |
| Pull requests | Read and write | Open and update PRs |
| Issues | Read and write | Dependency Dashboard issue |
| Workflows | Read and write | Update `uses:` lines in `.github/workflows` |
| Checks | Read and write | Read CI results (upstream recommendation) |
| Commit statuses | Read and write | Read CI status, set Renovate's own status checks (upstream recommendation) |
| Metadata | Read-only | Mandatory. GitHub sets this automatically. |
| Dependabot alerts | Read-only | Optional. Lets Renovate open security fix PRs from vulnerability alerts. |
| Administration | Read-only | Optional. Lets Renovate read branch protection rules. |

No organization or account permissions are needed. "Members" and similar account-level
permissions apply only to organizations, not to a personal account.

### 3. Generate credentials

1. Click "Create GitHub App".
2. On the App page, copy the **Client ID**.
3. Under "Private keys", click "Generate a private key". This downloads a `.pem` file.

### 4. Install the App

1. On the App page, click "Install App".
2. Choose your account.
3. Choose "Only select repositories" and select `JesseBowling/ipgrep`.

### 5. Add credentials to the repo

Go to the repo's Settings > Secrets and variables > Actions.

- Variables tab: set `RENOVATE_APP_CLIENT_ID` to the Client ID. This is a variable, not
  a secret: the Client ID is not sensitive, and the workflow reads it in an `if:`
  condition, where secrets are not available.
- Secrets tab: set `RENOVATE_APP_PRIVATE_KEY` to the full content of the `.pem` file,
  including the `BEGIN` and `END` lines.

CLI equivalent:

```sh
gh variable set RENOVATE_APP_CLIENT_ID -R JesseBowling/ipgrep --body '<client-id>'
gh secret set RENOVATE_APP_PRIVATE_KEY -R JesseBowling/ipgrep < ipgrep-renovate.private-key.pem
```

Delete the local `.pem` file after you set the secret.

**Note:** `actions/create-github-app-token@v3` deprecates the `app-id` input in favor of
`client-id`. This is why the workflow and these steps use the Client ID, not the App ID.

## Alternative: fine-grained PAT

Use this only if you do not want to create a GitHub App. Commits and PRs then show your
own user account, not an App identity.

1. Go to Settings > Developer settings > Personal access tokens > Fine-grained tokens >
   Generate new token.
2. Set Resource owner to `JesseBowling`.
3. Set Repository access to "Only select repositories" and select `ipgrep`.
4. Set an expiration date. Put a reminder somewhere to rotate the token before it
   expires.
5. Set repository permissions:

| Permission | Access |
|---|---|
| Contents | Read and write |
| Pull requests | Read and write |
| Issues | Read and write |
| Workflows | Read and write |
| Commit statuses | Read and write (upstream lists Read and write for this token type) |
| Dependabot alerts | Read-only (optional) |
| Metadata | Read-only (automatic) |

6. Add the token as a repo secret:

```sh
gh secret set RENOVATE_TOKEN -R JesseBowling/ipgrep
```

Do **not** set the `RENOVATE_APP_CLIENT_ID` variable in this case. When that variable is
empty, the workflow skips the App token step and falls back to `RENOVATE_TOKEN`.

A classic PAT works too, with `repo` and `workflow` scopes. This is not recommended: it
grants broader access than a fine-grained token.

## Run it manually / dry run

Go to the Actions tab > Renovate > Run workflow. Set these inputs:

| Input | Values | Meaning |
|---|---|---|
| `log-level` | `info`, `debug` | Logging detail |
| `dry-run` | `none`, `extract`, `lookup`, `full` | See below |

Dry-run modes:

- `none` — normal run. Creates branches and PRs.
- `extract` — only finds dependencies. Does not look up new versions.
- `lookup` — also looks up new versions. Does not create branches.
- `full` — does everything except write to GitHub. No branches, PRs, or issues are
  created.

Read the results in the job log. In `full` mode, search the log for `DRY-RUN: Would`
to see each branch, PR, or issue change that Renovate skipped.

CLI equivalent:

```sh
gh workflow run renovate.yaml -R JesseBowling/ipgrep -f dry-run=full -f log-level=debug
gh run watch -R JesseBowling/ipgrep
```

Recommended first use: run `dry-run=lookup` with `log-level: debug` first, then run a
normal (`dry-run=none`) run once the lookup output looks right.

Only one Renovate run can run at a time. The workflow uses the concurrency group
`renovate`; a new run waits for the current run to finish.

## Change the schedule

Two files must agree on the schedule:

- `.github/workflows/renovate.yaml` — `on.schedule[].cron`. This is UTC cron syntax, for
  example `'0 3 * * 6'` means Saturday 03:00 UTC. GitHub can start a scheduled run some
  minutes late.
- `.github/renovate.json5` — `lockFileMaintenance.schedule`. This is set to
  `['on saturday']`, with `timezone: 'UTC'`. Renovate's own default for lock file
  maintenance is "before 4am on monday", which never matches a Saturday cron run, so it
  must be set to match the cron day.

Normal dependency updates have no top-level `schedule` in the config, so Renovate
creates them on every run. Do not add a top-level `schedule` that excludes the cron
time, or Renovate will skip creating PRs during the scheduled run.

A manual run on a day other than Saturday still creates normal update PRs, but it does
not create the lock file maintenance PR, since `lockFileMaintenance.schedule` only
matches Saturday.

After editing either file, validate the Renovate config:

```sh
npx --yes --package renovate -- renovate-config-validator --strict
```

## What to expect

- No onboarding PR. The config is already committed, and the workflow sets
  `RENOVATE_ONBOARDING: 'false'`.
- The first run opens a "Dependency Dashboard" issue. It lists pending, open, and
  rate-limited updates, with checkboxes to retry or force updates. Tick a box, and the
  next scheduled run acts on it. Trigger a manual run to apply it sooner.
- Each Saturday, expect: one PR per Python dependency update (a major version update
  gets its own separate PR), one grouped "GitHub Actions" PR, and one "Lock file
  maintenance" PR that refreshes `uv.lock`.
- There is no hourly PR limit (`prHourlyLimit: 0`). At most 10 Renovate PRs stay open at
  once (Renovate's default `prConcurrentLimit`).
- Renovate rebases its open PRs on its next run when they have merge conflicts with
  `main` (default `rebaseWhen: auto`).
- PRs trigger the normal CI Tests workflow, because they come from the App token or the
  PAT, not from `GITHUB_TOKEN`.
- To stop an update: close the PR without merging. Renovate will not recreate a PR for
  that same version. It will open a new PR if a newer version becomes available. You
  can also add an ignore rule in `.github/renovate.json5`.

## Turn on automerge (optional)

Automerge is off by default (`automerge: false` at the top level). To enable it for
low-risk updates, add a package rule, for example:

```json5
{
  description: 'Automerge non-major updates',
  matchUpdateTypes: ['minor', 'patch', 'digest', 'lockFileMaintenance'],
  automerge: true,
},
```

The top-level `automerge: false` stays as the default; this package rule overrides it
for the matched update types only.

Requirements:

- Set up a branch protection rule or ruleset on `main` with required status checks (the
  CI Tests jobs). Without this, Renovate merges a PR without waiting for CI to pass.
- Turn on "Allow auto-merge" in the repo settings (Settings > General). Renovate then
  enables GitHub's native auto-merge on each eligible PR, and GitHub merges it when the
  required checks pass (`platformAutomerge`, on by default). Without that setting,
  Renovate merges the PR itself on its next run after checks pass, which is weekly.
- If `main` requires an approving review, automerge cannot complete without your
  review. Approve the PR, or merge it by hand.

## References

- <https://docs.renovatebot.com/>
- <https://docs.renovatebot.com/modules/platform/github/>
- <https://github.com/renovatebot/github-action>
- <https://github.com/actions/create-github-app-token>
- <https://docs.renovatebot.com/configuration-options/>
- <https://docs.renovatebot.com/self-hosted-configuration/#dryrun>
