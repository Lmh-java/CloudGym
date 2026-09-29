"""Provision and operate the sandbox account pool (see ``harness/sandbox/pool.py``).

    uv run sandbox-pool list                                  # lease state (no AWS)
    uv run sandbox-pool verify --allow-aws                    # STS every account
    uv run sandbox-pool add --count 2 --allow-aws             # create org accounts into the sandbox OU
    uv run sandbox-pool reset <account> --allow-aws           # sweep a dirty account, mark it clean
    uv run sandbox-pool quarantine <account> --reason '...'   # keep it out of the pool
    uv run sandbox-pool release <account>                     # mark clean by hand (after a manual sweep)
    uv run sandbox-pool janitor --allow-aws                   # loop: reset every dirty account as it appears

``add`` runs as the organization's management account (``[aws.pool].management_profile``):
it checks the accounts-per-organization quota, calls ``organizations:CreateAccount`` with the
root email from ``email_template`` and the org access role, moves the account into ``ou_id``
(the sandbox SCP is inherited), writes a ``role_arn``/``source_profile`` stanza to
``~/.aws/config`` and an ``[[aws.pool.accounts]]`` entry to ``aws.local.toml``, then verifies
the new account through STS and a dry-run sweep (nothing to delete = golden state).
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.aws_safety import (  # noqa: E402
    AwsSafetyError, AwsTarget, PoolConfig, aws_environment, config_path, load_aws_target,
    load_pool_config, load_pool_targets, verify_aws_target,
)
from harness.sandbox import Pool, PoolError  # noqa: E402

AWS_CONFIG = Path("~/.aws/config").expanduser()
ACCOUNTS_QUOTA = ("organizations", "L-E619E033")   # "Maximum number of accounts" per organization
CREATE_TIMEOUT_S = 15 * 60
VERIFY_RETRY_S = 3 * 60


def die(msg: str) -> "NoReturn":  # noqa: F821
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _pool() -> Pool:
    try:
        return Pool.open(REPO_ROOT)
    except (AwsSafetyError, PoolError) as exc:
        die(str(exc))


def _find(pool: Pool, selector: str) -> AwsTarget:
    for target in pool.targets.values():
        if selector in (target.account_id, target.label, target.profile):
            return target
    die(f"no pool account matches {selector!r}; `sandbox-pool list`")


# -- commands ---------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    pool = _pool()
    print(pool.describe())
    print("  " + " ".join(f"{k}={v}" for k, v in sorted(pool.counts().items())))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if not args.allow_aws:
        die("verify calls STS in every account; pass --allow-aws")
    failures = 0
    for target in load_pool_targets(REPO_ROOT):
        try:
            identity = verify_aws_target(target, aws_environment(target))
            print(f"  {target.label:<24} {target.account_id}  ok  {identity['Arn']}")
        except AwsSafetyError as exc:
            failures += 1
            print(f"  {target.label:<24} {target.account_id}  FAIL  {exc}")
    return 1 if failures else 0


def cmd_release(args: argparse.Namespace) -> int:
    pool = _pool()
    target = _find(pool, args.account)
    try:
        pool.mark(target.account_id, "clean")
    except PoolError as exc:
        die(str(exc))
    log(f"{target.label} ({target.account_id}) marked clean")
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    pool = _pool()
    target = _find(pool, args.account)
    try:
        pool.mark(target.account_id, "quarantined", reason=args.reason)
    except PoolError as exc:
        die(str(exc))
    log(f"{target.label} ({target.account_id}) quarantined: {args.reason}")
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    """Sweep the account with the sandbox-clean sweeper, prove it empty, mark it clean."""
    if not args.allow_aws:
        die("reset deletes real resources; pass --allow-aws")
    pool = _pool()
    target = _find(pool, args.account)
    state = next(r for r in pool.status() if r["account_id"] == target.account_id)
    if state["state"] == "leased":
        die(f"{target.label} is leased by {state['holder']}; stop that run first")
    try:
        problem = reset_account(pool, target, args.region, dry_run=args.dry_run)
    except AwsSafetyError as exc:
        die(str(exc))
    return 1 if problem else 0


def reset_account(pool: Pool, target: AwsTarget, region: str | None, *, dry_run: bool = False,
                  log=log) -> str | None:
    """Sweep ``target``, prove it is back at baseline, mark it clean. None on success, else why
    it stays dirty (the account is marked dirty with that reason). Never called on a leased account."""
    from scripts.sandbox_cleanup import sweep

    log(f"reset {target.label} ({target.account_id}) {'DRY RUN' if dry_run else ''}")
    sweeper = sweep(target, region, dry_run=dry_run)
    log(f"  {'would delete' if dry_run else 'deleted'} {len(sweeper.deleted)}; failed {len(sweeper.failed)}")
    if dry_run:
        return None
    if sweeper.failed:
        for item in sweeper.failed:
            log(f"    failed: {item}")
        problem = f"reset left {len(sweeper.failed)} resource(s); rerun"
        pool.mark(target.account_id, "dirty", reason=problem)
        return problem
    problem = _golden(target, region)
    if problem:
        pool.mark(target.account_id, "dirty", reason=f"reset finished but {problem}")
        return problem
    pool.mark(target.account_id, "clean")
    log(f"  {target.label} is clean")
    return None


JANITOR_BACKOFF_S = (300.0, 900.0, 1800.0)     # after the 1st, 2nd, 3rd+ failed reset in a row


def dirty_due(rows: list[dict], *, now: float, grace_s: float, failures: dict[str, int],
              last_try: dict[str, float], backoff: tuple[float, ...] = JANITOR_BACKOFF_S) -> list[str]:
    """Account ids the janitor should reset now: dirty (never leased or quarantined) for at least
    ``grace_s``, and past the backoff of their previous failed resets."""
    due = []
    for row in rows:
        if row.get("state") != "dirty":
            continue
        account_id = row["account_id"]
        if now - float(row.get("since") or 0) < grace_s:
            continue
        n = failures.get(account_id, 0)
        if n and now - last_try.get(account_id, 0.0) < backoff[min(n, len(backoff)) - 1]:
            continue
        due.append(account_id)
    return due


def cmd_janitor(args: argparse.Namespace) -> int:
    """Reset dirty accounts as they appear, so a leak costs one sweep instead of an idle account.

    Only ``dirty`` accounts are touched: a dirty account is never leased (the pool hands out clean
    ones only), so sweeping it cannot race a cell; ``quarantined`` (reserved, owned elsewhere) and
    ``leased`` accounts are left alone. One account at a time; a failed reset backs off."""
    if not args.allow_aws:
        die("the janitor deletes real resources; pass --allow-aws")
    stamp = lambda: time.strftime("%H:%M:%S", time.gmtime())  # noqa: E731
    say = lambda m: log(f"[janitor {stamp()}] {m}")  # noqa: E731
    failures: dict[str, int] = {}
    last_try: dict[str, float] = {}
    say(f"every {args.interval:g}s; dirty for >= {args.grace:g}s; backoff after a failed reset "
        + ", ".join(f"{s:g}s" for s in JANITOR_BACKOFF_S))
    while True:
        pool = _pool()          # re-read the config each pass: accounts added to aws.local.toml join
        rows = pool.status()
        for account_id in dirty_due(rows, now=time.time(), grace_s=args.grace, failures=failures, last_try=last_try):
            target = pool.targets[account_id]
            row = next(r for r in rows if r["account_id"] == account_id)
            say(f"{target.label} dirty: {str(row.get('last_error') or '')[:160]}")
            last_try[account_id] = time.time()
            try:
                problem = reset_account(pool, target, args.region, log=lambda m: say("  " + m.strip()))
            except PoolError as exc:          # leased in the meantime (someone released + re-leased it)
                say(f"  skipped: {exc}")
                continue
            except Exception as exc:  # noqa: BLE001 - one bad sweep must not stop the janitor
                problem = f"{type(exc).__name__}: {str(exc)[:300]}"
                try:
                    pool.mark(account_id, "dirty", reason=f"janitor: {problem}")
                except PoolError:
                    pass
            if problem:
                failures[account_id] = failures.get(account_id, 0) + 1
                wait = JANITOR_BACKOFF_S[min(failures[account_id], len(JANITOR_BACKOFF_S)) - 1]
                say(f"  {target.label} still dirty ({problem[:160]}); failure {failures[account_id]}, next try in {wait:g}s")
            else:
                failures.pop(account_id, None)
                say(f"  {target.label} back in the pool")
        if args.once:
            return 0
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            return 130


def _golden(target: AwsTarget, region: str | None) -> str | None:
    """None when a dry-run sweep finds nothing (the account is at its baseline); otherwise why not."""
    from scripts.sandbox_cleanup import sweep

    sweeper = sweep(target, region, dry_run=True)
    if sweeper.deleted:
        log(f"  not at baseline; a sweep would delete {len(sweeper.deleted)} resource(s):")
        for item in sweeper.deleted[:20]:
            log(f"    {item}")
        return f"a sweep would delete {len(sweeper.deleted)} resource(s)"
    if sweeper.unavailable:
        log(f"  {len(sweeper.unavailable)} service(s) not yet enabled in this account (new-account lag)")
        return "services not yet enabled: " + "; ".join(sweeper.unavailable)[:300]
    return None


# -- add: organizations:CreateAccount --------------------------------------------

def _management_session(config: PoolConfig):
    import boto3

    session = boto3.Session(profile_name=config.management_profile)
    sts = session.client("sts")
    try:
        identity = sts.get_caller_identity()
    except Exception as exc:  # noqa: BLE001 - surface the SSO hint
        die(f"cannot use management profile {config.management_profile!r}: {exc}\n"
            f"Run: aws sso login --profile {config.management_profile}")
    org = session.client("organizations")
    description = org.describe_organization()["Organization"]
    if identity["Account"] != description["MasterAccountId"]:
        die(f"profile {config.management_profile!r} is account {identity['Account']}, not the organization's "
            f"management account {description['MasterAccountId']}; CreateAccount must run there")
    return session, org


def _org_accounts(org) -> list[dict]:
    accounts = []
    for page in org.get_paginator("list_accounts").paginate():
        accounts.extend(page.get("Accounts", []))
    return accounts


def _quota(session) -> float | None:
    try:
        quotas = session.client("service-quotas", region_name="us-east-1")
        return float(quotas.get_service_quota(ServiceCode=ACCOUNTS_QUOTA[0],
                                              QuotaCode=ACCOUNTS_QUOTA[1])["Quota"]["Value"])
    except Exception as exc:  # noqa: BLE001 - quota lookup is advisory
        log(f"  (accounts-per-organization quota unavailable: {exc}; default is 10)")
        return None


def _next_index(config: PoolConfig, targets: list[AwsTarget], org_accounts: list[dict]) -> int:
    """1 + the highest index already used by a configured profile or an org account name,
    so a root email is never reused (AWS rejects EMAIL_ALREADY_EXISTS, and closed accounts keep theirs)."""
    used = [0]
    pattern = re.compile(rf"^{re.escape(config.account_name_prefix)}(\d+)$")
    for account in org_accounts:
        match = pattern.match(account.get("Name") or "")
        if match:
            used.append(int(match.group(1)))
    prefix = re.compile(rf"^{re.escape(config.profile_prefix)}(\d+)$")
    for target in targets:
        match = prefix.match(target.profile)
        if match:
            used.append(int(match.group(1)))
    return max(used) + 1


def _create_account(org, *, email: str, name: str, role: str) -> str:
    response = org.create_account(Email=email, AccountName=name, RoleName=role,
                                  IamUserAccessToBilling="DENY")
    request_id = response["CreateAccountStatus"]["Id"]
    deadline = time.monotonic() + CREATE_TIMEOUT_S
    while True:
        status = org.describe_create_account_status(CreateAccountRequestId=request_id)["CreateAccountStatus"]
        state = status["State"]
        if state == "SUCCEEDED":
            return status["AccountId"]
        if state == "FAILED":
            die(f"CreateAccount {name} failed: {status.get('FailureReason')}")
        if time.monotonic() > deadline:
            die(f"CreateAccount {name} still {state} after {CREATE_TIMEOUT_S // 60} min; request {request_id}")
        log(f"  {name}: {state} …")
        time.sleep(10)


def _move_to_ou(org, account_id: str, ou_id: str) -> None:
    parents = org.list_parents(ChildId=account_id)["Parents"]
    source = parents[0]["Id"]
    if source == ou_id:
        return
    org.move_account(AccountId=account_id, SourceParentId=source, DestinationParentId=ou_id)


def profile_stanza(profile: str, account_id: str, config: PoolConfig, region: str) -> str:
    return (f"\n[profile {profile}]\n"
            f"role_arn = arn:aws:iam::{account_id}:role/{config.access_role}\n"
            f"source_profile = {config.management_profile}\n"
            f"region = {region}\n")


def _write_aws_profile(profile: str, stanza: str) -> bool:
    """Append the stanza unless ``[profile <name>]`` already exists. Returns True when written."""
    existing = AWS_CONFIG.read_text() if AWS_CONFIG.is_file() else ""
    if re.search(rf"^\[profile {re.escape(profile)}\]\s*$", existing, re.M):
        return False
    AWS_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    with AWS_CONFIG.open("a") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(stanza)
    return True


def _append_pool_account(profile: str, account_id: str, name: str) -> None:
    path = config_path(REPO_ROOT)
    text = path.read_text()
    entry = f'\n[[aws.pool.accounts]]\nprofile = "{profile}"\naccount_id = "{account_id}"\nname = "{name}"\n'
    path.write_text(text + ("" if text.endswith("\n") else "\n") + entry)


def _verify_new(target: AwsTarget) -> dict[str, str]:
    """The org role is usable seconds to a couple of minutes after creation; retry STS until then."""
    deadline = time.monotonic() + VERIFY_RETRY_S
    while True:
        try:
            return verify_aws_target(target, aws_environment(target))
        except AwsSafetyError as exc:
            if time.monotonic() > deadline:
                die(f"new account {target.account_id} never became reachable: {exc}")
            log(f"  waiting for {target.profile}: {str(exc).splitlines()[0][:100]}")
            time.sleep(15)


def cmd_add(args: argparse.Namespace) -> int:
    if not args.allow_aws:
        die("add creates AWS accounts; pass --allow-aws")
    try:
        config = load_pool_config(REPO_ROOT)
        primary = load_aws_target(REPO_ROOT)
        targets = load_pool_targets(REPO_ROOT)
    except AwsSafetyError as exc:
        die(str(exc))
    if config is None:
        die("no [aws.pool] section in .cloudgym/aws.local.toml; see aws.example.toml")
    session, org = _management_session(config)
    existing = _org_accounts(org)
    quota = _quota(session)
    live = [a for a in existing if a.get("Status") != "SUSPENDED"]
    log(f"organization: {len(existing)} account(s) ({len(live)} not suspended); quota {quota or '?'}")
    if quota is not None and len(existing) + args.count > quota:
        die(f"adding {args.count} would exceed the accounts-per-organization quota ({quota:g}); "
            f"request an increase for {ACCOUNTS_QUOTA[1]} 'Maximum number of accounts' (Service Quotas → AWS "
            f"Organizations) or close accounts")
    index = _next_index(config, targets, existing)
    created = 0
    for n in range(index, index + args.count):
        email = config.email_template.format(n=n)
        name = f"{config.account_name_prefix}{n:02d}"
        profile = f"{config.profile_prefix}{n:02d}"
        if args.dry_run:
            log(f"would create {name} <{email}> → profile {profile}")
            continue
        log(f"creating {name} <{email}> …")
        account_id = _create_account(org, email=email, name=name, role=config.access_role)
        log(f"  account {account_id}; moving into {config.ou_id}")
        _move_to_ou(org, account_id, config.ou_id)
        stanza = profile_stanza(profile, account_id, config, primary.region)
        if args.print_config:
            print(stanza)
        elif _write_aws_profile(profile, stanza):
            log(f"  wrote [profile {profile}] to {AWS_CONFIG}")
        else:
            log(f"  [profile {profile}] already in {AWS_CONFIG}")
        _append_pool_account(profile, account_id, name)
        log(f"  appended [[aws.pool.accounts]] {profile} to {config_path(REPO_ROOT)}")
        target = AwsTarget(profile, account_id, primary.region, config.access_role, access="org-role", name=name)
        created += 1
        try:
            identity = _verify_new(target)
            log(f"  verified as {identity['Arn']}")
            problem = _golden(target, None)
        except Exception as exc:  # noqa: BLE001 - the account exists and is registered; only its readiness is unknown
            problem = f"post-create check failed: {type(exc).__name__}: {str(exc)[:200]}"
        if problem:
            Pool.open(REPO_ROOT).mark(account_id, "dirty", reason=f"new account: {problem}")
            log(f"  marked dirty ({problem[:120]}); run `sandbox-pool reset {name} --allow-aws` in a while")
        else:
            log(f"  {name} is clean and leasable")
    if not args.dry_run:
        log(f"added {created} account(s); pool now {len(load_pool_targets(REPO_ROOT))}")
    return 0


# -- cli ----------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sandbox-pool", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="lease state of every configured account (no AWS)")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("verify", help="STS get-caller-identity through every account's profile")
    p.add_argument("--allow-aws", action="store_true")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("add", help="create org accounts into the sandbox OU and register them")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--allow-aws", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="show the names/emails that would be created")
    p.add_argument("--print-config", action="store_true", help="print the ~/.aws/config stanza instead of writing it")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("reset", help="sweep a dirty account and mark it clean")
    p.add_argument("account", help="account id, label or profile")
    p.add_argument("--allow-aws", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--region")
    p.set_defaults(fn=cmd_reset)

    p = sub.add_parser("janitor", help="loop: sweep and mark clean every dirty account (never leased/quarantined)")
    p.add_argument("--allow-aws", action="store_true")
    p.add_argument("--interval", type=float, default=60.0, help="seconds between scans (default 60)")
    p.add_argument("--grace", type=float, default=60.0,
                   help="leave an account dirty this long before sweeping it (default 60)")
    p.add_argument("--region")
    p.add_argument("--once", action="store_true", help="one scan, then exit")
    p.set_defaults(fn=cmd_janitor)

    p = sub.add_parser("release", help="mark an account clean without sweeping (you swept it by hand)")
    p.add_argument("account")
    p.set_defaults(fn=cmd_release)

    p = sub.add_parser("quarantine", help="keep an account out of the pool until reset")
    p.add_argument("account")
    p.add_argument("--reason", required=True)
    p.set_defaults(fn=cmd_quarantine)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
