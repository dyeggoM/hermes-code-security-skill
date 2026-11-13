#!/usr/bin/env python3
"""Hermes Security Matrix: deterministic state management, not an automated vulnerability detector.

The pipeline it tracks is the one OpenAI described for its Linux kernel sweep: Scout agents choose
audit targets by reachability and security relevance, Analyst agents work one target each and produce
candidates, a triage step reproduces a candidate before anything is called confirmed, and an
independent reviewer signs off on the fix. This CLI records that state; it never decides what a target
is or what a bug is.
"""
# pyright: reportOptionalMemberAccess=false
# `db(..., create=False)` returns None when a clone has no ledger, and only the read-only commands
# (status, check) can reach that path — they guard it explicitly. Every mutating command below gets a
# connection because main() only opens one when the command writes.
import argparse, datetime, hashlib, json, sqlite3, subprocess, sys
from pathlib import Path

VERSION = '0.3.0'
SEVERITIES = ('critical', 'high', 'medium', 'low')

def git(root,*args):
    x=subprocess.run(['git','-C',str(root),*args],capture_output=True,text=True)
    if x.returncode: raise RuntimeError(x.stderr.strip() or 'git failed')
    return x.stdout.strip()

def head_sha(root):
    """HEAD of a repository that has at least one commit, with an error a human can act on."""
    try: return git(root,'rev-parse','HEAD')
    except RuntimeError:
        raise RuntimeError('this repository has no commits yet; commit once before running the matrix')

def root_dir(value):
    p=Path(value).resolve()
    git(p,'rev-parse','--show-toplevel')
    return Path(git(p,'rev-parse','--show-toplevel'))

def db(root,create=True):
    folder=root/'.security'
    if not create and not (folder/'security.db').is_file():return None
    folder.mkdir(exist_ok=True)
    c=sqlite3.connect(folder/'security.db',timeout=30)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript("""CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, mode TEXT NOT NULL, commit_sha TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scope(run_id INTEGER NOT NULL, path TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY(run_id,path));
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, path TEXT NOT NULL, symbol TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL, status TEXT NOT NULL, source_hash TEXT NOT NULL, created_run INTEGER NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, previous TEXT, next TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, commit_sha TEXT NOT NULL, scope_digest TEXT NOT NULL, status TEXT NOT NULL, reviewer TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, title TEXT NOT NULL, paths TEXT NOT NULL, reachability TEXT NOT NULL, relevance TEXT NOT NULL, priority TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL, created_run INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);""")
    # Findings gained the target linkage after the first databases existed. ADD COLUMN is the only
    # migration SQLite offers, and it is enough here because the column is nullable.
    if 'target_id' not in {r['name'] for r in c.execute('PRAGMA table_info(findings)')}:
        c.execute('ALTER TABLE findings ADD COLUMN target_id TEXT')
    return c

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def source_hash(root,path):
    f=(root/path).resolve()
    if not f.is_relative_to(root) or not f.is_file():return 'missing'
    return hashlib.sha256(f.read_bytes()).hexdigest()

CODE_EXTENSIONS = ('.cs', '.csproj', '.json', '.config', '.yml', '.yaml', '.razor', '.cshtml',
                   '.ts', '.tsx', '.js', '.mjs', '.cjs', '.vue', '.sh', '.ps1', '.sql', '.html',
                   '.py', '.pyi', '.toml', '.ini')
LOCKFILES = ('package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock')
# Directories that never hold hand-written source: dependency caches, build output, tool state. The
# .NET ones are here because a repo can carry both stacks, the Python ones because a virtualenv or a
# __pycache__ inside the tree is thousands of files nobody audits.
SKIP_DIRS = ('bin', 'obj', '.security', '.git', 'node_modules', '__pycache__', '.venv', 'venv',
             '.mypy_cache', '.pytest_cache', '.ruff_cache', 'site-packages', 'dist', 'build')
# Test trees do not ship, so they are not attack surface — except when the audit is about fixtures
# (a committed secret, a credential baked into a sample). That case opts back in with --include-tests.
TEST_DIRS = ('tests', 'test', '__tests__', 'spec')

def generated(path):
    """Machine-written files nobody should review line by line."""
    name = path.rsplit('/', 1)[-1]
    dirs = path.split('/')
    return (name in LOCKFILES or 'Migrations' in dirs
            or path.endswith('.Designer.cs') or path.endswith('.g.cs')
            or ('alembic' in dirs and 'versions' in dirs))

def files(root,mode,base,include_generated=False,include_tests=False):
    if mode=='full':
        raw=git(root,'ls-files','--cached','--others','--exclude-standard').splitlines()
    else:
        raw=set(git(root,'diff','--name-only','HEAD').splitlines()+git(root,'ls-files','--others','--exclude-standard').splitlines())
        if base:raw|=set(git(root,'diff','--name-only',base,'HEAD').splitlines())
    return sorted(x for x in raw if x.endswith(CODE_EXTENSIONS)
                  and not any(y in x.split('/') for y in SKIP_DIRS)
                  and (include_tests or not any(y in x.split('/') for y in TEST_DIRS))
                  and (include_generated or not generated(x))
                  and (root/x).is_file())

def target_paths(values):
    """--path may be repeated, and one value may carry several comma-separated paths."""
    out=[]
    for value in values:
        for part in value.replace(';', ',').split(','):
            part=part.strip()
            if part and part not in out: out.append(part)
    return out

def evaluate(root,c):
    """Read-only verdict: what the gate decides and why. Never writes anything."""
    head=head_sha(root)
    if c is None:
        return {'valid':False,'pending':0,'unresolved':0,'open_targets':0,'head':head,'latest':None,
                'reason':'no security ledger in this clone (.security/security.db) — run a scan first'}
    pending=c.execute('SELECT COUNT(*) FROM scope WHERE status="pending"').fetchone()[0]
    unresolved=c.execute("SELECT COUNT(*) FROM findings WHERE status NOT IN ('verified_fixed','integration_verified','false_positive')").fetchone()[0]
    open_targets=c.execute("SELECT COUNT(*) FROM targets WHERE status='open'").fetchone()[0]
    latest=c.execute('SELECT * FROM reviews ORDER BY id DESC LIMIT 1').fetchone()
    matches=bool(latest and latest['scope_digest']==snapshot(root,c))
    valid=bool(latest and latest['status']=='passed' and latest['commit_sha']==head and matches
               and unresolved==0 and pending==0 and open_targets==0)
    if valid: reason=f'review valid for {head[:12]}'
    elif latest is None: reason='no integration review recorded'
    elif latest['status']!='passed': reason=f'the last review was recorded as {latest["status"]}'
    elif latest['commit_sha']!=head: reason=f'the last review covers {latest["commit_sha"][:12]} but HEAD is {head[:12]}'
    elif pending: reason=f'{pending} unreviewed scope entr(ies)'
    elif open_targets: reason=f'{open_targets} audit target(s) still open'
    elif unresolved: reason=f'{unresolved} open finding(s)'
    else: reason='the tree changed since the review (a source hash in scope moved)'
    return {'valid':valid,'pending':pending,'unresolved':unresolved,'open_targets':open_targets,
            'head':head,'latest':latest,'reason':reason}

def render(root,c):
    state=evaluate(root,c)
    rows=c.execute('SELECT * FROM findings ORDER BY CASE severity WHEN "critical" THEN 0 WHEN "high" THEN 1 WHEN "medium" THEN 2 ELSE 3 END,id').fetchall()
    targets=c.execute("SELECT * FROM targets ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,id").fetchall()
    pending,unresolved,head,valid=state['pending'],state['unresolved'],state['head'],state['valid']
    safe=lambda x:str(x).replace('|','\\|').replace('\n',' ')
    lines=['# SECURITY_MATRIX.md','','Generated from `.security/security.db`. Do not edit directly.','',
           f'- Git HEAD: `{head}`',
           f'- Unreviewed scope entries: **{pending}**',
           f'- Open audit targets: **{state["open_targets"]}** of **{len(targets)}**',
           f'- Unresolved findings: **{unresolved}**',
           f'- Integration review: **{"VALID" if valid else "REQUIRED"}**','']
    if targets:
        lines+=['## Audit targets','','| ID | Priority | Reachability | Where | Target | Status |','|---|---|---|---|---|---|']
        for t in targets:
            lines.append(f"| {safe(t['id'])} | {safe(t['priority'])} | {safe(t['reachability'])} | `{safe(t['paths'])}` | {safe(t['title'])} | {safe(t['status'])} |")
        lines.append('')
    lines+=['## Findings','','| ID | Severity | Location | Finding | Status |','|---|---|---|---|---|']
    for r in rows:
        lines.append(f"| {safe(r['id'])} | {safe(r['severity'])} | `{safe(r['path'])}::{safe(r['symbol'])}` | {safe(r['title'])} | {safe(r['status'])} |")
    lines+=['','## Details','']
    for r in rows:
        lines += [f"### {r['id']}: {r['title']}",f"- Evidence: {r['evidence']}",f"- Description: {r['description']}"]
        if r['target_id']: lines.append(f"- Audit target: {r['target_id']}")
        lines += [f"- Source hash: `{r['source_hash']}`",'']
    (root/'SECURITY_MATRIX.md').write_text('\n'.join(lines)+'\n')
    status=['# REMEDIATION_STATUS.md','',f'Unresolved findings: {unresolved}',f'Open audit targets: {state["open_targets"]}','', '| ID | Function | Status |','|---|---|---|']
    for r in rows:status.append(f"| {r['id']} | `{r['symbol']}` | {r['status']} |")
    (root/'.security'/'REMEDIATION_STATUS.md').write_text('\n'.join(status)+'\n')
    (root/'.security'/'FINAL_SECURITY_REVIEW.md').write_text('# Final security review\n\n'+('PASSED for current snapshot.\n' if valid else 'REQUIRED: independent integration review not valid for current snapshot.\n'))
    return valid

def snapshot(root,c):
    entries=c.execute('SELECT path,status FROM scope ORDER BY path,status').fetchall()
    findings=c.execute('SELECT id,status,path,target_id FROM findings ORDER BY id').fetchall()
    targets=c.execute('SELECT id,status FROM targets ORDER BY id').fetchall()
    return digest(json.dumps({
        'scope':[(r['path'],r['status'],source_hash(root,r['path'])) for r in entries],
        'findings':[(r['id'],r['status'],r['path'],r['target_id']) for r in findings],
        'targets':[(r['id'],r['status']) for r in targets]},sort_keys=True))

def main():
    a=argparse.ArgumentParser();a.add_argument('--repo',default='.');sub=a.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('scan');s.add_argument('--mode',choices=['incremental','full'],default='incremental');s.add_argument('--base')
    s.add_argument('--include-generated',action='store_true',help='also scope lockfiles, EF migrations and alembic versions')
    s.add_argument('--include-tests',action='store_true',help='also scope tests/ trees (fixtures with baked-in credentials, for instance)')
    s=sub.add_parser('target-add',help='Scout output: record one audit target before analysing it')
    s.add_argument('--title',required=True)
    s.add_argument('--path',required=True,dest='paths',action='append',help='repeat for every path or path:start-end range in the target')
    s.add_argument('--reachability',required=True,help='who can trigger it, on a portable scale: anonymous < user < privileged < process (map your project roles onto it)')
    s.add_argument('--relevance',required=True,help='why it is security-relevant: auth boundary, file write, raw SQL, token lifetime...')
    s.add_argument('--priority',choices=['high','medium','low'],required=True)
    s.add_argument('--actor',required=True);s.add_argument('--note',default='')
    s=sub.add_parser('target-close');s.add_argument('id');s.add_argument('--status',choices=['audited','dismissed'],required=True);s.add_argument('--actor',required=True);s.add_argument('--note',required=True)
    s=sub.add_parser('finding');s.add_argument('--path',required=True);s.add_argument('--symbol',required=True);s.add_argument('--title',required=True);s.add_argument('--severity',choices=list(SEVERITIES),required=True);s.add_argument('--description',required=True);s.add_argument('--evidence',required=True);s.add_argument('--actor',required=True);s.add_argument('--target',help='audit target this candidate came from')
    s=sub.add_parser('transition');s.add_argument('id');s.add_argument('--status',required=True,choices=['needs_validation','confirmed','in_remediation','fixed_pending_verification','verified_fixed','integration_verified','false_positive','accepted_risk','reopened']);s.add_argument('--actor',required=True);s.add_argument('--note',required=True)
    s=sub.add_parser('scope-reviewed');s.add_argument('--run',type=int,required=True)
    s.add_argument('--path',help='one path of that run');s.add_argument('--all',action='store_true',help='every pending path of that run, for a scope you read in one pass');s.add_argument('--actor',required=True)
    s=sub.add_parser('review');s.add_argument('--status',choices=['passed','failed'],required=True);s.add_argument('--reviewer',required=True);s.add_argument('--note',required=True)
    s=sub.add_parser('check',help='read-only release gate: exit 0 when the review is valid, 1 when not');s.add_argument('--json',action='store_true');s.add_argument('--quiet',action='store_true')
    sub.add_parser('version',help='print the CLI version — compare it with the repo you installed from')
    sub.add_parser('status')
    args=a.parse_args()
    # `version` must answer outside a git repository too: that is where you run it from when you are
    # wondering whether the installed copy matches the one in the repo.
    if args.cmd=='version':
        print(VERSION);return
    root=root_dir(args.repo);c=db(root,create=args.cmd not in ('status','check'))
    try:
        if args.cmd=='scan':
            head=head_sha(root);paths=files(root,args.mode,args.base,args.include_generated,args.include_tests)
            # A new scan supersedes the previous run's outstanding scope: keeping old pending rows
            # would block the gate forever on files a later run no longer lists.
            c.execute("UPDATE scope SET status='superseded' WHERE status='pending'")
            cur=c.execute('INSERT INTO runs(mode,commit_sha,created_at,status) VALUES(?,?,?,?)',(args.mode,head,now(),'pending'))
            run=cur.lastrowid
            for path in paths:c.execute('INSERT INTO scope(run_id,path) VALUES(?,?)',(run,path))
            # Existing findings in changed files require revalidation.
            for path in paths:
                for r in c.execute('SELECT id,status,source_hash FROM findings WHERE path=?',(path,)).fetchall():
                    if r['source_hash']!=source_hash(root,path) and r['status'] in ('verified_fixed','integration_verified'):
                        c.execute('UPDATE findings SET status=?,updated_at=? WHERE id=?',('reopened',now(),r['id']))
                        c.execute('INSERT INTO events(finding_id,previous,next,actor,note,created_at) VALUES(?,?,?,?,?,?)',(r['id'],r['status'],'reopened','system','Source changed',now()))
            c.commit();render(root,c)
            print(json.dumps({'run':run,'mode':args.mode,'paths':paths,'note':'Scope prepared. Next: the scout pass turns these paths into audit targets (target-add), an analyst reads each target, and a candidate is only confirmed after a reproduction. No automatic vulnerability detection was performed.'},indent=2))
        elif args.cmd=='target-add':
            run=c.execute('SELECT id FROM runs ORDER BY id DESC LIMIT 1').fetchone()
            if not run:raise ValueError('Run scan first')
            paths=target_paths(args.paths)
            if not paths:raise ValueError('A target needs at least one path')
            for p in paths:
                if not (root/p.split(':')[0]).resolve().is_relative_to(root):raise ValueError(f'Path outside repository: {p}')
            tid='T-'+digest('|'.join([args.title,*paths]))[:8].upper()
            if c.execute('SELECT id FROM targets WHERE id=?',(tid,)).fetchone():
                raise ValueError(f'{tid} is already recorded for that title and those paths; close it or change the title')
            c.execute('INSERT INTO targets VALUES(?,?,?,?,?,?,?,?,?,?,?)',(tid,args.title,','.join(paths),args.reachability,args.relevance,args.priority,'open',args.note,run['id'],now(),now()))
            c.commit();render(root,c);print(tid)
        elif args.cmd=='target-close':
            t=c.execute('SELECT * FROM targets WHERE id=?',(args.id,)).fetchone()
            if not t:raise ValueError('Unknown audit target')
            if t['status']!='open':raise ValueError(f'{args.id} is already {t["status"]}')
            c.execute('UPDATE targets SET status=?,note=?,updated_at=? WHERE id=?',(args.status,args.note,now(),args.id))
            c.commit();render(root,c);print(args.id,args.status)
        elif args.cmd=='finding':
            if not (root/args.path).resolve().is_relative_to(root):raise ValueError('Path outside repository')
            run=c.execute('SELECT id FROM runs ORDER BY id DESC LIMIT 1').fetchone()
            if not run:raise ValueError('Run scan first')
            if args.target and not c.execute('SELECT id FROM targets WHERE id=?',(args.target,)).fetchone():
                raise ValueError(f'Unknown audit target {args.target}')
            fid='SEC-'+digest('|'.join([args.path,args.symbol,args.title]))[:12].upper()
            cur=c.execute('INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(fid,args.path,args.symbol,args.title,args.severity,args.description,args.evidence,'needs_validation',source_hash(root,args.path),run['id'],now(),args.target))
            if not cur.rowcount:
                # Silently ignoring the duplicate would still leave an event claiming a transition.
                raise ValueError(f'{fid} is already recorded for that path/symbol/title; use transition to change it')
            c.execute('INSERT INTO events(finding_id,previous,next,actor,note,created_at) VALUES(?,?,?,?,?,?)',(fid,None,'needs_validation',args.actor,'Candidate recorded',now()))
            c.commit();render(root,c);print(fid)
        elif args.cmd=='transition':
            r=c.execute('SELECT * FROM findings WHERE id=?',(args.id,)).fetchone()
            if not r:raise ValueError('Unknown finding')
            allowed={'needs_validation':{'confirmed','false_positive'},'confirmed':{'in_remediation','accepted_risk'},'in_remediation':{'fixed_pending_verification','confirmed'},'fixed_pending_verification':{'verified_fixed','reopened'},'verified_fixed':{'integration_verified','reopened'},'integration_verified':{'reopened'},'reopened':{'in_remediation','needs_validation'},'accepted_risk':{'reopened'},'false_positive':{'reopened'}}
            if args.status not in allowed.get(r['status'],set()):raise ValueError('Invalid transition')
            if args.status in ('verified_fixed','integration_verified') and r['source_hash']!=source_hash(root,r['path']):
                # Update fingerprint only at verified_fixed, after the independent verifier checks the new source.
                if args.status!='verified_fixed':raise ValueError('Source changed since verification')
            if args.status=='integration_verified':raise ValueError('Use review command for integration approval')
            if args.status=='verified_fixed':
                c.execute('UPDATE findings SET source_hash=? WHERE id=?',(source_hash(root,r['path']),args.id))
            c.execute('UPDATE findings SET status=?,updated_at=? WHERE id=?',(args.status,now(),args.id))
            c.execute('INSERT INTO events(finding_id,previous,next,actor,note,created_at) VALUES(?,?,?,?,?,?)',(args.id,r['status'],args.status,args.actor,args.note,now()))
            c.commit();render(root,c);print(args.id,args.status)
        elif args.cmd=='scope-reviewed':
            if not args.path and not args.all:raise ValueError('Pass --path PATH or --all')
            if args.all:
                cur=c.execute('UPDATE scope SET status="reviewed" WHERE run_id=? AND status="pending"',(args.run,))
                if not cur.rowcount:raise ValueError('No pending scope entries left in that run')
                c.commit();render(root,c);print(f'reviewed {cur.rowcount} path(s) of run {args.run}');return
            cur=c.execute('UPDATE scope SET status="reviewed" WHERE run_id=? AND path=? AND status="pending"',(args.run,args.path))
            if not cur.rowcount:
                existing=c.execute('SELECT status FROM scope WHERE run_id=? AND path=?',(args.run,args.path)).fetchone()
                raise ValueError(f'Scope entry is not pending ({existing["status"] if existing else "not in that run"}); run a fresh scan' if existing else 'Scope path not found')
            c.commit();render(root,c);print('reviewed',args.path)
        elif args.cmd=='review':
            unresolved=c.execute("SELECT COUNT(*) FROM findings WHERE status NOT IN ('verified_fixed','integration_verified','false_positive')").fetchone()[0]
            pending=c.execute('SELECT COUNT(*) FROM scope WHERE status="pending"').fetchone()[0]
            open_targets=c.execute("SELECT COUNT(*) FROM targets WHERE status='open'").fetchone()[0]
            if args.status=='passed' and (unresolved or pending or open_targets):
                raise ValueError(f'Cannot pass: {unresolved} unresolved, {pending} unreviewed scope entries, {open_targets} open audit targets')
            c.execute('INSERT INTO reviews(commit_sha,scope_digest,status,reviewer,note,created_at) VALUES(?,?,?,?,?,?)',(head_sha(root),snapshot(root,c),args.status,args.reviewer,args.note,now()))
            c.commit();render(root,c);print('review recorded:',args.status)
        elif args.cmd in ('status','check'):
            # Both are read-only: a command that answers "is this committable?" must not rewrite the
            # tree it is asked about. Documents are written by the mutating commands instead.
            state=evaluate(root,c)
            findings=[dict(x) for x in c.execute('SELECT id,path,symbol,severity,status,target_id FROM findings ORDER BY id')] if c else []
            unreviewed=[dict(x) for x in c.execute('SELECT run_id,path FROM scope WHERE status="pending"')] if c else []
            targets=[dict(x) for x in c.execute('SELECT id,title,paths,reachability,relevance,priority,status FROM targets ORDER BY id')] if c else []
            latest=state['latest']
            payload={'version':VERSION,'valid_integration_review':state['valid'],'head':state['head'],'reason':state['reason'],
                     'latest_review':dict(latest) if latest else None,
                     'review_applies_to_head':bool(latest and latest['commit_sha']==state['head']),
                     'unreviewed_scope_count':state['pending'],'unresolved_count':state['unresolved'],
                     'open_targets_count':state['open_targets'],
                     'findings':findings,'unreviewed_scope':unreviewed,'targets':targets}
            if args.cmd=='check':
                if not args.quiet:
                    if args.json:
                        print(json.dumps(payload,indent=2))
                    else:
                        # stderr: the gate runs inside git, where stdout is not the developer's terminal.
                        print(f"security gate: {'pass — ' if state['valid'] else 'BLOCKED — '}{state['reason']}",file=sys.stderr)
                sys.exit(0 if state['valid'] else 1)
            print(json.dumps(payload,indent=2))
    finally:
        if c is not None:c.close()

if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,sqlite3.Error) as e:print(f'ERROR: {e}',file=sys.stderr);sys.exit(2)
