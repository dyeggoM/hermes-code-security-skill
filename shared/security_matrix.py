#!/usr/bin/env python3
"""Hermes Security Matrix: deterministic state management, not an automated vulnerability detector."""
import argparse, datetime, hashlib, json, re, sqlite3, subprocess, sys
from pathlib import Path

def git(root,*args):
    x=subprocess.run(['git','-C',str(root),*args],capture_output=True,text=True)
    if x.returncode: raise RuntimeError(x.stderr.strip() or 'git failed')
    return x.stdout.strip()

def root_dir(value):
    p=Path(value).resolve()
    git(p,'rev-parse','--show-toplevel')
    return Path(git(p,'rev-parse','--show-toplevel'))

def db(root):
    folder=root/'.security';folder.mkdir(exist_ok=True)
    c=sqlite3.connect(folder/'security.db',timeout=30)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript("""CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, mode TEXT NOT NULL, commit_sha TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scope(run_id INTEGER NOT NULL, path TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY(run_id,path));
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, path TEXT NOT NULL, symbol TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL, status TEXT NOT NULL, source_hash TEXT NOT NULL, created_run INTEGER NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, previous TEXT, next TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, commit_sha TEXT NOT NULL, scope_digest TEXT NOT NULL, status TEXT NOT NULL, reviewer TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);""")
    return c

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def source_hash(root,path):
    f=(root/path).resolve()
    if not f.is_relative_to(root) or not f.is_file():return 'missing'
    return hashlib.sha256(f.read_bytes()).hexdigest()

def files(root,mode,base):
    if mode=='full':
        raw=git(root,'ls-files','--cached','--others','--exclude-standard').splitlines()
    else:
        raw=set(git(root,'diff','--name-only','HEAD').splitlines()+git(root,'ls-files','--others','--exclude-standard').splitlines())
        if base:raw|=set(git(root,'diff','--name-only',base,'HEAD').splitlines())
    return sorted(x for x in raw if x.endswith(('.cs','.csproj','.json','.config','.yml','.yaml','.razor','.cshtml')) and not any(y in x.split('/') for y in ('bin','obj','.security','.git')) and (root/x).is_file())

def render(root,c):
    rows=c.execute('SELECT * FROM findings ORDER BY CASE severity WHEN "critical" THEN 0 WHEN "high" THEN 1 WHEN "medium" THEN 2 ELSE 3 END,id').fetchall()
    pending=c.execute('SELECT COUNT(*) FROM scope WHERE status != "reviewed"').fetchone()[0]
    unresolved=c.execute("SELECT COUNT(*) FROM findings WHERE status NOT IN ('verified_fixed','integration_verified','false_positive')").fetchone()[0]
    latest=c.execute('SELECT * FROM reviews ORDER BY id DESC LIMIT 1').fetchone()
    head=git(root,'rev-parse','HEAD')
    valid=bool(latest and latest['status']=='passed' and latest['commit_sha']==head and latest['scope_digest']==snapshot(root,c) and unresolved==0 and pending==0)
    lines=['# SECURITY_MATRIX.md','','Generated from `.security/security.db`. Do not edit directly.','',f'- Git HEAD: `{head}`',f'- Unreviewed scope entries: **{pending}**',f'- Unresolved findings: **{unresolved}**',f'- Integration review: **{"VALID" if valid else "REQUIRED"}**','','| ID | Severity | Location | Finding | Status |','|---|---|---|---|---|']
    for r in rows:
        safe=lambda x:str(x).replace('|','\\|').replace('\n',' ')
        lines.append(f"| {safe(r['id'])} | {safe(r['severity'])} | `{safe(r['path'])}::{safe(r['symbol'])}` | {safe(r['title'])} | {safe(r['status'])} |")
    lines+=['','## Details','']
    for r in rows:lines += [f"### {r['id']}: {r['title']}",f"- Evidence: {r['evidence']}",f"- Description: {r['description']}",f"- Source hash: `{r['source_hash']}`",'']
    (root/'SECURITY_MATRIX.md').write_text('\n'.join(lines)+'\n')
    status=['# REMEDIATION_STATUS.md','',f'Unresolved findings: {unresolved}','', '| ID | Function | Status |','|---|---|---|']
    for r in rows:status.append(f"| {r['id']} | `{r['symbol']}` | {r['status']} |")
    (root/'.security'/'REMEDIATION_STATUS.md').write_text('\n'.join(status)+'\n')
    (root/'.security'/'FINAL_SECURITY_REVIEW.md').write_text('# Final security review\n\n'+('PASSED for current snapshot.\n' if valid else 'REQUIRED: independent integration review not valid for current snapshot.\n'))
    return valid

def snapshot(root,c):
    entries=c.execute('SELECT path,status FROM scope ORDER BY path,status').fetchall()
    findings=c.execute('SELECT id,status,path FROM findings ORDER BY id').fetchall()
    return digest(json.dumps({'scope':[(r['path'],r['status'],source_hash(root,r['path'])) for r in entries],'findings':[(r['id'],r['status'],r['path']) for r in findings]},sort_keys=True))

def main():
    a=argparse.ArgumentParser();a.add_argument('--repo',default='.');sub=a.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('scan');s.add_argument('--mode',choices=['incremental','full'],default='incremental');s.add_argument('--base')
    s=sub.add_parser('finding');s.add_argument('--path',required=True);s.add_argument('--symbol',required=True);s.add_argument('--title',required=True);s.add_argument('--severity',choices=['critical','high','medium','low'],required=True);s.add_argument('--description',required=True);s.add_argument('--evidence',required=True);s.add_argument('--actor',required=True)
    s=sub.add_parser('transition');s.add_argument('id');s.add_argument('--status',required=True,choices=['needs_validation','confirmed','in_remediation','fixed_pending_verification','verified_fixed','integration_verified','false_positive','accepted_risk','reopened']);s.add_argument('--actor',required=True);s.add_argument('--note',required=True)
    s=sub.add_parser('scope-reviewed');s.add_argument('--run',type=int,required=True);s.add_argument('--path',required=True);s.add_argument('--actor',required=True)
    s=sub.add_parser('review');s.add_argument('--status',choices=['passed','failed'],required=True);s.add_argument('--reviewer',required=True);s.add_argument('--note',required=True)
    sub.add_parser('status')
    args=a.parse_args();root=root_dir(args.repo);c=db(root)
    try:
        if args.cmd=='scan':
            head=git(root,'rev-parse','HEAD');paths=files(root,args.mode,args.base)
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
            print(json.dumps({'run':run,'mode':args.mode,'paths':paths,'note':'Scope prepared; agent must inspect and record findings. No automatic vulnerability detection was performed.'},indent=2))
        elif args.cmd=='finding':
            if not (root/args.path).resolve().is_relative_to(root):raise ValueError('Path outside repository')
            run=c.execute('SELECT id FROM runs ORDER BY id DESC LIMIT 1').fetchone()
            if not run:raise ValueError('Run scan first')
            fid='SEC-'+digest('|'.join([args.path,args.symbol,args.title]))[:12].upper()
            c.execute('INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)',(fid,args.path,args.symbol,args.title,args.severity,args.description,args.evidence,'needs_validation',source_hash(root,args.path),run['id'],now()))
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
            cur=c.execute('UPDATE scope SET status="reviewed" WHERE run_id=? AND path=?',(args.run,args.path))
            if not cur.rowcount:raise ValueError('Scope path not found')
            c.commit();render(root,c);print('reviewed',args.path)
        elif args.cmd=='review':
            unresolved=c.execute("SELECT COUNT(*) FROM findings WHERE status NOT IN ('verified_fixed','integration_verified','false_positive')").fetchone()[0]
            pending=c.execute('SELECT COUNT(*) FROM scope WHERE status != "reviewed"').fetchone()[0]
            if args.status=='passed' and (unresolved or pending):raise ValueError(f'Cannot pass: {unresolved} unresolved, {pending} unreviewed scope entries')
            c.execute('INSERT INTO reviews(commit_sha,scope_digest,status,reviewer,note,created_at) VALUES(?,?,?,?,?,?)',(git(root,'rev-parse','HEAD'),snapshot(root,c),args.status,args.reviewer,args.note,now()))
            c.commit();render(root,c);print('review recorded:',args.status)
        elif args.cmd=='status':
            valid=render(root,c)
            print(json.dumps({'valid_integration_review':valid,'findings':[dict(x) for x in c.execute('SELECT id,path,symbol,severity,status FROM findings ORDER BY id')],'unreviewed_scope':[dict(x) for x in c.execute('SELECT run_id,path FROM scope WHERE status!="reviewed"')]},indent=2))
    finally:c.close()
if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,sqlite3.Error) as e:print(f'ERROR: {e}',file=sys.stderr);sys.exit(2)
