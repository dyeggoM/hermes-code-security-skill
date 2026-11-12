import json, pathlib, subprocess, sys, tempfile, unittest

CLI = pathlib.Path(__file__).resolve().parents[1] / 'shared/security_matrix.py'


def git(d, *args):
    return subprocess.run(['git', '-C', d, '-c', 'user.name=Test', '-c', 'user.email=test@example.com', *args],
                          check=True, capture_output=True, text=True).stdout


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.d = self._tmp.name
        self.p = pathlib.Path(self.d)
        git(self.d, 'init', '-q')

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(CLI), '--repo', self.d, *args],
                              capture_output=True, text=True)

    def ok(self, *args):
        r = self.run_cli(*args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def write(self, name, text):
        path = self.p / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return name


class Smoke(Base):
    def test_workflow(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', 'A.cs')
        git(self.d, 'commit', '-qm', 'init')
        self.write('A.cs', 'class A { void Run() {} }')
        self.ok('scan')
        self.assertEqual(self.run_cli('review', '--status', 'passed', '--reviewer', 'validator',
                                      '--note', 'ok').returncode, 2)
        self.ok('scope-reviewed', '--run', '1', '--path', 'A.cs', '--actor', 'scanner')
        self.ok('review', '--status', 'passed', '--reviewer', 'validator', '--note', 'checked')
        self.assertTrue((self.p / 'SECURITY_MATRIX.md').exists())

    def test_scope_reviewed_all_clears_a_multi_file_run_in_one_call(self):
        for name in ('A.cs', 'B.cs', 'C.cs'):
            self.write(name, 'class X {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        for name in ('A.cs', 'B.cs', 'C.cs'):
            self.write(name, 'class X { int y; }')
        scan = self.ok('scan')
        run = json.loads(scan.stdout)['run']
        self.assertEqual(len(json.loads(scan.stdout)['paths']), 3)
        # Without --all this is one call per path; the review cannot pass until every one is marked.
        self.assertEqual(self.run_cli('review', '--status', 'passed', '--reviewer', 'v',
                                      '--note', 'n').returncode, 2)
        self.ok('scope-reviewed', '--run', str(run), '--all', '--actor', 'scanner')
        self.ok('review', '--status', 'passed', '--reviewer', 'v', '--note', 'n')
        self.assertEqual(self.run_cli('scope-reviewed', '--run', str(run), '--all',
                                      '--actor', 'scanner').returncode, 2,
                         'a second --all with nothing pending is an error, not a silent no-op')

    def test_illegal_transition_and_outside_path(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', 'A.cs')
        git(self.d, 'commit', '-qm', 'init')
        self.write('A.cs', 'class A { int x; }')
        self.ok('scan')
        fid = self.ok('finding', '--path', 'A.cs', '--symbol', 'A', '--title', 't', '--severity', 'low',
                      '--description', 'd', '--evidence', 'e', '--actor', 'scanner').stdout.strip()
        self.assertEqual(self.run_cli('transition', fid, '--status', 'verified_fixed', '--actor', 'x',
                                      '--note', 'n').returncode, 2)
        self.assertEqual(self.run_cli('finding', '--path', '../other.cs', '--symbol', 'X', '--title', 't',
                                      '--severity', 'low', '--description', 'd', '--evidence', 'e',
                                      '--actor', 'a').returncode, 2)

    def test_duplicate_finding_is_rejected_without_a_phantom_event(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', 'A.cs')
        git(self.d, 'commit', '-qm', 'init')
        self.write('A.cs', 'class A { int x; }')
        self.ok('scan')
        args = ('finding', '--path', 'A.cs', '--symbol', 'A', '--title', 'dup', '--severity', 'low',
                '--description', 'd', '--evidence', 'e')
        self.ok(*args, '--actor', 'first')
        second = self.run_cli(*args, '--actor', 'second')
        self.assertEqual(second.returncode, 2)
        self.assertIn('already recorded', second.stderr)
        import sqlite3
        with sqlite3.connect(self.p / '.security' / 'security.db') as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM findings').fetchone()[0], 1)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)


class Scope(Base):
    def test_new_scan_supersedes_the_previous_run(self):
        self.write('A.cs', 'class A {}')
        self.write('B.cs', 'class B {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')

        self.write('A.cs', 'class A { int x; }')
        first = json.loads(self.ok('scan', '--mode', 'incremental').stdout)
        self.assertEqual(first['paths'], ['A.cs'])

        self.write('B.cs', 'class B { int y; }')
        second = json.loads(self.ok('scan', '--mode', 'incremental').stdout)
        self.assertEqual(second['paths'], ['A.cs', 'B.cs'])

        for path in second['paths']:
            self.ok('scope-reviewed', '--run', str(second['run']), '--path', path, '--actor', 'scanner')
        self.ok('review', '--status', 'passed', '--reviewer', 'validator', '--note', 'run 2 covered')
        self.assertTrue(json.loads(self.ok('status').stdout)['valid_integration_review'])

    def test_a_superseded_entry_cannot_be_marked_reviewed(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        self.write('A.cs', 'class A { int x; }')
        self.ok('scan')
        self.ok('scan')
        r = self.run_cli('scope-reviewed', '--run', '1', '--path', 'A.cs', '--actor', 'scanner')
        self.assertEqual(r.returncode, 2)
        self.assertIn('superseded', r.stderr)

    def test_scope_covers_the_front_end_and_skips_generated_files(self):
        self.write('imcui/src/services/api.ts', 'export const x = 1;\n')
        self.write('imcui/src/pages/Home.vue', '<template><div/></template>\n')
        self.write('scripts/dev.sh', 'echo hi\n')
        self.write('IMCAPI/Migrations/20260101000000_Initial.cs', 'class M {}\n')
        self.write('IMCAPI/DB/Models.cs', 'class Models {}\n')
        self.write('imcui/package-lock.json', '{"lockfileVersion": 3}\n')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')

        paths = json.loads(self.ok('scan', '--mode', 'full').stdout)['paths']
        self.assertEqual(paths, ['IMCAPI/DB/Models.cs', 'imcui/src/pages/Home.vue',
                                 'imcui/src/services/api.ts', 'scripts/dev.sh'])

        with_generated = json.loads(self.ok('scan', '--mode', 'full', '--include-generated').stdout)['paths']
        self.assertIn('IMCAPI/Migrations/20260101000000_Initial.cs', with_generated)
        self.assertIn('imcui/package-lock.json', with_generated)


class Gate(Base):
    """`check` is what the pre-commit hook runs: read-only, and honest about why it blocks."""

    def test_check_is_read_only_and_blocks_without_a_ledger(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        r = self.run_cli('check')
        self.assertEqual(r.returncode, 1)
        self.assertIn('no security ledger', r.stderr)
        self.assertFalse((self.p / '.security').exists(), 'check created a ledger')
        self.assertFalse((self.p / 'SECURITY_MATRIX.md').exists(), 'check wrote the matrix')

    def test_status_does_not_write_either(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        self.ok('status')
        self.assertFalse((self.p / '.security').exists())
        self.assertFalse((self.p / 'SECURITY_MATRIX.md').exists())

    def test_check_passes_then_blocks_when_head_moves(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        self.write('A.cs', 'class A { int x; }')
        self.ok('scan')
        self.ok('scope-reviewed', '--run', '1', '--path', 'A.cs', '--actor', 'scanner')
        self.ok('review', '--status', 'passed', '--reviewer', 'validator', '--note', 'read it')
        self.ok('check')

        git(self.d, 'add', 'A.cs')
        git(self.d, 'commit', '-qm', 'change')
        blocked = self.run_cli('check')
        self.assertEqual(blocked.returncode, 1)
        self.assertIn('HEAD is', blocked.stderr)

    def test_check_blocks_when_the_scope_hash_moved(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        self.write('A.cs', 'class A { int x; }')
        self.ok('scan')
        self.ok('scope-reviewed', '--run', '1', '--path', 'A.cs', '--actor', 'scanner')
        self.ok('review', '--status', 'passed', '--reviewer', 'validator', '--note', 'read it')
        # Same HEAD, different bytes on disk: the digest has to notice.
        self.write('A.cs', 'class A { int y; }')
        r = self.run_cli('check')
        self.assertEqual(r.returncode, 1)
        self.assertIn('source hash', r.stderr)

    def test_check_json_payload_reports_the_reason(self):
        self.write('A.cs', 'class A {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        r = self.run_cli('check', '--json')
        self.assertEqual(r.returncode, 1)
        payload = json.loads(r.stdout)
        self.assertFalse(payload['valid_integration_review'])
        self.assertIn('no security ledger', payload['reason'])


class Targets(Base):
    """The scout stage: a scope is not an audit until it has named, reachable targets."""

    def _scan_repo_read_pass(self):
        self.write('A.cs', 'class A {}')
        self.write('B.cs', 'class B {}')
        git(self.d, 'add', '.')
        git(self.d, 'commit', '-qm', 'init')
        self.write('A.cs', 'class A { int x; }')
        run = json.loads(self.ok('scan').stdout)['run']
        self.ok('scope-reviewed', '--run', str(run), '--all', '--actor', 'scanner')
        return run

    def test_an_open_target_blocks_the_gate(self):
        self._scan_repo_read_pass()
        tid = self.ok('target-add', '--title', 'Read path', '--path', 'A.cs',
                      '--reachability', 'anonymous', '--relevance', 'path handling',
                      '--priority', 'high', '--actor', 'scout').stdout.strip()
        self.assertTrue(tid.startswith('T-'))
        blocked = self.run_cli('check')
        self.assertEqual(blocked.returncode, 1)
        self.assertIn('BLOCKED', blocked.stderr)

        # Closing the target is what makes the review recordable at all; then the gate opens.
        self.ok('target-close', tid, '--status', 'audited', '--actor', 'analyst', '--note', 'read all of it')
        self.ok('review', '--status', 'passed', '--reviewer', 'validator', '--note', 'target audited')
        self.ok('check')

    def test_findings_link_back_to_their_target(self):
        self._scan_repo_read_pass()
        tid = self.ok('target-add', '--title', 'Read path', '--path', 'A.cs',
                      '--reachability', 'anonymous', '--relevance', 'path handling',
                      '--priority', 'high', '--actor', 'scout').stdout.strip()
        fid = self.ok('finding', '--path', 'A.cs', '--symbol', 'A.Read', '--title', 't', '--severity', 'high',
                      '--description', 'd', '--evidence', 'A.cs:1', '--actor', 'analyst',
                      '--target', tid).stdout.strip()
        status = json.loads(self.ok('status').stdout)
        self.assertEqual([f['target_id'] for f in status['findings']], [tid])
        self.assertIn('| ' + tid, (self.p / 'SECURITY_MATRIX.md').read_text())
        self.assertIn(fid, (self.p / 'SECURITY_MATRIX.md').read_text())

    def test_unknown_target_and_outside_paths_are_rejected(self):
        self._scan_repo_read_pass()
        r = self.run_cli('finding', '--path', 'A.cs', '--symbol', 'A', '--title', 't', '--severity', 'low',
                         '--description', 'd', '--evidence', 'e', '--actor', 'a', '--target', 'T-NOPE')
        self.assertEqual(r.returncode, 2)
        self.assertIn('Unknown audit target', r.stderr)
        r = self.run_cli('target-add', '--title', 'x', '--path', '../evil.cs', '--reachability', 'anon',
                         '--relevance', 'r', '--priority', 'low', '--actor', 's')
        self.assertEqual(r.returncode, 2)
        self.assertIn('outside repository', r.stderr)

    def test_duplicate_target_is_rejected(self):
        self._scan_repo_read_pass()
        args = ('target-add', '--title', 'Read path', '--path', 'A.cs', '--reachability', 'anonymous',
                '--relevance', 'path handling', '--priority', 'high', '--actor', 'scout')
        self.ok(*args)
        r = self.run_cli(*args)
        self.assertEqual(r.returncode, 2)
        self.assertIn('already recorded', r.stderr)

    def test_a_review_pass_requires_closed_targets(self):
        self._scan_repo_read_pass()
        self.ok('target-add', '--title', 'Read path', '--path', 'A.cs', '--reachability', 'anonymous',
                '--relevance', 'path handling', '--priority', 'high', '--actor', 'scout')
        r = self.run_cli('review', '--status', 'passed', '--reviewer', 'v', '--note', 'n')
        self.assertEqual(r.returncode, 2)
        self.assertIn('open audit targets', r.stderr)


if __name__ == '__main__':
    unittest.main()
