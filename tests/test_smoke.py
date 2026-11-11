import pathlib, subprocess, sys, tempfile, unittest
CLI=pathlib.Path(__file__).resolve().parents[1]/'shared/security_matrix.py'
class Smoke(unittest.TestCase):
 def test_workflow(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)
   def run(*a):return subprocess.run([sys.executable,str(CLI),'--repo',d,*a],capture_output=True,text=True)
   subprocess.run(['git','init','-q',d],check=True)
   (p/'A.cs').write_text('class A {}')
   subprocess.run(['git','-C',d,'add','A.cs'],check=True)
   subprocess.run(['git','-C',d,'-c','user.name=Test','-c','user.email=test@example.com','commit','-qm','init'],check=True)
   (p/'A.cs').write_text('class A { void Run() {} }')
   self.assertEqual(run('scan').returncode,0)
   self.assertEqual(run('review','--status','passed','--reviewer','validator','--note','ok').returncode,2)
   self.assertEqual(run('scope-reviewed','--run','1','--path','A.cs','--actor','scanner').returncode,0)
   self.assertEqual(run('review','--status','passed','--reviewer','validator','--note','checked').returncode,0)
   self.assertTrue((p/'SECURITY_MATRIX.md').exists())
if __name__=='__main__':unittest.main()
