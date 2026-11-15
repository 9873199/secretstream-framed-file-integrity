"""Resolve only the installed same-version sodium extension for frozen Python source."""
import importlib.abc,importlib.metadata,importlib.util,json,os,runpy,sys,sysconfig
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in [HERE/'replay-source',*HERE.parents] if (p/'src/nacl/secretstream.py').exists())
assert importlib.metadata.version('PyNaCl')=='1.6.2','Install the dependency-lock PyNaCl1.6.2 wheel'
EXT=Path(sysconfig.get_path('platlib'))/'nacl/_sodium.pyd'
if not EXT.exists():
 EXT=next((Path(sysconfig.get_path('platlib'))/'nacl').glob('_sodium*.so'))
class SodiumExtension(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='nacl._sodium':return importlib.util.spec_from_file_location(fullname,str(EXT))
sys.meta_path.insert(0,SodiumExtension());sys.path[:0]=[str(ROOT/'src'),str(ROOT),str(HERE)]
if len(sys.argv)>1 and sys.argv[1]=='--smoke':
 import io,nacl,nacl.secretstream as s
 assert Path(s.__file__).resolve().is_relative_to(ROOT.resolve())
 key=b'K'*32;enc=io.BytesIO();out=io.BytesIO();s.encrypt_stream(io.BytesIO(b'portable-control'),enc,key);s.decrypt_stream(io.BytesIO(enc.getvalue()),out,key,scratch=io.BytesIO());assert out.getvalue()==b'portable-control'
 print(json.dumps({'status':'PASS','source':s.__file__,'extension':str(EXT),'wheel_version':'1.6.2'}));raise SystemExit(0)
if len(sys.argv)>1 and sys.argv[1]=='--pytest':
 import pytest
 raise SystemExit(pytest.main(sys.argv[2:]))
script=HERE/(sys.argv[1] if len(sys.argv)>1 else 'test_acceptance.py');sys.argv=[str(script),*sys.argv[2:]];runpy.run_path(str(script),run_name='__main__')
