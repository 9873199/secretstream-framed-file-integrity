import io
from test_acceptance import ContainerAcceptance,encrypt,strict,ShortWrite,Writes,s
c=ContainerAcceptance()
c.test_binary_roundtrip();print('Real secretstream binary round-trip: PASS')
c.test_reader_independent_push_and_rekey();print('Independent AD, rekey and FINAL: PASS')
c.test_every_byte_truncation_zero_target_writes();print('Every-byte truncation, zero target writes: PASS')
c.test_cross_file_splice_other_context();print('Different context splice rejected: PASS')
bad=0
tmp=io.BytesIO(b'OLD-DATA'*5);tmp.seek(5);n,out,tmp,src=strict(encrypt(b'new'),scratch=tmp)
leak=out.getvalue()!=b'new';bad+=leak
print('Reused scratch output:', 'FAIL - old content copied' if leak else 'PASS')
tmp=io.BytesIO(b'OLD-DATA');out=Writes()
try:strict(b'bad',scratch=tmp,target=out)
except s.ContainerFormatError:pass
unclean=tmp.getvalue()!=b'';bad+=unclean
print('Bad header clears scratch:', 'FAIL - content remains' if unclean else 'PASS')
plain=b'hello'*5
for label,tmp,out in [('Scratch',ShortWrite(),Writes()),('Target',io.BytesIO(),ShortWrite())]:
 try:
  n,out,tmp,src=strict(encrypt(plain),scratch=tmp,target=out);failed=out.getvalue()!=plain;bad+=failed
  print(label+' short write:',('FAIL - success reported, bytes='+str(len(out.getvalue()))+'/'+str(len(plain))) if failed else 'PASS')
 except OSError:print(label+' short write: PASS - error reported')
print('Observed failing checks:',bad)
raise SystemExit(bool(bad))
