"""Real libsodium container acceptance; no remote storage."""
import io,struct,unittest
import nacl.bindings as b
import nacl.secretstream as s
KEY=b'K'*b.crypto_secretstream_xchacha20poly1305_KEYBYTES
CTX=b'backup-context-A';A=b.crypto_secretstream_xchacha20poly1305_ABYTES
MSG=b.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
FINAL=b.crypto_secretstream_xchacha20poly1305_TAG_FINAL
REKEY=b.crypto_secretstream_xchacha20poly1305_TAG_REKEY
LIMIT=A+16
class ShortRead(io.BytesIO):
 def __init__(self,value,cap=2):super().__init__(value);self.cap=cap;self.requests=[]
 def read(self,n=-1):
  if n<0:raise AssertionError('unbounded read')
  self.requests.append(n);return super().read(min(n,self.cap))
class NonSeek:
 def __init__(self,value):self.inner=ShortRead(value,3);self.closed=False
 def read(self,n=-1):return self.inner.read(n)
class Writes(io.BytesIO):
 def __init__(self,value=b''):super().__init__(value);self.calls=[]
 def write(self,value):self.calls.append(bytes(value));return super().write(value)
class BrokenWrite(io.BytesIO):
 def write(self,value):raise OSError('synthetic destination failure')
class ShortWrite(io.BytesIO):
 def write(self,value):return super().write(value[:max(1,len(value)//2)])
def encrypt(data=b'abc\x00def'*8,context=CTX):
 out=io.BytesIO();s.encrypt_stream(ShortRead(data),out,KEY,context,max_frame_length=LIMIT);return out.getvalue()
def split(data):
 h=data[:s.CONTAINER_HEADER_SIZE];pos=len(h);frames=[]
 while pos<len(data):
  n=struct.unpack('!I',data[pos:pos+4])[0];frames.append(data[pos:pos+4+n]);pos+=4+n
 assert pos==len(data);return h,frames
def strict(data,context=CTX,scratch=None,target=None):
 src=NonSeek(data);scratch=io.BytesIO() if scratch is None else scratch;target=Writes() if target is None else target
 n=s.decrypt_stream(src,target,KEY,context,scratch=scratch,max_frame_length=LIMIT)
 return n,target,scratch,src
def ad(h,context,seq,n):
 return b'nacl.secretstream/1'+b'h'+struct.pack('!I',len(h))+h+b'c'+struct.pack('!I',len(context))+context+b's'+struct.pack('!Q',seq)+b'l'+struct.pack('!I',n)
def independent_container(chunks,context=CTX):
 state=b.crypto_secretstream_xchacha20poly1305_state();head=b.crypto_secretstream_xchacha20poly1305_init_push(state,KEY);h=b'NACLSS\x01'+head;out=h
 for i,(plain,tag) in enumerate(chunks):
  n=len(plain)+A;cipher=b.crypto_secretstream_xchacha20poly1305_push(state,plain,ad(h,context,i,n),tag);out+=struct.pack('!I',n)+cipher
 return out
def independent_pull(data,context=CTX):
 h,frames=split(data);state=b.crypto_secretstream_xchacha20poly1305_state();b.crypto_secretstream_xchacha20poly1305_init_pull(state,h[-b.crypto_secretstream_xchacha20poly1305_HEADERBYTES:],KEY)
 return [b.crypto_secretstream_xchacha20poly1305_pull(state,f[4:],ad(h,context,i,len(f)-4)) for i,f in enumerate(frames)]

class ContainerAcceptance(unittest.TestCase):
 def rejected(self,data,exception=s.ContainerError):
  out=Writes(b'preserve');out.seek(0,2);scratch=io.BytesIO();source=NonSeek(data)
  with self.assertRaises(exception):s.decrypt_stream(source,out,KEY,CTX,scratch=scratch,max_frame_length=LIMIT)
  self.assertEqual(out.calls,[]);self.assertEqual(out.getvalue(),b'preserve');self.assertEqual(scratch.getvalue(),b'');self.assertFalse(out.closed);self.assertFalse(scratch.closed);self.assertFalse(source.closed)
 def test_binary_roundtrip(self):
  plain=bytes(range(256));n,out,tmp,src=strict(encrypt(plain));self.assertEqual(out.getvalue(),plain);self.assertEqual(n,len(plain));self.assertEqual(tmp.getvalue(),b'');self.assertFalse(out.closed);self.assertFalse(src.closed)
 def test_empty_exactly_one_final(self):
  data=encrypt(b'');pulled=independent_pull(data);self.assertEqual(pulled,[(b'',FINAL)]);self.assertEqual(strict(data)[1].getvalue(),b'')
 def test_writer_independent_pull_and_ad(self):
  plain=b'abc'*30;pulled=independent_pull(encrypt(plain));self.assertEqual(b''.join(x[0] for x in pulled),plain);self.assertEqual(sum(t==FINAL for _,t in pulled),1);self.assertEqual(pulled[-1][1],FINAL)
 def test_reader_independent_push_and_rekey(self):
  data=independent_container([(b'first',MSG),(b'second',REKEY),(b'last',FINAL)]);self.assertEqual(strict(data)[1].getvalue(),b'firstsecondlast')
 def test_writer_explicit_rekey(self):
  out=io.BytesIO();writer=s.SecretStreamWriter(out,KEY,CTX,max_frame_length=LIMIT);writer.write(b'first');writer.rekey();writer.write(b'last');writer.finish();pulled=independent_pull(out.getvalue());self.assertEqual(b''.join(x[0] for x in pulled),b'firstlast');self.assertIn(REKEY,[t for _,t in pulled])
 def test_short_read_nonseek_input(self):
  plain=b'hello'*30;n,out,tmp,src=strict(encrypt(plain));self.assertEqual(out.getvalue(),plain);self.assertTrue(src.inner.requests)
 def test_bounded_short_source_reads(self):
  source=ShortRead(b'A'*100,1);out=io.BytesIO();s.encrypt_stream(source,out,KEY,CTX,max_frame_length=LIMIT);self.assertLessEqual(max(source.requests),LIMIT-A);self.assertEqual(strict(out.getvalue())[1].getvalue(),b'A'*100)
 def test_maximum_configured_frame_exact(self):
  data=independent_container([(b'X'*(LIMIT-A),FINAL)]);self.assertEqual(strict(data)[1].getvalue(),b'X'*(LIMIT-A))
 def test_unsafe_constructor_limit(self):
  with self.assertRaises((ValueError,TypeError)):s.SecretStreamWriter(io.BytesIO(),KEY,max_frame_length=s.CONTAINER_MAX_FRAME_LENGTH+1)
 def test_every_byte_truncation_zero_target_writes(self):
  data=encrypt(b'hello'*7)
  for end in range(len(data)):
   with self.subTest(offset=end):self.rejected(data[:end])
 def test_missing_final(self):
  h,f=split(encrypt());self.rejected(h+b''.join(f[:-1]),s.FinalFrameError)
 def test_duplicate_final(self):
  data=encrypt();h,f=split(data);self.rejected(data+f[-1],s.FinalFrameError)
 def test_trailing_byte(self):self.rejected(encrypt()+b'!',s.FinalFrameError)
 def test_reordered_frames(self):
  h,f=split(encrypt());f[0],f[1]=f[1],f[0];self.rejected(h+b''.join(f),s.FrameAuthenticationError)
 def test_cross_file_splice_same_context(self):
  h,f=split(encrypt());_,q=split(encrypt());f[1]=q[1];self.rejected(h+b''.join(f),s.FrameAuthenticationError)
 def test_cross_file_splice_other_context(self):
  h,f=split(encrypt());_,q=split(encrypt(context=b'other'));f[1]=q[1];self.rejected(h+b''.join(f),s.FrameAuthenticationError)
 def test_wrong_context(self):
  out=Writes();tmp=io.BytesIO()
  with self.assertRaises(s.FrameAuthenticationError):s.decrypt_stream(io.BytesIO(encrypt()),out,KEY,b'other',scratch=tmp,max_frame_length=LIMIT)
  self.assertEqual(out.calls,[]);self.assertEqual(tmp.getvalue(),b'')
 def test_wrong_key(self):
  with self.assertRaises(s.FrameAuthenticationError):s.SecretStreamReader(io.BytesIO(encrypt()),b'Z'*len(KEY),CTX,max_frame_length=LIMIT).readall()
 def test_bad_magic_and_version(self):
  data=encrypt()
  for index in [0,len(s.MAGIC)]:
   with self.subTest(index=index):x=bytearray(data);x[index]^=1;self.rejected(bytes(x),s.ContainerFormatError)
 def test_length_before_frame_body_read(self):
  data=encrypt()[:s.CONTAINER_HEADER_SIZE]+struct.pack('!I',LIMIT+1)
  source=ShortRead(data,100);reader=s.SecretStreamReader(source,KEY,CTX,max_frame_length=LIMIT);before=len(source.requests)
  with self.assertRaises(s.ContainerFormatError):reader.read_frame()
  self.assertLessEqual(max(source.requests[before:]),4)
 def test_length_below_abytes(self):self.rejected(encrypt()[:s.CONTAINER_HEADER_SIZE]+struct.pack('!I',A-1),s.ContainerFormatError)
 def test_incremental_not_complete_without_final(self):
  h,f=split(encrypt());reader=s.SecretStreamReader(io.BytesIO(h+b''.join(f[:-1])),KEY,CTX,max_frame_length=LIMIT);self.assertTrue(next(reader));self.assertFalse(reader.final_seen)
  with self.assertRaises(s.FinalFrameError):list(reader)
 def test_scratch_write_failure_zero_target(self):
  out=Writes();scratch=BrokenWrite()
  with self.assertRaisesRegex(OSError,'synthetic'):strict(encrypt(),scratch=scratch,target=out)
  self.assertEqual(out.calls,[]);self.assertFalse(scratch.closed)
 def test_final_copy_failure_propagated_and_scrubbed(self):
  tmp=io.BytesIO();out=BrokenWrite()
  with self.assertRaisesRegex(OSError,'synthetic'):strict(encrypt(),scratch=tmp,target=out)
  self.assertEqual(tmp.getvalue(),b'');self.assertFalse(out.closed)
 def test_dirty_scratch_does_not_leak_old_data(self):
  tmp=io.BytesIO(b'OLD-PLAINTEXT-SHOULD-NOT-LEAK'*4);tmp.seek(7);n,out,tmp,src=strict(encrypt(b'new'),scratch=tmp);self.assertEqual(out.getvalue(),b'new');self.assertEqual(n,3);self.assertEqual(tmp.getvalue(),b'')
 def test_header_failure_clears_dirty_scratch(self):
  tmp=io.BytesIO(b'OLD-PLAINTEXT');out=Writes()
  with self.assertRaises(s.ContainerFormatError):strict(b'bad',scratch=tmp,target=out)
  self.assertEqual(out.calls,[]);self.assertEqual(tmp.getvalue(),b'')
 def test_short_scratch_write_not_silent_success(self):
  tmp=ShortWrite();out=Writes();plain=b'hello'*5
  try:n,out,tmp,src=strict(encrypt(plain),scratch=tmp,target=out)
  except OSError:return
  self.assertEqual(out.getvalue(),plain);self.assertEqual(n,len(plain))
 def test_short_target_write_not_silent_success(self):
  out=ShortWrite();plain=b'hello'*5
  try:n,out,tmp,src=strict(encrypt(plain),target=out)
  except OSError:return
  self.assertEqual(out.getvalue(),plain);self.assertEqual(n,len(plain))
if __name__=='__main__':unittest.main(verbosity=2)
