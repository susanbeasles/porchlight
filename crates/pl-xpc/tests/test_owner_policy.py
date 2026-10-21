"""Compile the exact native policy helpers with a mocked filesystem/XPC credential.
This tests parsing/authorization, not macOS XPC APIs or installed ownership.
"""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[3]
s=(root/'crates/pl-xpc/csrc/xpc_shim.c').read_text()
a=s.index('static uid_t telemetry_owner');b=s.index('/* System policy:')
helpers=s[a:b]
test=r'''
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
typedef void *xpc_connection_t;
static const char *owner_text="501\n";
static size_t owner_len=4;
static uid_t peer_uid=501, console_uid=501, file_uid=0;
static mode_t file_mode=0600;
static int parent_bad=0, open_bad=0, links=1;
static int fake_lstat(const char *p, struct stat *s) {
 memset(s,0,sizeof(*s));
 s->st_mode=strcmp(p,"/dev/console")==0?S_IFCHR:S_IFDIR;
 s->st_uid=strcmp(p,"/dev/console")==0?console_uid:0;
 if (parent_bad) s->st_mode|=0020;
 return 0;
}
static int fake_open(const char *p, int flags) {
 (void)p; assert(flags&O_NOFOLLOW); assert(flags&O_CLOEXEC); return open_bad?-1:5;
}
static int fake_fstat(int fd, struct stat *s) {
 (void)fd; memset(s,0,sizeof(*s));s->st_mode=S_IFREG|file_mode;s->st_uid=file_uid;s->st_nlink=links;s->st_size=owner_len;return 0;
}
static ssize_t fake_read(int fd, void *buf, size_t len) {
 (void)fd; assert(owner_len<=len);memcpy(buf,owner_text,owner_len);return owner_len;
}
static int fake_close(int fd) {(void)fd;return 0;}

#define lstat fake_lstat
#define open fake_open
#define fstat fake_fstat
#define read fake_read
#define close fake_close
'''+helpers+r'''
int main(void) {
 assert(load_telemetry_owner()==0); assert(enrolled_owner_matches(peer_uid));
 peer_uid=502;assert(!enrolled_owner_matches(peer_uid));peer_uid=501;
 file_uid=501;assert(load_telemetry_owner()==-1);file_uid=0;
 file_mode=0660;assert(load_telemetry_owner()==-1);file_mode=0600;
 links=2;assert(load_telemetry_owner()==-1);links=1;
 parent_bad=1;assert(load_telemetry_owner()==-1);parent_bad=0;
 open_bad=1;assert(load_telemetry_owner()==-1);open_bad=0;
 owner_text="0\n";owner_len=2;assert(load_telemetry_owner()==-1);
 owner_text="501x";owner_len=4;assert(load_telemetry_owner()==-1);
 owner_text="501\0x";owner_len=5;assert(load_telemetry_owner()==-1);
 owner_text="4294967295";owner_len=10;assert(load_telemetry_owner()==-1);
 owner_text="501\n";owner_len=4;assert(load_telemetry_owner()==0);
 telemetry_owner=(uid_t)-1;assert(!enrolled_owner_matches(peer_uid));
 return 0;
}
'''
with tempfile.TemporaryDirectory() as td:
 p=Path(td);(p/'test.c').write_text(test)
 subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
print('PASS: enrollment assertions against exact native owner policy helpers with mocked filesystem/credentials; native XPC untested')
