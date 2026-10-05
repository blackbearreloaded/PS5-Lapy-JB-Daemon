"""Exercise the helper's actual credential snapshot and restore functions on host."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OwnedCredentialsTests(unittest.TestCase):
    def test_full_attributes_round_trip_and_flag_offset(self):
        source = (ROOT / 'source/owned_root_daemon.c').read_text()
        structure = source[source.index('struct credentials {'):]
        structure = structure[:structure.index('};') + 2]
        functions = source[source.index('static int save_credentials('):
                           source.index('static int await_target_stop(')]
        elevate = source[source.index('    elevated = original;'):
                         source.index('    cred_changed = 1;')]
        program = '''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define UCRED_NGROUPS 0x10
''' + structure + '''
static struct credentials state;
static int attrs_error;
'''
        for field, kind in [('uid', 'uid_t'), ('ruid', 'uid_t'), ('svuid', 'uid_t'),
                            ('rgid', 'gid_t'), ('svgid', 'gid_t'), ('authid', 'uint64_t')]:
            program += f'''
static {kind} kernel_get_ucred_{field}(pid_t pid) {{ (void)pid; return state.{field}; }}
static int kernel_set_ucred_{field}(pid_t pid, {kind} value) {{ (void)pid; state.{field} = value; return 0; }}
'''
        program += '''
static int kernel_get_ucred_attrs(pid_t pid, uint8_t attrs[32]) {
    (void)pid; if (attrs_error) return -1;
    memcpy(attrs, state.attrs, 32); return 0;
}
static int kernel_set_ucred_attrs(pid_t pid, const uint8_t attrs[32]) {
    (void)pid; memcpy(state.attrs, attrs, 32); return 0;
}
static int kernel_get_ucred_caps(pid_t pid, uint8_t caps[16]) {
    (void)pid; memcpy(caps, state.caps, 16); return 0;
}
static int kernel_set_ucred_caps(pid_t pid, const uint8_t caps[16]) {
    (void)pid; memcpy(state.caps, caps, 16); return 0;
}
static int kernel_copyout(intptr_t address, void *out, size_t length) {
    (void)address; assert(length == sizeof(state.ngroups));
    memcpy(out, &state.ngroups, length); return 0;
}
static int kernel_copyin(const void *in, intptr_t address, size_t length) {
    (void)address; assert(length == sizeof(state.ngroups));
    memcpy(&state.ngroups, in, length); return 0;
}
#define SYSTEM_AUTHID UINT64_C(0x4801000000000013)
''' + functions + '''
int main(void) {
    struct credentials original, elevated;
    state.uid = state.ruid = state.svuid = 1000;
    state.rgid = state.svgid = 1000; state.ngroups = 1;
    for (unsigned i = 0; i < 32; ++i) state.attrs[i] = i + 1;
    assert(save_credentials(10, 0, &original) == 0);
''' + elevate + '''
    for (unsigned i = 0; i < 32; ++i)
        assert(elevated.attrs[i] == (uint8_t)(original.attrs[i] | (i == 3 ? 0x80 : 0)));
    assert(set_credentials(10, 0, &elevated) == 0);
    state.attrs[31] ^= 1;
    assert(!credentials_match(10, &elevated, 0));
    assert(set_credentials(10, 0, &original) == 0);
    assert(!memcmp(state.attrs, original.attrs, 32));
    attrs_error = 1;
    assert(save_credentials(10, 0, &original) == EFAULT);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            c = Path(directory) / 'test.c'
            exe = Path(directory) / 'test'
            c.write_text(program)
            subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'cc')), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
