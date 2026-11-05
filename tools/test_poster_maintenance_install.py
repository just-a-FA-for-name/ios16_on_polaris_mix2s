import ctypes as C
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUBS = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#define ARM64_BOARD_CONFIG_SWEET 1
#define kSuccess 0
#define FREAD 1
#define FWRITE 2
#define UIO_READ 0
#define UIO_WRITE 1
#define UIO_SYSSPACE 0
#define IO_SYNC 1
#define IO_UNIT 2
#define Z_WAITOK 0
#define NULLVP NULL
#define VATTR_INIT(p) memset(p, 0, sizeof(*(p)))
#define VATTR_WANTED(p, field) ((void)0)
#define printf(...) ((void)0)
typedef void *DTEntry;
typedef uintptr_t vm_offset_t;
typedef void *vfs_context_t;
typedef char *caddr_t;
struct file { int exists, mode, uid, links, regular; size_t length; uint8_t data[524288]; };
typedef struct file *vnode_t;
struct vnode_attr { uint64_t va_data_size; unsigned va_uid, va_nlink; };
static struct file files[2];
static int enabled, board, writes, opens, fail_create, corrupt, fail_write;
static uint32_t image[8];
static uint64_t base, memory_size, region[2];
bool polaris_touch_i2c_board(void) { return board; }
static void PE_parse_boot_argn(const char *name, void *out, int size) { memcpy(out, &enabled, size); }
static int SecureDTLookupEntry(void *root, const char *name, DTEntry *out) { *out = (void *)1; return 0; }
static int SecureDTGetProperty(DTEntry node, const char *key, const void **out, unsigned *size) {
    if (!strcmp(key, "dram-base")) { *out = &base; *size = 8; }
    else if (!strcmp(key, "dram-size")) { *out = &memory_size; *size = 8; }
    else { *out = region; *size = 16; }
    return 0;
}
static uintptr_t ml_static_ptovirt(uintptr_t address) { return (uintptr_t)image; }
static vfs_context_t vfs_context_kernel(void) { return NULL; }
static void *vfs_context_ucred(vfs_context_t ctx) { return NULL; }
static void *vfs_context_proc(vfs_context_t ctx) { return NULL; }
static void *kalloc_data(size_t size, int flags) { return malloc(size); }
static void kfree_data(void *data, size_t size) { free(data); }
static int vnode_open(const char *path, int flags, int mode, int extra, vnode_t *vp, vfs_context_t ctx) {
    opens++;
    int index = !strcmp(path, "/usr/libexec/polaris-poster-maintenance") ? 0 :
        !strcmp(path, "/Library/LaunchDaemons/com.polaris.poster-maintenance.plist") ? 1 : -1;
    if (index < 0) return EINVAL;
    struct file *f = &files[index];
    if (!(flags & O_NOFOLLOW)) return EINVAL;
    if (flags & O_CREAT) {
        if (!(flags & O_EXCL) || flags & O_TRUNC) return EINVAL;
        if (f->exists) return EEXIST;
        if (fail_create == index + 1) return EIO;
        f->exists = 1; f->mode = mode;
    } else if (!f->exists) return ENOENT;
    *vp = f;
    return 0;
}
static int vnode_close(vnode_t vp, int flags, vfs_context_t ctx) { return 0; }
static int vnode_isreg(vnode_t vp) { return vp->regular; }
static int vnode_getattr(vnode_t vp, struct vnode_attr *attr, vfs_context_t ctx) {
    attr->va_data_size = vp->length; attr->va_uid = vp->uid; attr->va_nlink = vp->links;
    return 0;
}
static int vn_rdwr(int operation, vnode_t vp, caddr_t bytes, int size, int offset,
    int space, int flags, void *cred, int *residual, void *process) {
    *residual = 0;
    if (operation == UIO_READ) { memcpy(bytes, vp->data, size); return 0; }
    writes++;
    if (!(flags & IO_SYNC) || !(flags & IO_UNIT)) return EINVAL;
    vp->length = size;
    memcpy(vp->data, bytes, size);
    if (corrupt) vp->data[0] ^= 1;
    if (fail_write == (int)(vp - files) + 1) { vp->length = size / 2; return EIO; }
    return 0;
}
'''

CONTROL = r'''
void mock_reset(void) {
    memset(files, 0, sizeof(files));
    for (int i = 0; i < 2; i++) { files[i].links = 1; files[i].regular = 1; }
    memset(image, 0, sizeof(image)); image[0] = 0xfeedfacf; image[1] = 0x0100000c; image[3] = 2;
    enabled = writes = opens = fail_create = corrupt = fail_write = 0; board = 1;
    base = 0x100000000ull; memory_size = 0x100000; region[0] = base + 0x4000; region[1] = sizeof(image);
}
void mock_existing(int index, int valid) {
    struct file *f = &files[index]; f->exists = 1;
    f->length = index ? sizeof(pm_plist) - 1 : sizeof(image);
    memcpy(f->data, index ? (const void *)pm_plist : image, f->length);
    if (!valid) f->data[0] ^= 1;
}
void mock_set(int key, int value) {
    switch (key) {
    case 0: enabled = value; break;
    case 1: board = value; break;
    case 2: fail_create = value; break;
    case 3: image[3] = value; break;
    case 4: corrupt = value; break;
    case 5: fail_write = value; break;
    case 6: files[0].uid = value; break;
    case 7: files[0].links = value; break;
    case 8: files[0].regular = value; break;
    case 9: region[0] += value; break;
    case 10: region[1] = value; break;
    }
}
int mock_get(int key) {
    switch (key) {
    case 0: return writes;
    case 1: return opens;
    case 2: return files[0].exists;
    case 3: return files[1].exists;
    case 4: return files[0].mode;
    case 5: return files[1].mode;
    }
    return -1;
}
'''


class PosterMaintenanceInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'out').mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix='poster-install-', dir=ROOT / 'out')
        cls.addClassCleanup(cls.temp.cleanup)
        patch = (ROOT / 'xnu/patches/0101-polaris-scoped-poster-maintenance.patch').read_text()
        lines = patch.splitlines()
        end = next(i for i in range(3, len(lines)) if lines[i].startswith('--- a/'))
        added = lines[3:end]
        if not all(line.startswith('+') for line in added):
            raise ValueError('Unexpected installer patch layout')
        source = '\n'.join(line[1:] for line in added if not line.startswith('+#include'))
        file = Path(cls.temp.name) / 'fixture.c'
        file.write_text(STUBS + source + '\n' + CONTROL)
        binary = Path(cls.temp.name) / 'fixture.so'
        linking = ['-dynamiclib'] if sys.platform == 'darwin' else ['-shared', '-fPIC']
        subprocess.run(['cc', '-std=c11', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra',
                        '-Werror', '-Wno-unused-parameter', *linking, str(file), '-o', str(binary)], check=True)
        cls.lib = C.CDLL(str(binary))
        cls.lib.mock_set.argtypes = cls.lib.mock_existing.argtypes = [C.c_int, C.c_int]
        cls.lib.mock_get.argtypes = [C.c_int]

    def setUp(self):
        self.lib.mock_reset()

    def run_installer(self):
        self.lib.polaris_poster_maintenance_install()

    def test_default_disabled_and_wrong_board_do_no_io(self):
        self.run_installer()
        self.assertEqual(self.lib.mock_get(1), 0)
        self.lib.mock_set(0, 1)
        self.lib.mock_set(1, 0)
        self.run_installer()
        self.assertEqual(self.lib.mock_get(1), 0)

    def test_bad_payload_has_no_io(self):
        for key, value in ((3, 6), (9, 1), (10, 0), (10, 524289)):
            with self.subTest(key=key):
                self.lib.mock_reset()
                self.lib.mock_set(0, 1)
                self.lib.mock_set(key, value)
                self.run_installer()
                self.assertEqual(self.lib.mock_get(1), 0)

    def test_creates_only_two_verified_files_with_explicit_modes(self):
        self.lib.mock_set(0, 1)
        self.run_installer()
        self.assertEqual([self.lib.mock_get(i) for i in (0, 2, 3, 4, 5)],
                         [2, 1, 1, 0o755, 0o644])
        self.run_installer()
        self.assertEqual(self.lib.mock_get(0), 2)

    def test_unknown_existing_files_are_never_overwritten(self):
        for index in (0, 1):
            with self.subTest(index=index):
                self.lib.mock_reset()
                self.lib.mock_set(0, 1)
                self.lib.mock_existing(index, 0)
                self.run_installer()
                self.assertEqual(self.lib.mock_get(0), 0)

    def test_owner_links_and_file_type_are_checked(self):
        for key, value in ((6, 501), (7, 2), (8, 0)):
            self.lib.mock_reset()
            self.lib.mock_set(0, 1)
            self.lib.mock_existing(0, 1)
            self.lib.mock_set(key, value)
            self.run_installer()
            self.assertEqual(self.lib.mock_get(0), 0)

    def test_helper_failure_never_creates_launch_job(self):
        for key in (2, 4, 5):
            self.lib.mock_reset()
            self.lib.mock_set(0, 1)
            self.lib.mock_set(key, 1)
            self.run_installer()
            self.assertEqual(self.lib.mock_get(3), 0)

    def test_orphan_job_is_not_activated_by_creating_helper(self):
        self.lib.mock_set(0, 1)
        self.lib.mock_existing(1, 1)
        self.run_installer()
        self.assertEqual(self.lib.mock_get(0), 0)
        self.assertEqual(self.lib.mock_get(2), 0)

    def test_partial_job_is_not_overwritten_on_retry(self):
        self.lib.mock_set(0, 1)
        self.lib.mock_set(5, 2)
        self.run_installer()
        self.assertEqual(self.lib.mock_get(0), 2)
        self.lib.mock_set(5, 0)
        self.run_installer()
        self.assertEqual(self.lib.mock_get(0), 2)


if __name__ == '__main__':
    unittest.main()
