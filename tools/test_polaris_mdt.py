import ctypes as C
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
U8 = C.c_ubyte


class Segment(C.Structure):
    _fields_ = [('index', C.c_uint32), ('file_offset', C.c_uint32),
                ('file_size', C.c_uint32), ('memory_size', C.c_uint32),
                ('destination', C.c_uint64), ('code_length', C.c_uint32)]


class Plan(C.Structure):
    _fields_ = [('count', C.c_uint32), ('relocatable', C.c_uint32),
                ('boot_address', C.c_uint64), ('span', C.c_uint64),
                ('segments', Segment * 100)]


class Blob(C.Structure):
    _fields_ = [('data', C.POINTER(U8)), ('size', C.c_size_t)]


def fixture(relocate=True, second_address=0x3000, file_size=4):
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = ident + struct.pack('<HHIIIIIHHHHHH', 2, 164, 1, 0x1000,
                                52, 0, 0, 52, 32, 3, 0, 0, 0)
    flags = 0x08000000 if relocate else 0
    return header + b''.join(struct.pack('<8I', *values) for values in (
        (0, 0, 0, 0, 0, 0, 0x02000000, 0),
        (1, 0x1000, 0, 0x1000, file_size, 8, flags, 0x1000),
        (1, 0x2000, 0, second_address, 0, 16, flags, 0x1000)))


def metadata_fixture(layout='packed'):
    data = bytearray(fixture())
    struct.pack_into('<I', data, 52 + 16, len(data))
    struct.pack_into('<I', data, 52 + 24, 0x07000000)
    struct.pack_into('<8I', data, 84, 0, 0x1000, 0, 0, 8, 8, 0x02000000, 0)
    header = bytes(data)
    hashes = b'HASHDATA'
    if layout == 'packed':
        data += hashes
    elif layout == 'embedded':
        data += bytes(0x1000 - len(data)) + hashes
    return bytes(data), header + hashes


class PolarisMDTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'out').mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix='mdt-test-', dir=ROOT / 'out')
        cls.addClassCleanup(cls.temp.cleanup)
        binary = Path(cls.temp.name) / 'mdt.so'
        linking = ['-dynamiclib'] if sys.platform == 'darwin' else ['-shared', '-fPIC']
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        *linking, str(ROOT / 'userland/polaris_mdt.c'),
                        '-o', str(binary)], check=True)
        cls.lib = C.CDLL(str(binary))
        cls.lib.polaris_mdt_plan.argtypes = [
            C.POINTER(U8), C.c_size_t, C.c_uint64, C.c_uint64, C.POINTER(Plan)]
        cls.lib.polaris_mdt_stage.argtypes = [
            C.POINTER(U8), C.c_size_t, C.c_uint64, C.c_uint64,
            C.POINTER(Blob), C.c_uint32, C.POINTER(U8), C.c_size_t]
        cls.lib.polaris_mdt_metadata.argtypes = [
            C.POINTER(U8), C.c_size_t, C.POINTER(Blob), C.c_uint32,
            C.POINTER(U8), C.c_size_t, C.POINTER(C.c_size_t)]

    def plan(self, data, base=0x8e400000, size=0x7800000):
        source = (U8 * len(data)).from_buffer_copy(data)
        result = Plan()
        status = self.lib.polaris_mdt_plan(source, len(data), base, size, C.byref(result))
        return status, result

    def test_relocation_holes_bss_and_cumulative_auth_lengths(self):
        status, plan = self.plan(fixture())
        self.assertEqual(status, 0)
        self.assertEqual((plan.count, plan.relocatable, plan.boot_address, plan.span),
                         (2, 1, 0x8e400000, 0x3000))
        self.assertEqual((plan.segments[0].destination, plan.segments[1].destination),
                         (0x8e400000, 0x8e402000))
        self.assertEqual((plan.segments[0].code_length, plan.segments[1].code_length),
                         (8, 24))

    def test_nonrelocatable_uses_physical_addresses(self):
        status, plan = self.plan(fixture(False), base=0x1000, size=0x3000)
        self.assertEqual(status, 0)
        self.assertEqual((plan.relocatable, plan.boot_address), (0, 0x1000))
        self.assertLess(self.plan(fixture(False))[0], 0)

    def test_rejects_overlap_truncation_overflow_and_wrong_elf(self):
        bad = bytearray(fixture()); bad[5] = 2
        bad_machine = bytearray(fixture()); struct.pack_into('<H', bad_machine, 18, 183)
        for data in (bytes(bad), bytes(bad_machine), fixture()[:51], fixture()[:-1],
                     fixture(second_address=0x1004), fixture(file_size=9),
                     fixture(second_address=0xfffffff8)):
            with self.subTest(data=data[-12:]):
                self.assertLess(self.plan(data)[0], 0)
        self.assertLess(self.plan(fixture(), base=0xfffffffffffff000)[0], 0)
        self.assertLess(self.plan(fixture(), size=0x2000)[0], 0)

    def test_split_copy_zero_bss_preserve_holes(self):
        data = fixture()
        meta = (U8 * len(data)).from_buffer_copy(data)
        source = (U8 * 4)(1, 2, 3, 4)
        blobs = (Blob * 3)()
        blobs[1] = Blob(source, 4)
        output = (U8 * 0x3000)(*([0xa5] * 0x3000))
        def stage():
            return self.lib.polaris_mdt_stage(meta, len(data), 0x8e400000,
                len(output), blobs, len(blobs), output, len(output))
        self.assertEqual(stage(), 0)
        self.assertEqual(list(output[:8]), [1, 2, 3, 4, 0, 0, 0, 0])
        self.assertEqual(list(output[0x2000:0x2010]), [0] * 16)
        self.assertEqual(output[8], 0xa5)
        self.assertEqual(output[0x2010], 0xa5)
        C.memset(output, 0xa5, len(output))
        blobs[1].size = 3
        self.assertLess(stage(), 0)
        self.assertTrue(all(v == 0xa5 for v in output))

    def test_embedded_segments_and_truncated_embedded_rejection(self):
        data = fixture() + bytes(0x1000 - len(fixture())) + b'ABCD'
        status, _ = self.plan(data)
        self.assertEqual(status, 0)
        meta = (U8 * len(data)).from_buffer_copy(data)
        output = (U8 * 0x3000)()
        self.assertEqual(self.lib.polaris_mdt_stage(
            meta, len(data), 0x8e400000, len(output), None, 0, output, len(output)), 0)
        self.assertEqual(bytes(output[:4]), b'ABCD')
        self.assertLess(self.lib.polaris_mdt_stage(
            meta, len(data) - 1, 0x8e400000, len(output), None, 0, output, len(output)), 0)

    def test_late_bad_source_and_aliased_input_never_partially_write(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 52 + 2 * 32 + 16, 4)
        meta = (U8 * len(data)).from_buffer_copy(data)
        source = (U8 * 4)(1, 2, 3, 4)
        blobs = (Blob * 3)()
        blobs[1] = Blob(source, 4)
        output = (U8 * 0x3000)(*([0xa5] * 0x3000))
        self.assertLess(self.lib.polaris_mdt_stage(
            meta, len(data), 0x8e400000, len(output), blobs, 3, output, len(output)), 0)
        self.assertTrue(all(v == 0xa5 for v in output))
        blobs[2] = Blob(C.cast(output, C.POINTER(U8)), 4)
        self.assertLess(self.lib.polaris_mdt_stage(
            meta, len(data), 0x8e400000, len(output), blobs, 3, output, len(output)), 0)
        self.assertTrue(all(v == 0xa5 for v in output))

    def metadata(self, data, blobs=None, capacity=256):
        source = (U8 * len(data)).from_buffer_copy(data)
        output = (U8 * capacity)(*([0xa5] * capacity))
        written = C.c_size_t(0xbeef)
        status = self.lib.polaris_mdt_metadata(
            source, len(data), blobs, len(blobs) if blobs is not None else 0,
            output, capacity, C.byref(written))
        return status, bytes(output), written.value

    def test_auth_metadata_packed_and_embedded_have_no_padding(self):
        for layout in ('packed', 'embedded'):
            data, expected = metadata_fixture(layout)
            status, output, written = self.metadata(data)
            self.assertEqual(status, 0)
            self.assertEqual(written, len(expected))
            self.assertEqual(output[:written], expected)
            self.assertEqual(output[written:], b'\xa5' * (len(output) - written))

    def test_auth_metadata_split_hash_and_size_query(self):
        data, expected = metadata_fixture('split')
        hashes = (U8 * 8).from_buffer_copy(b'HASHDATA')
        blobs = (Blob * 3)()
        blobs[1] = Blob(hashes, 8)
        status, output, written = self.metadata(data, blobs)
        self.assertEqual((status, output[:written]), (0, expected))
        source = (U8 * len(data)).from_buffer_copy(data)
        size = C.c_size_t()
        self.assertEqual(self.lib.polaris_mdt_metadata(
            source, len(data), blobs, 3, None, 0, C.byref(size)), 0)
        self.assertEqual(size.value, len(expected))

    def test_auth_metadata_rejects_ambiguous_headers_without_writes(self):
        data, _ = metadata_fixture()
        cases = [data[:-1], data[:51]]
        for offset, value in ((52, 1), (56, 4), (68, 52), (76, 0x02000000), (100, 0),
                              (108, 0), (140, 0x02000000)):
            bad = bytearray(data)
            struct.pack_into('<I', bad, offset, value)
            cases.append(bad)
        for bad in cases:
            status, output, written = self.metadata(bad)
            self.assertLess(status, 0)
            self.assertEqual(output, b'\xa5' * len(output))
            self.assertEqual(written, 0xbeef)

    def test_auth_metadata_capacity_and_split_truncation(self):
        data, expected = metadata_fixture()
        status, output, written = self.metadata(data, capacity=len(expected) - 1)
        self.assertLess(status, 0)
        self.assertEqual((output, written), (b'\xa5' * len(output), 0xbeef))
        data, _ = metadata_fixture('split')
        hashes = (U8 * 7)(*range(7))
        blobs = (Blob * 3)()
        blobs[1] = Blob(hashes, 7)
        self.assertLess(self.metadata(data, blobs)[0], 0)

    def test_auth_metadata_rejects_output_or_length_alias(self):
        data, _ = metadata_fixture()
        storage = (U8 * 512)()
        C.memmove(storage, data, len(data))
        original = bytes(storage)
        written = C.c_size_t(0xbeef)
        self.assertLess(self.lib.polaris_mdt_metadata(
            storage, len(data), None, 0, storage, 512, C.byref(written)), 0)
        self.assertEqual((bytes(storage), written.value), (original, 0xbeef))
        source = (U8 * len(data)).from_buffer_copy(data)
        alias = C.cast(storage, C.POINTER(C.c_size_t))
        self.assertLess(self.lib.polaris_mdt_metadata(
            source, len(data), None, 0, storage, 512, alias), 0)
        self.assertEqual(bytes(storage), original)


if __name__ == '__main__':
    unittest.main()
