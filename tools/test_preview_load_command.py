import hashlib
import struct
import unittest
from add_preview_load_command import transform, directories, validate_hashes, LIBRARY


def fixture(padding_byte=False):
    header=struct.pack('<8I',0xfeedfacf,0x0100000c,0,2,2,168,4,0)
    segment=struct.pack('<II16sQQQQIIII',0x19,152,b'__TEXT',0x100000000,8192,0,8192,7,5,1,0)
    section=struct.pack('<16s16sQQIIIIIIII',b'__text',b'__TEXT',0x100001000,4096,
        4096,2,0,0,0x80000400,0,0,0)
    cdsize=112
    signature_size=20+cdsize
    command=struct.pack('<4I',0x1d,16,8192,signature_size)
    data=bytearray((header+segment+section+command).ljust(8192,b'\0'))
    data[4096:8192]=bytes((i%251 for i in range(4096)))
    if padding_byte:data[210]=0x55
    directory=struct.pack('>9I4BI',0xfade0c02,cdsize,0x20100,0,48,44,0,2,8192,32,2,0,12,0)+b'lab\0'
    directory+=hashlib.sha256(data[:4096]).digest()+hashlib.sha256(data[4096:]).digest()
    return bytes(data)+struct.pack('>5I',0xfade0cc0,signature_size,1,0,20)+directory


class PreviewLoadCommandTests(unittest.TestCase):
    def test_adds_library_preserves_all_executable_bytes_and_rehashes(self):
        original=fixture()
        result,report=transform(original)
        self.assertEqual(len(result),len(original))
        self.assertEqual(result[4096:8192],original[4096:8192])
        self.assertIn(LIBRARY,result[:4096])
        self.assertNotEqual(result[-64:],original[-64:])
        self.assertTrue(report['executable_sections_unchanged'])
        validate_hashes(result,directories(original)[3])

    def test_rejects_signed_page_corruption(self):
        data=bytearray(fixture());data[5000]^=1
        with self.assertRaisesRegex(ValueError,'does not match'):transform(bytes(data))

    def test_rejects_used_header_padding_even_with_valid_page_hashes(self):
        with self.assertRaisesRegex(ValueError,'unused header padding'):transform(fixture(True))

    def test_rejects_duplicate_load_without_mutating_input(self):
        patched,_=transform(fixture())
        with self.assertRaisesRegex(ValueError,'already present'):transform(patched)


if __name__=='__main__':unittest.main()
