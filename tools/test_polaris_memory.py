"""Regression: physical RAM capacity is not an absolute physical end address."""
import struct
import unittest
import mkadt


def dram(tree):
    chosen=next(c for c in tree.children if c.name=='chosen')
    props={k:v for k,f,v in chosen.props}
    return struct.unpack('<Q',props['dram-base'])[0],struct.unpack('<Q',props['dram-size'])[0]


class PolarisMemoryTests(unittest.TestCase):
    def test_six_gib_uses_continuously_backed_high_window(self):
        base,size=dram(mkadt.build(polaris=True,ram=6))
        # Independently captured FDT + Linux System RAM endpoints. The old
        # ~2-GiB declaration was backed, but failed to expose this full range.
        self.assertGreaterEqual(size,3*1024**3)
        self.assertEqual(base,0x100000000)
        self.assertLessEqual(base+size,0x1fd4a0000)
        self.assertLessEqual(base+size,0x80000000+6*1024**3)
        self.assertEqual((base|size)&0x3fff,0)

    def test_default_and_eight_gib_remain_conservative(self):
        self.assertEqual(dram(mkadt.build(polaris=True)),dram(mkadt.build(polaris=True,ram=6)))
        base,size=dram(mkadt.build(polaris=True,ram=8))
        self.assertLessEqual(base+size,0x1fcc00000)

    def test_sweet_mapping_not_changed(self):
        self.assertEqual(dram(mkadt.build()),(0xb0000000,0x4d000000))
        self.assertEqual(dram(mkadt.build(highmem=True)),(0x100000000,0xfcc00000))


if __name__=='__main__':unittest.main()
