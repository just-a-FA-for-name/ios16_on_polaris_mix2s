import ctypes as C
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_polaris_mdt import Plan, Segment

ROOT = Path(__file__).resolve().parents[1]
U32 = C.c_uint32
Read = C.CFUNCTYPE(C.c_int, C.c_void_p, U32, C.POINTER(U32))
Write = C.CFUNCTYPE(C.c_int, C.c_void_p, U32, U32)
Barrier = C.CFUNCTYPE(C.c_int, C.c_void_p)
Publish = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(Segment))
Now = C.CFUNCTYPE(C.c_uint64, C.c_void_p)
Pause = C.CFUNCTYPE(None, C.c_void_p, U32)


class IO(C.Structure):
    _fields_ = [('context', C.c_void_p), ('read', Read), ('write', Write),
                ('barrier', Barrier), ('publish_segment', Publish),
                ('now_us', Now), ('pause_us', Pause)]


class Session(C.Structure):
    _fields_ = [('state', U32), ('next_segment', U32), ('firmware_error', U32),
                ('plan', C.POINTER(Plan)), ('io', C.POINTER(IO))]


class PolarisMSSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'out').mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix='mss-test-', dir=ROOT / 'out')
        cls.addClassCleanup(cls.temp.cleanup)
        binary = Path(cls.temp.name) / 'mss.so'
        linking = ['-dynamiclib'] if sys.platform == 'darwin' else ['-shared', '-fPIC']
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', *linking,
                        str(ROOT / 'userland/polaris_mss.c'), '-o', str(binary)], check=True)
        cls.lib = C.CDLL(str(binary))
        cls.lib.polaris_mss_metadata.argtypes = [
            C.POINTER(Session), C.POINTER(IO), C.POINTER(Plan), U32, U32]
        cls.lib.polaris_mss_segment.argtypes = [C.POINTER(Session), U32]
        cls.lib.polaris_mss_finish.argtypes = [C.POINTER(Session), U32]

    def setUp(self):
        self.plan = Plan(count=2, relocatable=1, boot_address=0x8e400000, span=0x3000)
        self.plan.segments[0] = Segment(2, 0x1000, 4, 8, 0x8e400000, 8)
        self.plan.segments[1] = Segment(3, 0x2000, 4, 16, 0x8e402000, 24)
        self.regs = {4: 1, 12: 1, 24: 0}
        self.events = []
        self.clock = 0
        self.auto_reply = True
        self.failed_publish = False
        self.freeze_clock = False
        def read(_, offset, output):
            self.events.append(('read', offset))
            output[0] = self.regs.get(offset, 0)
            return 0
        def write(_, offset, value):
            self.events.append(('write', offset, value))
            self.regs[offset] = value
            if self.auto_reply:
                if offset == 8 and value == 1:
                    self.regs[12] = 3
                if offset == 24 and value == 24:
                    self.regs[12] = 4
            return 0
        def barrier(_):
            self.events.append(('barrier',))
            return 0
        def publish(_, segment):
            self.events.append(('publish', segment.contents.index))
            return -1 if self.failed_publish else 0
        def pause(_, delay):
            if not self.freeze_clock:
                self.clock += delay
        self.io = IO(None, Read(read), Write(write), Barrier(barrier),
                     Publish(publish), Now(lambda _: self.clock), Pause(pause))
        self.session = Session()

    def metadata(self, address=0x96a00000, timeout=200):
        return self.lib.polaris_mss_metadata(C.byref(self.session), C.byref(self.io),
                                           C.byref(self.plan), address, timeout)

    def segment(self, index):
        return self.lib.polaris_mss_segment(C.byref(self.session), index)

    def finish(self):
        return self.lib.polaris_mss_finish(C.byref(self.session), 200)

    def test_real_rmb_sequence_and_cumulative_lengths(self):
        self.assertEqual(self.metadata(), 0)
        self.assertEqual(self.segment(0), 0)
        self.assertEqual(self.segment(1), 0)
        self.assertEqual(self.finish(), 0)
        self.assertEqual(self.session.state, 3)
        writes = [event for event in self.events if event[0] == 'write']
        self.assertEqual(writes, [
            ('write', 0x18, 0), ('write', 0x10, 0x96a00000), ('write', 8, 1),
            ('write', 0x14, 0x8e400000), ('write', 8, 2),
            ('write', 0x18, 8), ('write', 0x18, 24)])
        first = self.events.index(('publish', 2))
        self.assertEqual(self.events[first + 1], ('barrier',))
        self.assertGreater(self.events.index(('write', 0x18, 8)), first)

    def test_invalid_metadata_alignment_or_plan_has_no_io(self):
        self.assertLess(self.metadata(address=0x96a00001), 0)
        self.assertEqual(self.events, [])
        self.plan.segments[1].code_length = 0
        self.assertLess(self.metadata(), 0)
        self.assertEqual(self.events, [])

    def test_not_ready_or_stale_mba_never_gets_metadata_command(self):
        for pbl, mba in ((0, 1), (2, 1), (1, 3), (1, 4), (1, 0xffffffff)):
            self.session = Session()
            self.events = []
            self.regs.update({4: pbl, 12: mba})
            self.assertLess(self.metadata(), 0)
            self.assertFalse(any(event[0] == 'write' for event in self.events))

    def test_timeout_quarantines_even_with_frozen_clock(self):
        self.auto_reply = False
        self.freeze_clock = True
        self.assertEqual(self.metadata(), -3)
        self.assertEqual(self.session.state, 4)
        self.assertLess(len(self.events), 20)
        before = len(self.events)
        self.assertLess(self.segment(0), 0)
        self.assertEqual(len(self.events), before)

    def test_no_out_of_order_or_early_authentication(self):
        self.assertEqual(self.metadata(), 0)
        before = len(self.events)
        self.assertLess(self.segment(1), 0)
        self.assertLess(self.finish(), 0)
        self.assertEqual(len(self.events), before)
        self.assertEqual(self.segment(0), 0)
        before = len(self.events)
        self.assertLess(self.segment(0), 0)
        self.assertEqual(len(self.events), before)

    def test_failed_copy_never_notifies_firmware(self):
        self.assertEqual(self.metadata(), 0)
        self.events = []
        self.failed_publish = True
        self.assertEqual(self.segment(0), -2)
        self.assertEqual(self.session.state, 4)
        self.assertFalse(any(event[0] == 'write' for event in self.events))

    def test_negative_auth_status_preserved_and_never_accepted(self):
        self.assertEqual(self.metadata(), 0)
        self.assertEqual(self.segment(0), 0)
        self.assertEqual(self.segment(1), 0)
        self.regs[12] = 0xfffffff7
        self.assertEqual(self.finish(), -4)
        self.assertEqual(self.session.firmware_error, 0xfffffff7)
        self.assertEqual(self.session.state, 4)


if __name__ == '__main__':
    unittest.main()
