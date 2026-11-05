import ctypes as C
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
U8, U32 = C.c_uint8, C.c_uint32


class Decoder(C.Structure):
    _fields_ = [(name, U32) for name in (
        'used', 'expected', 'header_size', 'max_acl', 'ibs_enabled', 'quarantined')]
    _fields_ += [('packet', U8 * 4101)]


Packet = C.CFUNCTYPE(C.c_int, C.c_void_p, U8, C.POINTER(U8), U32)
Control = C.CFUNCTYPE(C.c_int, C.c_void_p, U8)


class Sink(C.Structure):
    _fields_ = [('context', C.c_void_p), ('packet', Packet), ('control', Control)]


class PolarisBluetoothH4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'out').mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix='bt-h4-', dir=ROOT / 'out')
        cls.addClassCleanup(cls.temp.cleanup)
        binary = Path(cls.temp.name) / 'h4.so'
        linking = ['-dynamiclib'] if sys.platform == 'darwin' else ['-shared', '-fPIC']
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        *linking, str(ROOT / 'userland/polaris_bt_h4.c'),
                        '-o', str(binary)], check=True)
        cls.lib = C.CDLL(str(binary))
        cls.lib.polaris_bt_h4_init.argtypes = [C.POINTER(Decoder), U32, U32]
        cls.lib.polaris_bt_h4_receive.argtypes = [
            C.POINTER(Decoder), C.POINTER(Sink), C.POINTER(U8), U32, C.POINTER(U32)]
        cls.lib.polaris_bt_h4_command.argtypes = [C.c_uint16, C.POINTER(U8), U32, C.POINTER(U8), U32]

    def setUp(self):
        self.decoder = Decoder()
        self.events, self.controls = [], []
        self.fail_packet = self.fail_control = False

        @Packet
        def packet(context, kind, body, length):
            self.events.append((kind, C.string_at(body, length)))
            return int(self.fail_packet)

        @Control
        def control(context, value):
            self.controls.append(value)
            return int(self.fail_control)

        self.sink = Sink(None, packet, control)
        self.assertEqual(self.lib.polaris_bt_h4_init(C.byref(self.decoder), 1024, 1), 0)

    def feed(self, data):
        source = (U8 * len(data)).from_buffer_copy(data)
        consumed = U32(0xbeef)
        result = self.lib.polaris_bt_h4_receive(
            C.byref(self.decoder), C.byref(self.sink), source, len(data), C.byref(consumed))
        return result, consumed.value

    def test_event_header_and_payload_can_be_split_at_every_byte(self):
        wire = b'\x04\x0e\x04\x01\x03\x0c\x00'
        for byte in wire[:-1]:
            self.assertEqual(self.feed(bytes([byte])), (0, 1))
            self.assertEqual(self.events, [])
        self.assertEqual(self.feed(wire[-1:]), (0, 1))
        self.assertEqual(self.events, [(4, wire[1:])])
        self.assertEqual(self.decoder.used, 0)

    def test_acl_sco_and_zero_length_event_in_one_chunk(self):
        wire = b'\x02\x01\x20\x03\x00abc\x03\x02\x00\x02xy\x04\xff\x00'
        self.assertEqual(self.feed(wire), (0, len(wire)))
        self.assertEqual(self.events, [
            (2, b'\x01\x20\x03\x00abc'), (3, b'\x02\x00\x02xy'), (4, b'\xff\x00')])

    def test_ibs_is_control_only_at_packet_boundaries(self):
        wire = b'\xfd\x04\xff\x03\xfd\xfc\xfe\xfc\xfe'
        self.assertEqual(self.feed(wire), (0, len(wire)))
        self.assertEqual(self.controls, [0xfd, 0xfc, 0xfe])
        self.assertEqual(self.events, [(4, b'\xff\x03\xfd\xfc\xfe')])

    def test_ibs_disabled_and_unknown_packet_types_quarantine(self):
        for byte in (1, 5, 0, 0xfd):
            self.lib.polaris_bt_h4_init(C.byref(self.decoder), 1024, 0)
            result, count = self.feed(bytes([byte]))
            self.assertEqual((result, count), (-2, 1))
            self.assertEqual(self.decoder.quarantined, 1)
            self.assertEqual(self.feed(b'\x04\xff\x00'), (-4, 0))
        self.assertEqual(self.events, [])

    def test_oversized_acl_is_rejected_before_payload_copy(self):
        wire = b'\x02\x00\x00\x01\x04' + b'x' * 20
        self.assertEqual(self.feed(wire), (-2, 5))
        self.assertEqual(self.events, [])
        self.assertEqual(self.decoder.quarantined, 1)

    def test_callback_failures_quarantine_without_retry(self):
        self.fail_packet = True
        self.assertEqual(self.feed(b'\x04\xff\x00'), (-3, 3))
        self.assertEqual(self.feed(b'\x04\xff\x00'), (-4, 0))
        self.assertEqual(len(self.events), 1)
        self.lib.polaris_bt_h4_init(C.byref(self.decoder), 1024, 1)
        self.fail_control = True
        self.assertEqual(self.feed(b'\xfd'), (-3, 1))
        self.assertEqual(self.feed(b'\xfd'), (-4, 0))
        self.assertEqual(self.controls, [0xfd])

    def test_random_fragments_preserve_all_frames(self):
        rng = random.Random(845)
        frames = []
        for _ in range(100):
            payload = bytes(rng.randrange(256) for _ in range(rng.randrange(40)))
            frames.append(b'\x04\xff' + bytes([len(payload)]) + payload)
        wire = b''.join(frames)
        index = 0
        while index < len(wire):
            part = wire[index:index + rng.randrange(1, 30)]
            self.assertEqual(self.feed(part), (0, len(part)))
            index += len(part)
        self.assertEqual(self.events, [(4, frame[1:]) for frame in frames])

    def test_maximum_acl_and_corrupted_decoder_bounds(self):
        self.lib.polaris_bt_h4_init(C.byref(self.decoder), 4096, 1)
        wire = b'\x02\x01\x00\x00\x10' + bytes(4096)
        self.assertEqual(self.feed(wire), (0, len(wire)))
        self.assertEqual(self.events, [(2, wire[1:])])
        self.decoder.used = 5000
        self.assertEqual(self.feed(b'x'), (-1, 0))
        self.assertEqual(self.lib.polaris_bt_h4_init(C.byref(self.decoder), 4097, 1), -1)

    def test_exact_command_and_rejection_without_writes(self):
        output = (U8 * 260)(*([0xa5] * 260))
        self.assertEqual(self.lib.polaris_bt_h4_command(0x0c03, None, 0, output, 260), 0)
        self.assertEqual(bytes(output[:4]), b'\x01\x03\x0c\x00')
        before = bytes(output)
        for opcode, length, capacity in ((0, 0, 260), (1, 256, 260), (1, 0, 3), (1, 1, 260)):
            self.assertEqual(self.lib.polaris_bt_h4_command(opcode, None, length, output, capacity), -1)
            self.assertEqual(bytes(output), before)

    def test_command_parameters_may_overlap_output(self):
        output = (U8 * 260)()
        output[:3] = b'abc'
        self.assertEqual(self.lib.polaris_bt_h4_command(0xfc01, output, 3, output, 260), 0)
        self.assertEqual(bytes(output[:7]), b'\x01\x01\xfc\x03abc')

    def test_aliasing_and_invalid_chunk_sizes_do_not_mutate_state(self):
        before = bytes(self.decoder)
        consumed = U32(99)
        self.assertEqual(self.lib.polaris_bt_h4_receive(
            C.byref(self.decoder), C.byref(self.sink), self.decoder.packet, 1, C.byref(consumed)), -1)
        self.assertEqual((bytes(self.decoder), consumed.value), (before, 0))
        source = (U8 * 1)(4)
        self.assertEqual(self.lib.polaris_bt_h4_receive(
            C.byref(self.decoder), C.byref(self.sink), source, 16385, C.byref(consumed)), -1)
        self.assertEqual(bytes(self.decoder), before)
        alias = C.cast(C.byref(self.decoder), C.POINTER(U32))
        self.assertEqual(self.lib.polaris_bt_h4_receive(
            C.byref(self.decoder), C.byref(self.sink), source, 1, alias), -1)
        self.assertEqual(bytes(self.decoder), before)

    def test_standalone_address_and_undefined_sanitized_fuzz(self):
        binary = Path(self.temp.name) / 'fuzz'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-I', str(ROOT / 'userland'),
                        str(ROOT / 'tools/polaris_bt_h4_fuzz.c'),
                        str(ROOT / 'userland/polaris_bt_h4.c'), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True, check=True, timeout=60)
        self.assertIn('50000 H4 stream and command trials passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
