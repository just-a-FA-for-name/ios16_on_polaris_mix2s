import ctypes as C
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
U32 = C.c_uint32


class Ring(C.Structure):
    _fields_ = [('data', C.POINTER(U32)), ('capacity', U32),
                ('read_index', U32), ('write_index', U32)]


class Channel(C.Structure):
    _fields_ = [('next_sequence', U32), ('quarantined', U32)]


Send = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(U32), U32)
Receive = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(U32), U32, C.POINTER(U32))
Now = C.CFUNCTYPE(C.c_uint64, C.c_void_p)
Pause = C.CFUNCTYPE(None, C.c_void_p, U32)
Fault = C.CFUNCTYPE(C.c_int, C.c_void_p)


class Transport(C.Structure):
    _fields_ = [('context', C.c_void_p), ('send', Send), ('receive', Receive),
                ('now_us', Now), ('pause_us', Pause), ('faulted', Fault)]


class PolarisHFITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'out').mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix='hfi-test-', dir=ROOT / 'out')
        cls.addClassCleanup(cls.temp.cleanup)
        binary = Path(cls.temp.name) / 'hfi.so'
        linking = ['-dynamiclib'] if sys.platform == 'darwin' else ['-shared', '-fPIC']
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        *linking, str(ROOT / 'userland/polaris_hfi.c'),
                        '-o', str(binary)], check=True)
        cls.lib = C.CDLL(str(binary))
        ptr = C.POINTER(U32)
        cls.lib.polaris_hfi_command.argtypes = [U32, U32, ptr, U32, ptr, U32]
        cls.lib.polaris_hfi_push.argtypes = [C.POINTER(Ring), ptr, U32]
        cls.lib.polaris_hfi_pop.argtypes = [C.POINTER(Ring), ptr, U32, ptr]
        cls.lib.polaris_hfi_ack.argtypes = [U32, ptr, U32, ptr, U32, ptr, ptr]
        cls.lib.polaris_hfi_exchange.argtypes = [
            C.POINTER(Channel), C.POINTER(Transport), U32, ptr, U32,
            ptr, U32, ptr, ptr, U32]

    def command(self, ident=1, seq=7, payload=(0x12345678,)):
        source = (U32 * len(payload))(*payload)
        dest = (U32 * (len(payload) + 1))()
        self.assertEqual(self.lib.polaris_hfi_command(
            ident, seq, source, len(payload), dest, len(dest)), 0)
        return dest

    def test_exact_v1_command_and_field_bounds(self):
        self.assertEqual(list(self.command()), [0x00700201, 0x12345678])
        dest = (U32 * 2)(0xaaaaaaaa, 0xbbbbbbbb)
        for ident, seq, words, capacity in ((256, 1, 0, 2), (1, 4096, 0, 2),
                                           (1, 1, 255, 2), (1, 1, 0, 0)):
            self.assertLess(self.lib.polaris_hfi_command(
                ident, seq, None, words, dest, capacity), 0)
            self.assertEqual(list(dest), [0xaaaaaaaa, 0xbbbbbbbb])
        self.command(seq=4095, payload=tuple(range(254)))

    def test_ring_wrap_without_v2_padding(self):
        storage = (U32 * 8)()
        ring = Ring(storage, 8, 6, 6)
        msg = self.command(payload=(11, 22))
        self.assertEqual(self.lib.polaris_hfi_push(C.byref(ring), msg, 3), 0)
        self.assertEqual(ring.write_index, 1)
        self.assertEqual([storage[6], storage[7], storage[0]], list(msg))
        out, count = (U32 * 3)(), U32()
        self.assertEqual(self.lib.polaris_hfi_pop(C.byref(ring), out, 3, C.byref(count)), 0)
        self.assertEqual((list(out), count.value, ring.read_index), (list(msg), 3, 1))
        self.assertEqual(self.lib.polaris_hfi_pop(C.byref(ring), out, 3, C.byref(count)), 1)

    def test_full_and_invalid_ring_do_not_publish_or_overwrite(self):
        storage = (U32 * 4)(1, 2, 3, 4)
        ring = Ring(storage, 4, 0, 3)
        msg = self.command(payload=())
        self.assertEqual(self.lib.polaris_hfi_push(C.byref(ring), msg, 1), 2)
        self.assertEqual((list(storage), ring.write_index), ([1, 2, 3, 4], 3))
        ring.read_index = 4
        self.assertLess(self.lib.polaris_hfi_push(C.byref(ring), msg, 1), 0)

    def test_truncated_corrupt_or_oversized_response_not_consumed(self):
        storage = (U32 * 8)(0x302, 42)
        ring = Ring(storage, 8, 0, 2)
        out, count = (U32 * 8)(), U32()
        self.assertLess(self.lib.polaris_hfi_pop(C.byref(ring), out, 8, C.byref(count)), 0)
        ring.write_index = 3
        self.assertLess(self.lib.polaris_hfi_pop(C.byref(ring), out, 2, C.byref(count)), 0)
        storage[0] = 0
        self.assertLess(self.lib.polaris_hfi_pop(C.byref(ring), out, 8, C.byref(count)), 0)
        self.assertEqual(ring.read_index, 0)

    def test_ack_requires_v1_type_original_id_sequence_and_size(self):
        request = self.command()[0]
        response = (U32 * 4)(0x2047e, request, 0, 0x10010000)
        out, count, error = (U32 * 4)(), U32(), U32()
        def decode():
            return self.lib.polaris_hfi_ack(request, response, 4, out, 4,
                                           C.byref(count), C.byref(error))
        self.assertEqual(decode(), 0)
        self.assertEqual((count.value, out[0]), (1, 0x10010000))
        for wrong in (request ^ 1, request ^ (1 << 20), request ^ (1 << 8)):
            response[1] = wrong
            self.assertEqual(decode(), -3)
        response[1] = request
        response[0] = 0x1047e
        self.assertLess(decode(), 0)
        response[0] = 0x2037e
        self.assertLess(decode(), 0)
        response[0] = 0x2047e
        response[2] = 0xdead
        self.assertEqual(decode(), -4)
        self.assertEqual(error.value, 0xdead)

    def test_ring_randomized_fifo(self):
        rng = random.Random(630)
        storage = (U32 * 64)()
        ring = Ring(storage, 64, 0, 0)
        expected = []
        for n in range(2000):
            if not expected or rng.randrange(2):
                msg = self.command(seq=n % 4096, payload=tuple(range(rng.randrange(8))))
                result = self.lib.polaris_hfi_push(C.byref(ring), msg, len(msg))
                self.assertIn(result, (0, 2))
                if result == 0:
                    expected.append(list(msg))
            else:
                out, count = (U32 * 255)(), U32()
                self.assertEqual(self.lib.polaris_hfi_pop(
                    C.byref(ring), out, 255, C.byref(count)), 0)
                self.assertEqual(list(out)[:count.value], expected.pop(0))

    def exchange_fixture(self, behavior, timeout=200, frozen=False, fault_at=None):
        channel = Channel(4095, 0)
        state = {'time': 0, 'sent': 0, 'reads': 0}
        def send(_, message, words):
            state['sent'] += 1
            state['request'] = message[0]
            return 0
        def receive(_, output, capacity, words):
            state['reads'] += 1
            packet = behavior(state)
            if packet is None:
                return 1
            for i, value in enumerate(packet):
                output[i] = value
            words[0] = len(packet)
            return 0
        def pause(_, delay):
            if not frozen:
                state['time'] += delay
        io = Transport(None, Send(send), Receive(receive),
                       Now(lambda _: state['time']), Pause(pause),
                       Fault(lambda _: fault_at is not None and state['reads'] >= fault_at))
        output, count, error = (U32 * 4)(), U32(), U32()
        status = self.lib.polaris_hfi_exchange(
            C.byref(channel), C.byref(io), 1, None, 0, output, 4,
            C.byref(count), C.byref(error), timeout)
        return status, channel, state, list(output)[:count.value], io

    def test_exchange_skips_stale_ack_and_accepts_matching_reply(self):
        def replies(state):
            echoed = state['request'] ^ (1 << 20) if state['reads'] == 1 else state['request']
            return [0x2047e, echoed, 0, 42]
        status, channel, state, payload, _ = self.exchange_fixture(replies)
        self.assertEqual((status, channel.next_sequence, channel.quarantined), (0, 0, 0))
        self.assertEqual((state['reads'], payload), (2, [42]))

    def test_exchange_timeout_quarantines_and_prevents_resubmit(self):
        status, channel, state, _, io = self.exchange_fixture(lambda _: None)
        self.assertEqual((status, channel.quarantined), (-5, 1))
        out, count, error = (U32 * 4)(), U32(), U32()
        self.assertEqual(self.lib.polaris_hfi_exchange(
            C.byref(channel), C.byref(io), 1, None, 0, out, 4,
            C.byref(count), C.byref(error), 200), -6)
        self.assertEqual(state['sent'], 1)

    def test_exchange_rejects_malformed_reply(self):
        status, channel, _, _, _ = self.exchange_fixture(
            lambda state: [0x1047e, state['request'], 0, 0])
        self.assertEqual((status, channel.quarantined), (-2, 1))

    def test_frozen_clock_cannot_cause_unbounded_wait(self):
        status, channel, state, _, _ = self.exchange_fixture(lambda _: None, frozen=True)
        self.assertEqual((status, channel.quarantined), (-5, 1))
        self.assertLessEqual(state['reads'], 6)

    def test_hardware_fault_stops_before_send_or_while_waiting(self):
        for threshold in (0, 1):
            status, channel, state, _, _ = self.exchange_fixture(
                lambda _: None, fault_at=threshold)
            self.assertEqual((status, channel.quarantined), (-7, 1))
            self.assertEqual(state['sent'], threshold)

    def test_reply_after_deadline_is_not_success(self):
        def late_reply(state):
            state['time'] = 201
            return [0x2047e, state['request'], 0, 42]
        status, channel, _, payload, _ = self.exchange_fixture(late_reply)
        self.assertEqual((status, channel.quarantined, payload), (-5, 1, []))


if __name__ == '__main__':
    unittest.main()
