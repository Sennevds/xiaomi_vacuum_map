class NodeJSLikeBuffer(object):

    def __init__(self, size):
        self._buf = bytearray(size)

    @staticmethod
    def _last_byte(value):
        return value % 256

    def write_8(self, value, offset):
        self._buf[offset] = self._last_byte(value)

    def write_32(self, value, offset):
        self._buf[offset] = value % 256
        self._buf[offset + 1] = self._last_byte(value >> 8)
        self._buf[offset + 2] = self._last_byte(value >> 16)
        self._buf[offset + 3] = self._last_byte(value >> 24)

    def to_hex(self):
        return ''.join('{:02x}'.format(x) for x in self._buf)
    def buf(self):
        return self._buf