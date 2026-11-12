"""
Zeroize & Native C Memory Sanitization Utility.
Wraps libvaultcrypto's C11 memset_s() + volatile memory barrier to guarantee
in-place zeroization of mutable C buffers without compiler dead-store elimination.
"""

import ctypes
import os
import sys
from backend.native.build import build_native_library


def load_native_lib() -> ctypes.CDLL:
    native_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "native"))
    ext = ".dylib" if sys.platform == "darwin" else ".so"
    lib_path = os.path.join(native_dir, f"libvaultcrypto{ext}")
    if not os.path.exists(lib_path):
        lib_path = build_native_library()

    lib = ctypes.CDLL(lib_path)
    lib.vault_secure_wipe.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    lib.vault_secure_wipe.restype = None
    return lib


_LIB = load_native_lib()


def secure_zero(buffer_obj) -> None:
    """
    Overwrite a mutable ctypes array or bytearray in-place using native C memset_s().
    Explicitly rejects immutable Python str/bytes to prevent false security assumptions.
    """
    if isinstance(buffer_obj, (str, bytes, int)):
        raise TypeError(
            f"Cannot zeroize immutable Python type '{type(buffer_obj).__name__}'. "
            "Keep secrets in C stack frames or mutable ctypes buffers."
        )

    if isinstance(buffer_obj, bytearray):
        if len(buffer_obj) == 0:
            return
        c_buf = (ctypes.c_uint8 * len(buffer_obj)).from_buffer(buffer_obj)
        _LIB.vault_secure_wipe(ctypes.addressof(c_buf), len(buffer_obj))
        return

    if isinstance(buffer_obj, ctypes.Array):
        size = ctypes.sizeof(buffer_obj)
        if size > 0:
            _LIB.vault_secure_wipe(ctypes.addressof(buffer_obj), size)
        return

    raise TypeError(f"Unsupported buffer type for secure_zero: {type(buffer_obj).__name__}")


class NativeBufferGuard:
    """
    Context manager allocating a fixed-size mutable ctypes uint8 buffer
    that is guaranteed to be wiped via C memset_s() on scope exit.
    """

    def __init__(self, size: int):
        if size <= 0:
            raise ValueError("Buffer size must be positive.")
        self.size = size
        self._buf = (ctypes.c_uint8 * size)()

    @property
    def buffer(self):
        return self._buf

    def __enter__(self):
        return self._buf

    def __exit__(self, exc_type, exc_val, exc_tb):
        secure_zero(self._buf)
        return False
