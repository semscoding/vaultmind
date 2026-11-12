"""
Compiler script for VaultMind's native C cryptographic enclave (libvaultcrypto.dylib).
"""

import os
import subprocess
import sys


def build_native_library() -> str:
    native_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(native_dir, "vaultcrypto.c")
    out_ext = ".dylib" if sys.platform == "darwin" else ".so"
    out_path = os.path.join(native_dir, f"libvaultcrypto{out_ext}")

    cmd = [
        "clang",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fPIC",
        "-shared",
        src_path,
        "-o",
        out_path,
    ]
    subprocess.run(cmd, check=True)
    return out_path


if __name__ == "__main__":
    built = build_native_library()
    print(f"Successfully compiled native C cryptographic core: {built}")
