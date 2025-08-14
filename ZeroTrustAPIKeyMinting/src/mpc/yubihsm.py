"""
yubihsm.py — Local wrapper for retrieving an MPC share from YubiKey-protected storage.

Purpose
-------
Encapsulates the retrieval of a single Shamir MPC share stored on disk (or in a mounted
secure device) in JSON format. In this PoC, the `path` attribute simply points to a
JSON file containing {"x": int, "y": int}. In production, this could instead be a
secure mount from a YubiKey PIV applet, encrypted filesystem, or TEE-attached storage.

Operational Guidance
--------------------
- Path format: expects a valid UTF-8 JSON file with keys "x" and "y", both integers.
- Custody: each share should be stored on a distinct hardware token or HSM-backed
  storage volume, ideally with independent custodians.
- Access control: protect file permissions so only the intended process/user can read.
- This class is designed for synchronous, read-only retrieval; no mutation or share
  splitting occurs here.

Production Considerations
-------------------------
- Replace filesystem open() calls with PKCS#11 or hardware-specific retrieval logic.
- Add signature/MAC verification of the share payload to detect tampering.
- Zeroize share values in memory immediately after use.
- Consider loading into volatile memory only (tmpfs/ramfs) when possible.

Example
-------
>>> dev = YubiShareDevice("/secure_mount/share_1.json")
>>> x, y = dev.get_share()
>>> print(f"Share index {x} with value {y}")
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Tuple


@dataclass
class YubiShareDevice:
    """
    Represents a single MPC share stored on a YubiKey-secured or otherwise
    protected device, retrievable via a JSON file path.

    Attributes:
        path (str): Absolute or relative path to the share JSON file.
                    Example: "/mnt/yubi/share_1.json"
    """
    path: str

    def get_share(self) -> Tuple[int, int]:
        """
        Load and return the Shamir share (x, y) from the JSON file.

        Returns:
            tuple[int, int]: The x-coordinate (share index) and y-coordinate (share value).

        Raises:
            FileNotFoundError: if the file does not exist at `path`.
            json.JSONDecodeError: if file content is not valid JSON.
            KeyError: if required keys ("x", "y") are missing.
            ValueError: if x or y are not integers.
        """
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"Share file not found: {self.path}")

        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)

        try:
            x, y = int(data["x"]), int(data["y"])
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"Invalid share file format at {self.path}: {e}")

        return x, y
