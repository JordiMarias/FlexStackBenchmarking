#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
"""
Certificate chain generator for FlexStack benchmarks.

Generates a minimal ECDSA-P256 certificate chain (Root CA → AA → AT1, AT2)
stored under ../certs/ for use by the secured benchmarks in both Python and Rust.
"""

import os
import sys
import time

from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.certificate import OwnCertificate

# ITS epoch: 2004-01-01T00:00:00 UTC
ITS_EPOCH = 1072915200

PSID_CAM = 36
PSID_DENM = 37
PSID_VAM = 638

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certs")


def current_its_time() -> int:
    return int(time.time()) - ITS_EPOCH


def main():
    os.makedirs(CERT_DIR, exist_ok=True)
    backend = PythonECDSABackend()

    # ── 1. Root CA (self-signed) ────────────────────────────────────────────
    root_ca = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate={
            "id": ("name", "benchmark-root-ca"),
            "cracaId": b"\x00\x00\x00",
            "crlSeries": 0,
            "validityPeriod": {
                "start": current_its_time(),
                "duration": ("years", 10),
            },
            "certIssuePermissions": [
                {
                    "subjectPermissions": ("all", None),
                    "minChainLength": 2,
                    "chainLengthRange": 0,
                    "eeType": (b"\x00", 1),
                }
            ],
            "verifyKeyIndicator": (
                "verificationKey",
                ("ecdsaNistP256", ("fill", None)),
            ),
        },
        issuer=None,
    )

    # ── 2. Authorization Authority (AA) ─────────────────────────────────────
    aa = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate={
            "id": ("name", "benchmark-aa"),
            "cracaId": b"\x00\x00\x00",
            "crlSeries": 0,
            "validityPeriod": {
                "start": current_its_time(),
                "duration": ("years", 10),
            },
            "certIssuePermissions": [
                {
                    "subjectPermissions": (
                        "explicit",
                        [
                            {
                                "psid": PSID_CAM,
                                "sspRange": ("all", None),
                            },
                            {
                                "psid": PSID_DENM,
                                "sspRange": ("all", None),
                            },
                            {
                                "psid": PSID_VAM,
                                "sspRange": ("all", None),
                            },
                        ],
                    ),
                    "minChainLength": 0,
                    "chainLengthRange": 0,
                    "eeType": (b"\x00", 1),
                }
            ],
            "verifyKeyIndicator": (
                "verificationKey",
                ("ecdsaNistP256", ("fill", None)),
            ),
        },
        issuer=root_ca,
    )

    # ── 3-4. Authorization Tickets (AT1, AT2) ──────────────────────────────
    ats = []
    for idx in range(1, 3):
        at = OwnCertificate.initialize_certificate(
            backend=backend,
            to_be_signed_certificate={
                "id": ("none", None),
                "cracaId": b"\x00\x00\x00",
                "crlSeries": 0,
                "validityPeriod": {
                    "start": current_its_time(),
                    "duration": ("years", 10),
                },
                "appPermissions": [
                    {"psid": PSID_CAM},
                    {"psid": PSID_DENM},
                    {"psid": PSID_VAM},
                ],
                "verifyKeyIndicator": (
                    "verificationKey",
                    ("ecdsaNistP256", ("fill", None)),
                ),
            },
            issuer=aa,
        )
        ats.append(at)

    # ── Persist to disk ─────────────────────────────────────────────────────
    def save(name, cert, backend_ref):
        cert_path = os.path.join(CERT_DIR, f"{name}.cert")
        key_path = os.path.join(CERT_DIR, f"{name}.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.encode())
        with open(key_path, "wb") as f:
            f.write(backend_ref.export_signing_key(cert.key_id))
        print(f"  {cert_path}")
        print(f"  {key_path}")

    print("Generated certificate chain:")
    save("root_ca", root_ca, backend)
    save("aa", aa, backend)
    for i, at in enumerate(ats, start=1):
        save(f"at{i}", at, backend)

    print(f"\nAll certificates saved to {CERT_DIR}/")
    print("Use these with both Python and Rust benchmarks (--security on).")


if __name__ == "__main__":
    main()
