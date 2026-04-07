#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
"""
FlexStack Benchmark — Python (CPython / PyPy)

Benchmark harness for v2xflexstack that measures:
  B1  Full-stack TX throughput (loopback)
  B2  Concurrent TX/RX throughput (loopback)
  B3  ASN.1 codec encode/decode throughput (in-memory)

Usage:
  sudo python3 benchmark.py --mode tx --security off --duration 60 --warmup 5
  sudo pypy3   benchmark.py --mode tx --security off --duration 60 --warmup 15

All modes produce one CSV row per run appended to --output.
"""

import argparse
import csv
import os
import random
import sys
import time
import threading

import numpy as np

# ── FlexStack imports ───────────────────────────────────────────────────────
from flexstack.linklayer.raw_link_layer import RawLinkLayer
from flexstack.geonet.router import Router as GNRouter
from flexstack.geonet.mib import MIB
from flexstack.geonet.gn_address import GNAddress, M, ST, MID
from flexstack.btp.router import Router as BTPRouter

# Security imports
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.sign_service import SignService
from flexstack.security.verify_service import VerifyService

# Facilities
from flexstack.facilities.ca_basic_service.ca_basic_service import (
    CooperativeAwarenessBasicService,
)
from flexstack.facilities.ca_basic_service.cam_transmission_management import (
    VehicleData,
)
from flexstack.utils.static_location_service import ThreadStaticLocationService

# LDM
from flexstack.facilities.local_dynamic_map.factory import LDMFactory
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    AccessPermission,
    Circle,
    Filter,
    FilterStatement,
    GeometricArea,
    Location,
    OrderTupleValue,
    OrderingDirection,
    ComparisonOperators,
    SubscribeDataobjectsReq,
    RegisterDataConsumerReq,
    RequestDataObjectsResp,
    TimestampIts,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import CAM

# ── Constants ───────────────────────────────────────────────────────────────
POSITION_LAT = 41.386931
POSITION_LON = 2.112104
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certs")

CSV_HEADER = [
    "run_id",
    "implementation",
    "platform",
    "security",
    "benchmark",
    "duration_s",
    "total_cams",
    "throughput_cams_s",
    "latency_mean_us",
    "latency_std_us",
    "latency_p50_us",
    "latency_p95_us",
    "latency_p99_us",
    "latency_min_us",
    "latency_max_us",
    "sign_latency_mean_us",
]


def generate_random_mac() -> bytes:
    """Generate a locally-administered unicast MAC address."""
    mac = bytearray(random.getrandbits(8) for _ in range(6))
    mac[0] = (mac[0] & 0xFC) | 0x02  # locally administered, unicast
    return bytes(mac)


# ── Security Setup ──────────────────────────────────────────────────────────
def setup_security(at_index: int = 1):
    """
    Load the certificate chain from ../certs/ and return
    (sign_service, verify_service, mib_security_flag).

    Certificates must be generated first with generate_certs.py.
    """
    backend = PythonECDSABackend()

    # Root CA
    with open(os.path.join(CERT_DIR, "root_ca.cert"), "rb") as f:
        root_ca = Certificate().decode(f.read(), issuer=None)

    # Authorization Authority
    with open(os.path.join(CERT_DIR, "aa.cert"), "rb") as f:
        aa = Certificate().decode(f.read(), issuer=root_ca)

    # Own AT with private key
    with open(os.path.join(CERT_DIR, f"at{at_index}.pem"), "rb") as f:
        key_id = backend.import_signing_key(f.read())
    with open(os.path.join(CERT_DIR, f"at{at_index}.cert"), "rb") as f:
        base = Certificate().decode(f.read(), issuer=aa)
    own_at = OwnCertificate(certificate=base.certificate, issuer=aa, key_id=key_id)

    # Peer AT (for verify)
    peer_index = 2 if at_index == 1 else 1
    with open(os.path.join(CERT_DIR, f"at{peer_index}.cert"), "rb") as f:
        peer_at = Certificate().decode(f.read(), issuer=aa)

    cert_library = CertificateLibrary(
        ecdsa_backend=backend,
        root_certificates=[root_ca],
        aa_certificates=[aa],
        at_certificates=[own_at, peer_at],
    )
    cert_library.add_own_certificate(own_at)

    sign_service = SignService(backend=backend, certificate_library=cert_library)
    verify_service = VerifyService(
        backend=backend,
        certificate_library=cert_library,
        sign_service=sign_service,
    )

    return sign_service, verify_service


# ── Stack Builder ───────────────────────────────────────────────────────────
def build_stack(security_on: bool, interface: str = "lo"):
    """
    Build the full FlexStack: LinkLayer → GN → BTP → LDM → CA Service.
    Returns (ca_basic_service, link_layer, location_service, station_id,
             rx_counter, rx_latencies_list).
    """
    mac = generate_random_mac()
    station_id = random.randint(1, 2147483647)

    # Location service (static, 1s updates)
    location_service = ThreadStaticLocationService(
        period=1000,
        latitude=POSITION_LAT,
        longitude=POSITION_LON,
    )

    # MIB + GN Router
    gn_addr = GNAddress(m=M.GN_MULTICAST, st=ST.PASSENGER_CAR, mid=MID(mac))

    if security_on:
        sign_service, verify_service = setup_security(at_index=1)
        try:
            from flexstack.geonet.mib import GnSecurity
            mib = MIB(itsGnLocalGnAddr=gn_addr, itsGnSecurity=GnSecurity.ENABLED)
        except ImportError:
            mib = MIB(itsGnLocalGnAddr=gn_addr)
        gn_router = GNRouter(
            mib=mib,
            sign_service=sign_service,
            verify_service=verify_service,
        )
    else:
        mib = MIB(itsGnLocalGnAddr=gn_addr)
        gn_router = GNRouter(mib=mib, sign_service=None)

    location_service.add_callback(gn_router.refresh_ego_position_vector)

    # BTP Router
    btp_router = BTPRouter(gn_router)
    gn_router.register_indication_callback(btp_router.btp_data_indication)

    # LDM
    ldm_location = Location.initializer(
        latitude=int(POSITION_LAT * 10**7),
        longitude=int(POSITION_LON * 10**7),
    )
    ldm_area = GeometricArea(
        circle=Circle(radius=5000), rectangle=None, ellipse=None
    )
    ldm = LDMFactory().create_ldm(
        ldm_location,
        ldm_maintenance_type="Reactive",
        ldm_service_type="Reactive",
        ldm_database_type="Dictionary",
    )
    location_service.add_callback(ldm_location.location_service_callback)

    # RX counter (thread-safe)
    rx_counter = {"count": 0, "latencies": []}
    rx_lock = threading.Lock()

    def ldm_rx_callback(data: RequestDataObjectsResp):
        t_rx = time.monotonic_ns()
        with rx_lock:
            rx_counter["count"] += 1

    # Subscribe to LDM for incoming CAMs (from other stations)
    ldm.if_ldm_4.register_data_consumer(
        RegisterDataConsumerReq(
            application_id=CAM,
            access_permisions=(AccessPermission.CAM,),
            area_of_interest=ldm_area,
        )
    )
    ldm.if_ldm_4.subscribe_data_consumer(
        SubscribeDataobjectsReq(
            application_id=CAM,
            data_object_type=(CAM,),
            priority=1,
            filter=Filter(
                filter_statement_1=FilterStatement(
                    "header.stationId",
                    ComparisonOperators.NOT_EQUAL,
                    station_id,
                )
            ),
            notify_time=TimestampIts(0),
            multiplicity=1,
            order=(
                OrderTupleValue(
                    attribute="cam.generationDeltaTime",
                    ordering_direction=OrderingDirection.ASCENDING,
                ),
            ),
        ),
        ldm_rx_callback,
    )

    # CA Basic Service
    vehicle_data = VehicleData(
        station_id=station_id,
        station_type=5,
        drive_direction="forward",
        vehicle_length={
            "vehicleLengthValue": 1023,
            "vehicleLengthConfidenceIndication": "unavailable",
        },
        vehicle_width=62,
    )
    ca_basic_service = CooperativeAwarenessBasicService(
        btp_router=btp_router,
        vehicle_data=vehicle_data,
        ldm=ldm,
    )
    location_service.add_callback(
        ca_basic_service.cam_transmission_management.location_service_callback
    )

    # Link Layer (loopback)
    btp_router.freeze_callbacks()
    link_layer = RawLinkLayer(
        interface,
        mac,
        receive_callback=gn_router.gn_data_indicate,
    )
    gn_router.link_layer = link_layer

    return (
        ca_basic_service,
        link_layer,
        location_service,
        gn_router,
        btp_router,
        station_id,
        rx_counter,
    )


# ── Teardown ────────────────────────────────────────────────────────────────
def teardown_stack(ca_svc, link_layer, location_service):
    """Gracefully stop all stack components."""
    try:
        ca_svc.stop()
    except Exception:
        pass
    try:
        location_service.stop_event.set()
        location_service.location_service_thread.join(timeout=3)
    except Exception:
        pass
    try:
        link_layer.sock.close()
    except Exception:
        pass


# ── CAM template helper ─────────────────────────────────────────────────────
def _make_cam_value(station_id):
    """Build a CAM value dict for encoding/sending."""
    return {
        "header": {"protocolVersion": 2, "messageId": 2, "stationId": station_id},
        "cam": {
            "generationDeltaTime": 1000,
            "camParameters": {
                "basicContainer": {
                    "stationType": 5,
                    "referencePosition": {
                        "latitude": 415520000, "longitude": 21340000,
                        "positionConfidenceEllipse": {
                            "semiMajorAxisLength": 4095,
                            "semiMinorAxisLength": 4095,
                            "semiMajorAxisOrientation": 3601,
                        },
                        "altitude": {"altitudeValue": 12000, "altitudeConfidence": "unavailable"},
                    },
                },
                "highFrequencyContainer": (
                    "basicVehicleContainerHighFrequency",
                    {
                        "heading": {"headingValue": 900, "headingConfidence": 127},
                        "speed": {"speedValue": 0, "speedConfidence": 127},
                        "driveDirection": "unavailable",
                        "vehicleLength": {"vehicleLengthValue": 1023, "vehicleLengthConfidenceIndication": "unavailable"},
                        "vehicleWidth": 62,
                        "longitudinalAcceleration": {"value": 161, "confidence": 102},
                        "curvature": {"curvatureValue": 1023, "curvatureConfidence": "unavailable"},
                        "curvatureCalculationMode": "unavailable",
                        "yawRate": {"yawRateValue": 32767, "yawRateConfidence": "unavailable"},
                    },
                ),
            },
        },
    }


# ── Benchmark: TX Throughput ────────────────────────────────────────────────
def bench_tx(args):
    """
    B1: Full-stack TX throughput.
    Sends encoded CAMs directly via BTP → GeoNet → loopback at max rate.
    Each btp_data_request() call is synchronous to the raw socket sendto(),
    so the count reflects actual packets on the wire.
    """
    from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder
    from flexstack.geonet.service_access_point import (
        PacketTransportType, HeaderType, TopoBroadcastHST,
        CommunicationProfile, TrafficClass, CommonNH,
    )
    from flexstack.btp.service_access_point import BTPDataRequest
    from flexstack.security.security_profiles import SecurityProfile

    security_on = args.security == "on"

    (
        ca_svc,
        link_layer,
        loc_svc,
        gn_router,
        btp_router,
        station_id,
        rx_counter,
    ) = build_stack(security_on=security_on, interface=args.interface)

    # Don't start the CA service timer — we send directly via BTP
    coder = CAMCoder()
    cam_value = _make_cam_value(station_id)
    encoded_cam = coder.encode(cam_value)

    def make_btp_request(data):
        return BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            source_port=0,
            destination_port=2001,
            destination_port_info=0,
            gn_packet_transport_type=PacketTransportType(
                header_type=HeaderType.TSB,
                header_subtype=TopoBroadcastHST.SINGLE_HOP,
            ),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(scf=False, channel_offload=False, tc_id=0),
            security_profile=(
                SecurityProfile.COOPERATIVE_AWARENESS_MESSAGE
                if security_on
                else SecurityProfile.NO_SECURITY
            ),
            its_aid=36,
            security_permissions=b"",
            gn_max_hop_limit=1,
            length=len(data),
            data=data,
        )

    # Warm-up
    print(f"  Warm-up phase ({args.warmup}s)...")
    warmup_end = time.monotonic_ns() + args.warmup * 10**9
    while time.monotonic_ns() < warmup_end:
        btp_router.btp_data_request(make_btp_request(encoded_cam))

    # Measurement — each call is synchronous to wire
    print(f"  Measurement phase ({args.duration}s)...")
    latencies = []
    t_start = time.monotonic_ns()
    deadline = t_start + args.duration * 10**9
    count = 0

    while time.monotonic_ns() < deadline:
        t0 = time.monotonic_ns()
        btp_router.btp_data_request(make_btp_request(encoded_cam))
        t1 = time.monotonic_ns()
        latencies.append((t1 - t0) / 1000)  # μs
        count += 1

    t_end = time.monotonic_ns()
    elapsed = (t_end - t_start) / 1e9
    throughput = count / elapsed

    # Cleanup
    teardown_stack(ca_svc, link_layer, loc_svc)

    return compute_stats(args, "tx", count, elapsed, throughput, latencies, [])


# ── Benchmark: Concurrent TX/RX ────────────────────────────────────────────
def bench_concurrent(args):
    """
    B2: Concurrent TX/RX throughput.
    Uses two separate stacks (different GN addresses) so the GN router's
    Duplicate Address Detection doesn't drop loopback packets.
    TX sends via BTP (synchronous to wire), RX receives on a separate stack.
    """
    from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder
    from flexstack.geonet.service_access_point import (
        PacketTransportType, HeaderType, TopoBroadcastHST,
        CommunicationProfile, TrafficClass, CommonNH,
    )
    from flexstack.btp.service_access_point import BTPDataRequest, BTPDataIndication
    from flexstack.security.security_profiles import SecurityProfile

    security_on = args.security == "on"

    # ── TX stack ─────────────────────────────────────────────────────────
    (
        tx_ca_svc,
        tx_link_layer,
        tx_loc_svc,
        tx_gn_router,
        tx_btp_router,
        tx_station_id,
        _,
    ) = build_stack(security_on=security_on, interface=args.interface)

    # ── RX stack (minimal: LinkLayer → GN → BTP with direct callback) ──
    rx_mac = generate_random_mac()
    rx_gn_addr = GNAddress(m=M.GN_MULTICAST, st=ST.PASSENGER_CAR, mid=MID(rx_mac))

    if security_on:
        rx_sign_svc, rx_verify_svc = setup_security(at_index=2)
        try:
            from flexstack.geonet.mib import GnSecurity
            rx_mib = MIB(itsGnLocalGnAddr=rx_gn_addr, itsGnSecurity=GnSecurity.ENABLED)
        except ImportError:
            rx_mib = MIB(itsGnLocalGnAddr=rx_gn_addr)
        rx_gn_router = GNRouter(
            mib=rx_mib,
            sign_service=rx_sign_svc,
            verify_service=rx_verify_svc,
        )
    else:
        rx_mib = MIB(itsGnLocalGnAddr=rx_gn_addr)
        rx_gn_router = GNRouter(mib=rx_mib, sign_service=None)

    rx_btp_router = BTPRouter(rx_gn_router)
    rx_gn_router.register_indication_callback(rx_btp_router.btp_data_indication)

    rx_counter = {"count": 0}
    rx_lock = threading.Lock()
    coder_rx = CAMCoder()

    def rx_btp_callback(indication: BTPDataIndication):
        try:
            coder_rx.decode(indication.data)
            with rx_lock:
                rx_counter["count"] += 1
        except Exception:
            pass

    rx_btp_router.register_indication_callback_btp(2001, rx_btp_callback)
    rx_btp_router.freeze_callbacks()

    rx_link_layer = RawLinkLayer(
        args.interface,
        rx_mac,
        receive_callback=rx_gn_router.gn_data_indicate,
    )
    rx_gn_router.link_layer = rx_link_layer

    # ── CAM encoding ─────────────────────────────────────────────────────
    coder = CAMCoder()
    cam_value = _make_cam_value(tx_station_id)
    encoded_cam = coder.encode(cam_value)

    def make_btp_request(data):
        return BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            source_port=0,
            destination_port=2001,
            destination_port_info=0,
            gn_packet_transport_type=PacketTransportType(
                header_type=HeaderType.TSB,
                header_subtype=TopoBroadcastHST.SINGLE_HOP,
            ),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(scf=False, channel_offload=False, tc_id=0),
            security_profile=(
                SecurityProfile.COOPERATIVE_AWARENESS_MESSAGE
                if security_on
                else SecurityProfile.NO_SECURITY
            ),
            its_aid=36,
            security_permissions=b"",
            gn_max_hop_limit=1,
            length=len(data),
            data=data,
        )

    # Warm-up
    print(f"  Warm-up phase ({args.warmup}s)...")
    warmup_end = time.monotonic_ns() + args.warmup * 10**9
    while time.monotonic_ns() < warmup_end:
        tx_btp_router.btp_data_request(make_btp_request(encoded_cam))
    rx_counter["count"] = 0  # Reset after warm-up

    # Measurement — TX is synchronous to wire
    print(f"  Measurement phase ({args.duration}s)...")
    t_start = time.monotonic_ns()
    deadline = t_start + args.duration * 10**9
    tx_count = 0

    while time.monotonic_ns() < deadline:
        tx_btp_router.btp_data_request(make_btp_request(encoded_cam))
        tx_count += 1

    t_end = time.monotonic_ns()
    elapsed = (t_end - t_start) / 1e9
    throughput = tx_count / elapsed
    rx_total = rx_counter["count"]

    print(f"  TX (wire): {tx_count} CAMs ({throughput:.0f}/s), RX: {rx_total} CAMs ({rx_total/elapsed:.0f}/s)")

    teardown_stack(tx_ca_svc, tx_link_layer, tx_loc_svc)
    try:
        rx_link_layer.sock.close()
    except Exception:
        pass

    return compute_stats(args, "concurrent", tx_count, elapsed, throughput, [], [])


# ── Benchmark: RX Throughput ────────────────────────────────────────────────
def bench_rx(args):
    """
    Full-stack RX throughput (receive-only).
    Listens on the network interface for incoming CAMs sent by a remote sender
    (e.g. another machine running `--mode tx`). No internal TX stack is spawned.
    Measures per-packet RX decode latency and throughput.
    """
    from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder

    security_on = args.security == "on"

    # ── RX stack (minimal: LinkLayer → GN → BTP with direct callback) ──
    rx_mac = generate_random_mac()
    rx_gn_addr = GNAddress(m=M.GN_MULTICAST, st=ST.PASSENGER_CAR, mid=MID(rx_mac))

    if security_on:
        rx_sign_svc, rx_verify_svc = setup_security(at_index=2)
        try:
            from flexstack.geonet.mib import GnSecurity
            rx_mib = MIB(itsGnLocalGnAddr=rx_gn_addr, itsGnSecurity=GnSecurity.ENABLED)
        except ImportError:
            rx_mib = MIB(itsGnLocalGnAddr=rx_gn_addr)
        rx_gn_router = GNRouter(
            mib=rx_mib,
            sign_service=rx_sign_svc,
            verify_service=rx_verify_svc,
        )
    else:
        rx_mib = MIB(itsGnLocalGnAddr=rx_gn_addr)
        rx_gn_router = GNRouter(mib=rx_mib, sign_service=None)

    rx_btp_router = BTPRouter(rx_gn_router)
    rx_gn_router.register_indication_callback(rx_btp_router.btp_data_indication)

    # Direct BTP callback for RX measurement — decode each CAM and record latency
    rx_counter = {"count": 0, "latencies": []}
    rx_lock = threading.Lock()
    coder_rx = CAMCoder()

    def rx_btp_callback(indication):
        t0 = time.monotonic_ns()
        try:
            coder_rx.decode(indication.data)
            t1 = time.monotonic_ns()
            with rx_lock:
                rx_counter["count"] += 1
                rx_counter["latencies"].append((t1 - t0) / 1000)  # μs
        except Exception:
            pass

    rx_btp_router.register_indication_callback_btp(2001, rx_btp_callback)
    rx_btp_router.freeze_callbacks()

    rx_link_layer = RawLinkLayer(
        args.interface,
        rx_mac,
        receive_callback=rx_gn_router.gn_data_indicate,
    )
    rx_gn_router.link_layer = rx_link_layer

    # Warm-up: receive and discard
    print(f"  Warm-up phase ({args.warmup}s) — waiting for packets from remote sender...")
    warmup_end = time.monotonic_ns() + args.warmup * 10**9
    while time.monotonic_ns() < warmup_end:
        time.sleep(0.1)

    warmup_count = rx_counter["count"]
    print(f"  Warm-up received {warmup_count} packets")
    rx_counter["count"] = 0
    rx_counter["latencies"] = []

    # Measurement
    print(f"  Measurement phase ({args.duration}s)...")
    t_start = time.monotonic_ns()
    time.sleep(args.duration)
    t_end = time.monotonic_ns()

    elapsed = (t_end - t_start) / 1e9
    rx_total = rx_counter["count"]
    throughput = rx_total / elapsed if elapsed > 0 else 0

    print(f"  RX: {rx_total} CAMs ({throughput:.0f}/s)")

    latencies = rx_counter["latencies"]

    try:
        rx_link_layer.sock.close()
    except Exception:
        pass

    return compute_stats(args, "rx", rx_total, elapsed, throughput, latencies, [])


# ── Benchmark: Codec ────────────────────────────────────────────────────────
def bench_codec(args):
    """
    B3: ASN.1 codec throughput (encode or decode, in-memory).
    Uses the flexstack's internal CAM encoding/decoding without network I/O.
    """
    from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder
    coder = CAMCoder()
    return _bench_codec_with_flexstack_coder(args, coder)


def _bench_codec_with_flexstack_coder(args, coder):
    """Codec benchmark using flexstack's CAMCoder."""
    # Build a sample CAM value (ETSI EN 302 637-2 v2 compliant)
    cam_value = {
        "header": {
            "protocolVersion": 2,
            "messageId": 2,
            "stationId": 12345,
        },
        "cam": {
            "generationDeltaTime": 1000,
            "camParameters": {
                "basicContainer": {
                    "stationType": 5,
                    "referencePosition": {
                        "latitude": 415520000,
                        "longitude": 21340000,
                        "positionConfidenceEllipse": {
                            "semiMajorAxisLength": 4095,
                            "semiMinorAxisLength": 4095,
                            "semiMajorAxisOrientation": 3601,
                        },
                        "altitude": {
                            "altitudeValue": 12000,
                            "altitudeConfidence": "unavailable",
                        },
                    },
                },
                "highFrequencyContainer": (
                    "basicVehicleContainerHighFrequency",
                    {
                        "heading": {
                            "headingValue": 900,
                            "headingConfidence": 127,
                        },
                        "speed": {
                            "speedValue": 0,
                            "speedConfidence": 127,
                        },
                        "driveDirection": "unavailable",
                        "vehicleLength": {
                            "vehicleLengthValue": 1023,
                            "vehicleLengthConfidenceIndication": "unavailable",
                        },
                        "vehicleWidth": 62,
                        "longitudinalAcceleration": {
                            "value": 161,
                            "confidence": 102,
                        },
                        "curvature": {
                            "curvatureValue": 1023,
                            "curvatureConfidence": "unavailable",
                        },
                        "curvatureCalculationMode": "unavailable",
                        "yawRate": {
                            "yawRateValue": 32767,
                            "yawRateConfidence": "unavailable",
                        },
                    },
                ),
            },
        },
    }

    is_encode = args.mode == "codec-encode"

    # Verify encoding works, pre-encode for decode benchmark
    encoded_once = coder.encode(cam_value)
    print(f"  CAM encoded size: {len(encoded_once)} bytes")
    if not is_encode:
        decoded = coder.decode(encoded_once)
        print(f"  CAM decoded station ID: {decoded['header']['stationId']}")

    # Warm-up
    print(f"  Warm-up phase ({args.warmup}s)...")
    t_warmup_end = time.monotonic_ns() + args.warmup * 10**9
    while time.monotonic_ns() < t_warmup_end:
        if is_encode:
            coder.encode(cam_value)
        else:
            coder.decode(encoded_once)

    # Measurement
    print(f"  Measurement phase ({args.duration}s)...")
    latencies = []
    t_start = time.monotonic_ns()
    deadline = t_start + args.duration * 10**9
    count = 0

    while time.monotonic_ns() < deadline:
        t0 = time.monotonic_ns()
        if is_encode:
            coder.encode(cam_value)
        else:
            coder.decode(encoded_once)
        t1 = time.monotonic_ns()
        latencies.append((t1 - t0) / 1000)
        count += 1

    t_end = time.monotonic_ns()
    elapsed = (t_end - t_start) / 1e9
    throughput = count / elapsed

    return compute_stats(args, args.mode, count, elapsed, throughput, latencies, [])


# ── Benchmark: Security Layer (Sign / Verify) ──────────────────────────────
def bench_security(args):
    """
    B5: Security layer throughput (sign or verify, in-memory).
    Measures ECDSA-P256 signing or verification of a CAM-sized payload
    without any networking. Uses the same SignService / VerifyService
    that the full-stack benchmarks use.
    """
    from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder
    from flexstack.security.sn_sap import SNSIGNRequest, SNVERIFYRequest

    is_sign = args.mode == "security-sign"
    coder = CAMCoder()

    # Build a realistic CAM payload to sign
    cam_value = _make_cam_value(12345)
    tbs_message = coder.encode(cam_value)
    print(f"  CAM payload size: {len(tbs_message)} bytes")

    sign_service, verify_service = setup_security(at_index=1)

    # Pre-sign one message to get a signed envelope for the verify benchmark
    sign_req = SNSIGNRequest(
        tbs_message_length=len(tbs_message),
        tbs_message=tbs_message,
        its_aid=36,
        permissions_length=0,
        permissions=b"",
    )
    signed_confirm = sign_service.sign_cam(sign_req)
    signed_message = signed_confirm.sec_message
    print(f"  Signed message size: {len(signed_message)} bytes")

    # Warm-up
    print(f"  Warm-up phase ({args.warmup}s)...")
    t_warmup_end = time.monotonic_ns() + args.warmup * 10**9
    if is_sign:
        while time.monotonic_ns() < t_warmup_end:
            req = SNSIGNRequest(
                tbs_message_length=len(tbs_message),
                tbs_message=tbs_message,
                its_aid=36,
                permissions_length=0,
                permissions=b"",
            )
            sign_service.sign_cam(req)
    else:
        while time.monotonic_ns() < t_warmup_end:
            req = SNVERIFYRequest(
                sec_header_length=0,
                sec_header=b"",
                message_length=len(signed_message),
                message=signed_message,
            )
            verify_service.verify(req)

    # Measurement
    print(f"  Measurement phase ({args.duration}s)...")
    latencies = []
    t_start = time.monotonic_ns()
    deadline = t_start + args.duration * 10**9
    count = 0

    if is_sign:
        while time.monotonic_ns() < deadline:
            req = SNSIGNRequest(
                tbs_message_length=len(tbs_message),
                tbs_message=tbs_message,
                its_aid=36,
                permissions_length=0,
                permissions=b"",
            )
            t0 = time.monotonic_ns()
            sign_service.sign_cam(req)
            t1 = time.monotonic_ns()
            latencies.append((t1 - t0) / 1000)
            count += 1
    else:
        while time.monotonic_ns() < deadline:
            req = SNVERIFYRequest(
                sec_header_length=0,
                sec_header=b"",
                message_length=len(signed_message),
                message=signed_message,
            )
            t0 = time.monotonic_ns()
            verify_service.verify(req)
            t1 = time.monotonic_ns()
            latencies.append((t1 - t0) / 1000)
            count += 1

    t_end = time.monotonic_ns()
    elapsed = (t_end - t_start) / 1e9
    throughput = count / elapsed

    label = "Sign" if is_sign else "Verify"
    print(f"  {label}: {count} ops ({throughput:.0f}/s)")

    return compute_stats(args, args.mode, count, elapsed, throughput, latencies, latencies)



# ── Statistics ──────────────────────────────────────────────────────────────
def compute_stats(args, benchmark, total, elapsed, throughput, latencies, sign_latencies):
    """Compute summary statistics and return as a dict for CSV output."""
    arr = np.array(latencies, dtype=np.float64) if latencies else np.array([0.0])

    impl_name = sys.implementation.name  # 'cpython' or 'pypy'
    impl_version = f"{sys.version_info.major}.{sys.version_info.minor}"

    row = {
        "run_id": args.run_id,
        "implementation": f"{impl_name}_{impl_version}",
        "platform": args.platform,
        "security": args.security,
        "benchmark": benchmark,
        "duration_s": f"{elapsed:.3f}",
        "total_cams": total,
        "throughput_cams_s": f"{throughput:.1f}",
        "latency_mean_us": f"{np.mean(arr):.2f}",
        "latency_std_us": f"{np.std(arr, ddof=1):.2f}" if len(arr) > 1 else "0.00",
        "latency_p50_us": f"{np.percentile(arr, 50):.2f}",
        "latency_p95_us": f"{np.percentile(arr, 95):.2f}",
        "latency_p99_us": f"{np.percentile(arr, 99):.2f}",
        "latency_min_us": f"{np.min(arr):.2f}",
        "latency_max_us": f"{np.max(arr):.2f}",
        "sign_latency_mean_us": (
            f"{np.mean(np.array(sign_latencies)):.2f}" if sign_latencies else "0.00"
        ),
    }

    return row


def write_csv_row(output_path, row):
    """Append a single CSV row. Creates the file with header if it doesn't exist."""
    file_exists = os.path.exists(output_path)
    with open(output_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


# ── CLI ─────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="FlexStack Benchmark — Python (CPython / PyPy)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Benchmark Modes:
  tx             Send CAMs at max rate, measure wire throughput
                 (also used as remote sender for rx mode)
  rx             Receive-only: listen for CAMs from a remote sender
                 and measure RX decode throughput
  concurrent     Self-contained TX+RX on same machine (two stacks)
  codec-encode     ASN.1 CAM encode throughput (in-memory)
  codec-decode     ASN.1 CAM decode throughput (in-memory)
  security-sign    ECDSA-P256 signing throughput (in-memory, no networking)
  security-verify  ECDSA-P256 verification throughput (in-memory, no networking)

Examples:
  sudo python3 benchmark.py --mode tx --security off --duration 60
  sudo pypy3   benchmark.py --mode tx --security on  --duration 60 --warmup 15
  python3       benchmark.py --mode codec-encode --duration 60

Cross-machine RX example:
  Machine A (sender):   sudo python3 benchmark.py --mode tx --interface eth0
  Machine B (receiver): sudo python3 benchmark.py --mode rx --interface eth0
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["tx", "rx", "concurrent", "codec-encode", "codec-decode", "security-sign", "security-verify"],
        required=True,
        help="Benchmark mode",
    )
    parser.add_argument(
        "--security",
        choices=["off", "on"],
        default="off",
        help="Security mode (ECDSA-P256 signing/verification)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Measurement duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=5,
        help="Warm-up duration in seconds (default: 5, use 15 for PyPy)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "results", "results.csv"
        ),
        help="CSV output file path",
    )
    parser.add_argument(
        "--run-id",
        type=int,
        default=1,
        help="Run identifier (passed by orchestrator)",
    )
    parser.add_argument(
        "--platform",
        type=str,
        default="laptop",
        choices=["laptop", "rpi3", "rpi5"],
        help="Platform identifier for CSV output",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default="lo",
        help="Network interface (default: lo for loopback)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    impl = sys.implementation.name
    print(f"{'=' * 60}")
    print(f"FlexStack Benchmark — {impl} {sys.version.split()[0]}")
    print(f"{'=' * 60}")
    print(f"  Mode     : {args.mode}")
    print(f"  Security : {args.security}")
    print(f"  Duration : {args.duration}s")
    print(f"  Warm-up  : {args.warmup}s")
    print(f"  Platform : {args.platform}")
    print(f"  Interface: {args.interface}")
    print(f"  Run ID   : {args.run_id}")
    print(f"  Output   : {args.output}")
    print()

    if args.mode == "tx":
        row = bench_tx(args)
    elif args.mode == "rx":
        row = bench_rx(args)
    elif args.mode == "concurrent":
        row = bench_concurrent(args)
    elif args.mode in ("codec-encode", "codec-decode"):
        row = bench_codec(args)
    elif args.mode in ("security-sign", "security-verify"):
        row = bench_security(args)
    else:
        print(f"Unknown mode: {args.mode}")
        sys.exit(1)

    # Write result
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    write_csv_row(args.output, row)

    # Print summary
    print()
    print(f"  Results:")
    print(f"    Total        : {row['total_cams']}")
    print(f"    Throughput   : {row['throughput_cams_s']} CAMs/s")
    print(f"    Latency mean : {row['latency_mean_us']} μs")
    print(f"    Latency p50  : {row['latency_p50_us']} μs")
    print(f"    Latency p95  : {row['latency_p95_us']} μs")
    print(f"    Latency p99  : {row['latency_p99_us']} μs")
    print(f"  Written to: {args.output}")


if __name__ == "__main__":
    main()
