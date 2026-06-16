// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
//!
//! FlexStack Benchmark — Rust
//!
//! Benchmark harness for `rustflexstack` measuring:
//!   B1  Full-stack TX throughput (loopback)
//!   B2  Concurrent TX/RX throughput (loopback)
//!   B3  ASN.1 codec encode/decode throughput (in-memory)
//!
//! Usage:
//!   sudo ./flexstack-bench --mode tx --security off --duration 60
//!   sudo ./flexstack-bench --mode concurrent --security on --duration 60

use clap::Parser;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;
use lazy_static::lazy_static;

lazy_static! {
    static ref RX_TIMESTAMPS: Mutex<VecDeque<Instant>> = Mutex::new(VecDeque::new());
}

use rustflexstack::btp::router::{BTPRouterHandle, Router as BTPRouter};
use rustflexstack::btp::service_access_point::{BTPDataIndication, BTPDataRequest};
use rustflexstack::facilities::ca_basic_service::cam_coder::{
    cam_header, generation_delta_time_now, AccelerationComponent, AccelerationConfidence,
    AccelerationValue, Altitude, AltitudeConfidence, AltitudeValue, BasicContainer,
    BasicVehicleContainerHighFrequency, Cam, CamCoder, CamParameters, CamPayload, Curvature,
    CurvatureCalculationMode, CurvatureConfidence, CurvatureValue, DriveDirection, Heading,
    HeadingConfidence, HeadingValue, HighFrequencyContainer, Latitude, Longitude,
    PositionConfidenceEllipse, ReferencePositionWithConfidence, SemiAxisLength, Speed,
    SpeedConfidence, SpeedValue, TrafficParticipantType, VehicleLength,
    VehicleLengthConfidenceIndication, VehicleLengthValue, VehicleWidth, Wgs84AngleValue, YawRate,
    YawRateConfidence, YawRateValue,
};
use rustflexstack::geonet::basic_header::{BasicHeader, BasicNH};
use rustflexstack::geonet::gn_address::{GNAddress, M, MID, ST};
use rustflexstack::geonet::mib::Mib;
use rustflexstack::geonet::position_vector::LongPositionVector;
use rustflexstack::geonet::router::{Router as GNRouter, RouterHandle};
use rustflexstack::geonet::service_access_point::{
    Area, CommonNH, CommunicationProfile, HeaderSubType,
    HeaderType, PacketTransportType, TopoBroadcastHST, TrafficClass,
};
use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;
use rustflexstack::security::sn_sap::{ReportVerify, SNSignRequest, SNVerifyRequest, SecurityProfile};

// Security imports
use rustflexstack::security::certificate::{Certificate, OwnCertificate};
use rustflexstack::security::certificate_library::CertificateLibrary;
use rustflexstack::security::ecdsa_backend::EcdsaBackend;
use rustflexstack::security::sign_service::SignService;
use rustflexstack::security::verify_service::{verify_message, VerifyEvent};

// ── CLI ─────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(
    name = "flexstack-bench",
    about = "FlexStack Benchmark — Rust",
    long_about = "Benchmark harness for RustFlexStack measuring TX/RX throughput and codec performance.\n\nModes:\n  tx              Send CAMs at max rate, measure wire throughput (also used as remote sender for rx)\n  rx              Receive-only: listen for CAMs from a remote sender and measure RX throughput\n  concurrent      Self-contained TX+RX on same machine (two stacks)\n  codec-encode    ASN.1 CAM encode throughput (in-memory)\n  codec-decode    ASN.1 CAM decode throughput (in-memory)\n  security-sign   ECDSA-P256 signing throughput (in-memory, no networking)\n  security-verify ECDSA-P256 verification throughput (in-memory, no networking)\n\nCross-machine RX example:\n  Machine A (sender):   sudo ./flexstack-bench --mode tx --interface eth0\n  Machine B (receiver): sudo ./flexstack-bench --mode rx --interface eth0"
)]
struct Args {
    /// Benchmark mode
    #[arg(long, value_parser = ["tx", "rx", "concurrent", "codec-encode", "codec-decode", "security-sign", "security-verify"])]
    mode: String,

    /// Security mode (ECDSA-P256 signing/verification)
    #[arg(long, default_value = "off", value_parser = ["off", "on"])]
    security: String,

    /// Measurement duration in seconds
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Warm-up duration in seconds
    #[arg(long, default_value_t = 5)]
    warmup: u64,

    /// CSV output file path
    #[arg(long, default_value = "../results/results.csv")]
    output: String,

    /// Run identifier (passed by orchestrator)
    #[arg(long, default_value_t = 1)]
    run_id: u32,

    /// Platform identifier for CSV output
    #[arg(long, default_value = "laptop", value_parser = ["laptop", "rpi3", "rpi5"])]
    platform: String,

    /// Network interface
    #[arg(long, default_value = "lo")]
    interface: String,

    /// Authorization Ticket index to use when security is enabled (1 or 2)
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=2))]
    at: u64,

    /// Path to the certificate directory containing root_ca.cert, aa.cert, at1.cert,
    /// at2.cert, at1.key, and at2.key (generated by python/generate_certs.py)
    #[arg(long, default_value = "certs")]
    certs_dir: String,
}

// ── CSV output ──────────────────────────────────────────────────────────────
const CSV_HEADER: &str = "run_id,implementation,platform,security,benchmark,duration_s,total_cams,throughput_cams_s,latency_mean_us,latency_std_us,latency_p50_us,latency_p95_us,latency_p99_us,latency_min_us,latency_max_us,sign_latency_mean_us";

struct BenchmarkResult {
    run_id: u32,
    platform: String,
    security: String,
    benchmark: String,
    duration_s: f64,
    total_cams: u64,
    throughput: f64,
    latency_mean: f64,
    latency_std: f64,
    latency_p50: f64,
    latency_p95: f64,
    latency_p99: f64,
    latency_min: f64,
    latency_max: f64,
    sign_latency_mean: f64,
}

impl BenchmarkResult {
    fn to_csv_row(&self) -> String {
        format!(
            "{},rust,{},{},{},{:.3},{},{:.1},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}",
            self.run_id,
            self.platform,
            self.security,
            self.benchmark,
            self.duration_s,
            self.total_cams,
            self.throughput,
            self.latency_mean,
            self.latency_std,
            self.latency_p50,
            self.latency_p95,
            self.latency_p99,
            self.latency_min,
            self.latency_max,
            self.sign_latency_mean,
        )
    }
}

fn write_csv_row(path: &str, result: &BenchmarkResult) {
    let path_buf = PathBuf::from(path);
    if let Some(parent) = path_buf.parent() {
        fs::create_dir_all(parent).ok();
    }

    let file_exists = path_buf.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path_buf)
        .expect("Failed to open CSV output file");

    if !file_exists {
        writeln!(file, "{}", CSV_HEADER).expect("Failed to write CSV header");
    }
    writeln!(file, "{}", result.to_csv_row()).expect("Failed to write CSV row");
}

// ── Statistics helpers ──────────────────────────────────────────────────────
fn mean(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<f64>() / data.len() as f64
}

fn std_dev(data: &[f64]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let m = mean(data);
    let variance = data.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (data.len() - 1) as f64;
    variance.sqrt()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn compute_stats(latencies: &mut Vec<f64>) -> (f64, f64, f64, f64, f64, f64, f64) {
    if latencies.is_empty() {
        return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let m = mean(latencies);
    let s = std_dev(latencies);
    let p50 = percentile(latencies, 50.0);
    let p95 = percentile(latencies, 95.0);
    let p99 = percentile(latencies, 99.0);
    let min = latencies[0];
    let max = *latencies.last().unwrap();
    (m, s, p50, p95, p99, min, max)
}

// ── Helpers ─────────────────────────────────────────────────────────────────
fn random_mac() -> [u8; 6] {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    [
        0x02,
        (s >> 24) as u8,
        (s >> 16) as u8,
        (s >> 8) as u8,
        s as u8,
        0xBE,
    ]
}

fn make_cam(station_id: u32) -> Cam {
    let hf = BasicVehicleContainerHighFrequency::new(
        Heading::new(HeadingValue(900), HeadingConfidence(127)),
        Speed::new(SpeedValue(0), SpeedConfidence(127)),
        DriveDirection::unavailable,
        VehicleLength::new(
            VehicleLengthValue(1023),
            VehicleLengthConfidenceIndication::unavailable,
        ),
        VehicleWidth(62),
        AccelerationComponent::new(AccelerationValue(161), AccelerationConfidence(102)),
        Curvature::new(CurvatureValue(1023), CurvatureConfidence::unavailable),
        CurvatureCalculationMode::unavailable,
        YawRate::new(YawRateValue(32767), YawRateConfidence::unavailable),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    Cam::new(
        cam_header(station_id),
        CamPayload::new(
            generation_delta_time_now(),
            CamParameters::new(
                BasicContainer::new(
                    TrafficParticipantType(5),
                    ReferencePositionWithConfidence::new(
                        Latitude(415_520_000),
                        Longitude(21_340_000),
                        PositionConfidenceEllipse::new(
                            SemiAxisLength(4095),
                            SemiAxisLength(4095),
                            Wgs84AngleValue(3601),
                        ),
                        Altitude::new(AltitudeValue(12000), AltitudeConfidence::unavailable),
                    ),
                ),
                HighFrequencyContainer::basicVehicleContainerHighFrequency(hf),
                None,
                None,
                None,
            ),
        ),
    )
}

fn cam_btp_request(data: Vec<u8>, security_on: bool) -> BTPDataRequest {
    BTPDataRequest {
        btp_type: CommonNH::BtpB,
        source_port: 0,
        destination_port: 2001,
        destination_port_info: 0,
        gn_packet_transport_type: PacketTransportType {
            header_type: HeaderType::Tsb,
            header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
        },
        gn_destination_address: GNAddress {
            m: M::GnMulticast,
            st: ST::Unknown,
            mid: MID::new([0xFF; 6]),
        },
        communication_profile: CommunicationProfile::Unspecified,
        gn_area: Area {
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
        },
        traffic_class: TrafficClass {
            scf: false,
            channel_offload: false,
            tc_id: 0,
        },
        security_profile: if security_on {
            SecurityProfile::CooperativeAwarenessMessage
        } else {
            SecurityProfile::NoSecurity
        },
        its_aid: 36,
        security_permissions: vec![],
        gn_max_hop_limit: 1,
        gn_max_packet_lifetime: None,
        gn_repetition_interval: None,
        gn_max_repetition_time: None,
        destination: None,
        length: data.len() as u16,
        data,
    }
}

/// Spawn a complete stack: GN + BTP + LinkLayer, with optional security middleware.
/// Returns (gn_handle, btp_handle).
/// If `tx_wire_counter` is Some, it is incremented each time a packet is handed to the LL.
fn spawn_stack(
    mib: Mib,
    mac: [u8; 6],
    iface: &str,
    sign_svc: Option<Arc<Mutex<SignService>>>,
    tx_wire_counter: Option<Arc<AtomicU64>>,
) -> (RouterHandle, BTPRouterHandle) {
    // GN router is always spawned WITHOUT security params — security is a middleware
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    let (raw_ll_tx, raw_ll_rx) = mpsc::channel::<Vec<u8>>();
    let (timed_tx, ll_to_gn_rx) = mpsc::channel::<(Instant, Vec<u8>)>();
    let ll_to_gn_tx = raw_ll_tx.clone();

    thread::spawn(move || {
        while let Ok(packet) = raw_ll_rx.recv() {
            let _ = timed_tx.send((Instant::now(), packet));
        }
    });

    if let Some(svc) = sign_svc {
        // ── TX path: GN → sign → LL ─────────────────────────────────────
        let (secured_ll_tx, secured_ll_rx) = mpsc::channel::<Vec<u8>>();
        let sign_svc_tx = Arc::clone(&svc);
        let wire_cnt = tx_wire_counter.clone();
        thread::spawn(move || {
            while let Ok(packet) = gn_to_ll_rx.recv() {
                if packet.len() < 4 {
                    let _ = secured_ll_tx.send(packet);
                    if let Some(ref c) = wire_cnt { c.fetch_add(1, Ordering::Relaxed); }
                    continue;
                }
                let bh_bytes: [u8; 4] = packet[0..4].try_into().unwrap();
                let bh = BasicHeader::decode(bh_bytes);
                match bh.nh {
                    BasicNH::CommonHeader if packet.len() > 4 => {
                        let request = SNSignRequest {
                            tbs_message: packet[4..].to_vec(),
                            its_aid: 36,
                            permissions: vec![],
                            generation_location: None,
                        };
                        let sec_message = {
                            let mut s = sign_svc_tx.lock().unwrap();
                            s.sign_request(&request).sec_message
                        };
                        let mut new_bh = bh;
                        new_bh.nh = BasicNH::SecuredPacket;
                        let secured: Vec<u8> = new_bh.encode().iter().copied()
                            .chain(sec_message.iter().copied()).collect();
                        let _ = secured_ll_tx.send(secured);
                        if let Some(ref c) = wire_cnt { c.fetch_add(1, Ordering::Relaxed); }
                    }
                    _ => {
                        let _ = secured_ll_tx.send(packet);
                        if let Some(ref c) = wire_cnt { c.fetch_add(1, Ordering::Relaxed); }
                    }
                }
            }
        });
        // LL uses the signed output channel
        RawLinkLayer::new(ll_to_gn_tx, secured_ll_rx, iface, mac).start();
        // ── RX path: LL → verify → GN ───────────────────────────────────
        let g1 = gn_handle.clone();
        let verify_svc = svc;
        thread::spawn(move || {
            while let Ok((t0, packet)) = ll_to_gn_rx.recv() {
                RX_TIMESTAMPS.lock().unwrap().push_back(t0);
                
                if packet.len() < 4 {
                    g1.send_incoming_packet(packet);
                    continue;
                }
                let bh_bytes: [u8; 4] = packet[0..4].try_into().unwrap();
                let bh = BasicHeader::decode(bh_bytes);
                match bh.nh {
                    BasicNH::SecuredPacket if packet.len() > 4 => {
                        let request = SNVerifyRequest {
                            message: packet[4..].to_vec(),
                        };
                        let (confirm, _events) = {
                            let mut s = verify_svc.lock().unwrap();
                            let s = &mut *s;
                            let result = verify_message(&request, &s.backend, &mut s.cert_library);
                            for event in &result.1 {
                                match event {
                                    VerifyEvent::UnknownAt(h8) => s.notify_unknown_at(h8),
                                    VerifyEvent::InlineP2pcdRequest(h3s) => s.notify_inline_p2pcd_request(h3s),
                                    VerifyEvent::ReceivedCaCertificate(cert) => s.notify_received_ca_certificate(cert.as_ref().clone()),
                                }
                            }
                            result
                        };
                        if confirm.report == ReportVerify::Success {
                            let mut new_bh = bh;
                            new_bh.nh = BasicNH::CommonHeader;
                            let plain: Vec<u8> = new_bh.encode().iter().copied()
                                .chain(confirm.plain_message.iter().copied()).collect();
                            g1.send_incoming_packet(plain);
                        } else {
                            let mut q = RX_TIMESTAMPS.lock().unwrap();
                            if !q.is_empty() { q.pop_front(); }
                        }
                    }
                    _ => g1.send_incoming_packet(packet),
                }
            }
        });
    } else {
        // No security — wire directly, with optional counter
        let wire_cnt = tx_wire_counter;
        if let Some(cnt) = wire_cnt {
            // Intercept GN→LL to count packets
            let (counted_ll_tx, counted_ll_rx) = mpsc::channel::<Vec<u8>>();
            thread::spawn(move || {
                while let Ok(packet) = gn_to_ll_rx.recv() { println!("gn_to_ll_rx len: {}", packet.len());
                    cnt.fetch_add(1, Ordering::Relaxed);
                    let _ = counted_ll_tx.send(packet);
                }
            });
            RawLinkLayer::new(ll_to_gn_tx, counted_ll_rx, iface, mac).start();
        } else {
            RawLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx, iface, mac).start();
        }
        let g1 = gn_handle.clone();
        thread::spawn(move || {
            while let Ok((t0, p)) = ll_to_gn_rx.recv() {
                RX_TIMESTAMPS.lock().unwrap().push_back(t0);
                g1.send_incoming_packet(p);
            }
        });
    }

    // GN ↔ BTP
    let b1 = btp_handle.clone();
    thread::spawn(move || {
        while let Ok(i) = gn_to_btp_rx.recv() {
            b1.send_gn_data_indication(i);
        }
    });
    let g2 = gn_handle.clone();
    thread::spawn(move || {
        while let Ok(r) = btp_to_gn_rx.recv() {
            g2.send_gn_data_request(r);
        }
    });

    (gn_handle, btp_handle)
}

// ── Security setup ──────────────────────────────────────────────────────────
/// Build a security stack by loading certificate files from `certs_dir`.
/// Expects: root_ca.cert, aa.cert, at1.cert, at2.cert, at1.key / at2.key.
/// Generate them once with: `python python/generate_certs.py`
/// Both TX and RX devices must share the same certificate chain so that
/// signatures produced by one device can be verified by the other.
fn build_security_stack(at_index: usize, certs_dir: &str) -> Arc<Mutex<SignService>> {
    let cert_dir = Path::new(certs_dir);

    let root_bytes = fs::read(cert_dir.join("root_ca.cert"))
        .expect("root_ca.cert not found — run python/generate_certs.py first");
    let aa_bytes = fs::read(cert_dir.join("aa.cert"))
        .expect("aa.cert not found — run python/generate_certs.py first");

    let root_ca = Certificate::from_bytes(&root_bytes, None);
    let aa = Certificate::from_bytes(&aa_bytes, Some(root_ca.clone()));

    let at1_bytes = fs::read(cert_dir.join("at1.cert")).expect("at1.cert not found");
    let at2_bytes = fs::read(cert_dir.join("at2.cert")).expect("at2.cert not found");

    let at1 = Certificate::from_bytes(&at1_bytes, Some(aa.clone()));
    let at2 = Certificate::from_bytes(&at2_bytes, Some(aa.clone()));

    let own_key_file = if at_index == 1 { "at1.key" } else { "at2.key" };
    let key_bytes = fs::read(cert_dir.join(own_key_file))
        .unwrap_or_else(|_| panic!("{} not found — run python/generate_certs.py first", own_key_file));

    let mut backend = EcdsaBackend::new();
    let key_id = backend.import_signing_key(&key_bytes);

    let (own_cert, peer_cert) = if at_index == 1 {
        (at1.clone(), at2.clone())
    } else {
        (at2.clone(), at1.clone())
    };

    let cert_lib = CertificateLibrary::new(
        &backend,
        vec![root_ca],
        vec![aa],
        vec![own_cert.clone(), peer_cert],
    );

    let mut sign_service = SignService::new(backend, cert_lib);
    let own = OwnCertificate::new(own_cert, key_id);
    sign_service.add_own_certificate(own);

    Arc::new(Mutex::new(sign_service))
}

/// Create two independent SignService instances from the same cert chain on disk.
/// TX uses at1 for signing, RX uses at2. Both share the same trust anchor so
/// signatures produced by one can be verified by the other.
/// Separate backends = no Mutex contention between the two stacks.
fn build_security_stack_pair(certs_dir: &str) -> (Arc<Mutex<SignService>>, Arc<Mutex<SignService>>) {
    let cert_dir = Path::new(certs_dir);

    let root_bytes = fs::read(cert_dir.join("root_ca.cert"))
        .expect("root_ca.cert not found — run python/generate_certs.py first");
    let aa_bytes = fs::read(cert_dir.join("aa.cert"))
        .expect("aa.cert not found — run python/generate_certs.py first");
    let at1_bytes = fs::read(cert_dir.join("at1.cert")).expect("at1.cert not found");
    let at2_bytes = fs::read(cert_dir.join("at2.cert")).expect("at2.cert not found");
    let at1_key = fs::read(cert_dir.join("at1.key")).expect("at1.key not found");
    let at2_key = fs::read(cert_dir.join("at2.key")).expect("at2.key not found");

    // ── TX service (signs with at1) ──────────────────────────────────────
    let mut tx_backend = EcdsaBackend::new();
    let tx_key_id = tx_backend.import_signing_key(&at1_key);
    let tx_root = Certificate::from_bytes(&root_bytes, None);
    let tx_aa = Certificate::from_bytes(&aa_bytes, Some(tx_root.clone()));
    let tx_at1 = Certificate::from_bytes(&at1_bytes, Some(tx_aa.clone()));
    let tx_at2 = Certificate::from_bytes(&at2_bytes, Some(tx_aa.clone()));
    let tx_cert_lib = CertificateLibrary::new(
        &tx_backend,
        vec![tx_root],
        vec![tx_aa],
        vec![tx_at1.clone(), tx_at2],
    );
    let mut tx_sign = SignService::new(tx_backend, tx_cert_lib);
    tx_sign.add_own_certificate(OwnCertificate::new(tx_at1, tx_key_id));

    // ── RX service (signs with at2, independent backend) ─────────────────
    let mut rx_backend = EcdsaBackend::new();
    let rx_key_id = rx_backend.import_signing_key(&at2_key);
    let rx_root = Certificate::from_bytes(&root_bytes, None);
    let rx_aa = Certificate::from_bytes(&aa_bytes, Some(rx_root.clone()));
    let rx_at1 = Certificate::from_bytes(&at1_bytes, Some(rx_aa.clone()));
    let rx_at2 = Certificate::from_bytes(&at2_bytes, Some(rx_aa.clone()));
    let rx_cert_lib = CertificateLibrary::new(
        &rx_backend,
        vec![rx_root],
        vec![rx_aa],
        vec![rx_at2.clone(), rx_at1],
    );
    let mut rx_sign = SignService::new(rx_backend, rx_cert_lib);
    rx_sign.add_own_certificate(OwnCertificate::new(rx_at2, rx_key_id));

    (Arc::new(Mutex::new(tx_sign)), Arc::new(Mutex::new(rx_sign)))
}

// ── Benchmark: TX Throughput ────────────────────────────────────────────────
fn bench_tx(args: &Args) -> BenchmarkResult {
    let mac = random_mac();
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let security_on = args.security == "on";

    let wire_counter = Arc::new(AtomicU64::new(0));
    let sign_svc = if security_on { Some(build_security_stack(args.at as usize, &args.certs_dir)) } else { None };
    let (gn_handle, btp_handle) = spawn_stack(mib, mac, &args.interface, sign_svc, Some(Arc::clone(&wire_counter)));

    // Seed position vector
    let mut epv = LongPositionVector::decode([0u8; 24]);
    epv.update_from_gps(41.552, 2.134, 0.0, 0.0, true);
    gn_handle.update_position_vector(epv);
    thread::sleep(Duration::from_millis(50));

    let coder = CamCoder::new();
    let template = make_cam(station_id);
    // Warm-up: feed packets to saturate the pipeline
    println!("  Warm-up phase ({}s)...", args.warmup);
    let warmup_end = Instant::now() + Duration::from_secs(args.warmup);
    while Instant::now() < warmup_end {
        if let Ok(data) = coder.encode(&template) {
            btp_handle.send_btp_data_request(cam_btp_request(data, security_on));
        }
    }

    // Let pipeline drain after warmup
    thread::sleep(Duration::from_millis(200));

    // Measurement: send packets sequentially, measure full-stack TX latency per packet
    // (encode → BTP → GN → optional security sign → link layer)
    println!("  Measurement phase ({}s)...", args.duration);
    let mut latencies: Vec<f64> = Vec::with_capacity(500_000);
    wire_counter.store(0, Ordering::SeqCst);
    let bench_start = Instant::now();
    let bench_end = bench_start + Duration::from_secs(args.duration);

    while Instant::now() < bench_end {
        let prev = wire_counter.load(Ordering::SeqCst);
        let t0 = Instant::now();
        if let Ok(data) = coder.encode(&make_cam(station_id)) {
            btp_handle.send_btp_data_request(cam_btp_request(data, security_on));
            // Spin-wait until the packet hits the wire (full stack traversal)
            while wire_counter.load(Ordering::Acquire) == prev {
                std::hint::spin_loop();
            }
            let t1 = Instant::now();
            latencies.push(t1.duration_since(t0).as_secs_f64() * 1e6);
        }
    }

    let elapsed = bench_start.elapsed().as_secs_f64();
    let total = latencies.len() as u64;
    let throughput = total as f64 / elapsed;

    let (lat_mean, lat_std, lat_p50, lat_p95, lat_p99, lat_min, lat_max) =
        compute_stats(&mut latencies);

    BenchmarkResult {
        run_id: args.run_id,
        platform: args.platform.clone(),
        security: args.security.clone(),
        benchmark: "tx".to_string(),
        duration_s: elapsed,
        total_cams: total,
        throughput,
        latency_mean: lat_mean,
        latency_std: lat_std,
        latency_p50: lat_p50,
        latency_p95: lat_p95,
        latency_p99: lat_p99,
        latency_min: lat_min,
        latency_max: lat_max,
        sign_latency_mean: 0.0,
    }
}

// ── Benchmark: Concurrent TX/RX ────────────────────────────────────────────
fn bench_concurrent(args: &Args) -> BenchmarkResult {
    // Two separate stacks (different GN addresses) so the GN router's
    // Duplicate Address Detection doesn't drop loopback packets.
    let tx_mac = random_mac();
    let mut tx_mib = Mib::new();
    tx_mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(tx_mac));
    tx_mib.itsGnBeaconServiceRetransmitTimer = 0;
    let station_id = u32::from_be_bytes([tx_mac[2], tx_mac[3], tx_mac[4], tx_mac[5]]);
    let security_on = args.security == "on";

    let wire_counter = Arc::new(AtomicU64::new(0));

    let (tx_sign_svc, rx_sign_svc) = if security_on {
        let (tx, rx) = build_security_stack_pair(&args.certs_dir);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (tx_gn, tx_btp) = spawn_stack(tx_mib, tx_mac, &args.interface, tx_sign_svc, Some(Arc::clone(&wire_counter)));

    let mut tx_epv = LongPositionVector::decode([0u8; 24]);
    tx_epv.update_from_gps(41.552, 2.134, 0.0, 0.0, true);
    tx_gn.update_position_vector(tx_epv);

    // RX stack
    let rx_mac = {
        let mut m = random_mac();
        m[5] = m[5].wrapping_add(1);
        m
    };
    let mut rx_mib = Mib::new();
    rx_mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(rx_mac));
    rx_mib.itsGnBeaconServiceRetransmitTimer = 0;

    let (rx_gn, rx_btp) = spawn_stack(rx_mib, rx_mac, &args.interface, rx_sign_svc, None);

    let mut rx_epv = LongPositionVector::decode([0u8; 24]);
    rx_epv.update_from_gps(41.552, 2.134, 0.0, 0.0, true);
    rx_gn.update_position_vector(rx_epv);

    // Register RX on BTP port 2001
    let (cam_ind_tx, cam_ind_rx) = mpsc::channel::<BTPDataIndication>();
    rx_btp.register_port(2001, cam_ind_tx);

    thread::sleep(Duration::from_millis(50));

    // Shared counters
    let rx_count = Arc::new(AtomicU64::new(0));
    let rx_errors = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));

    // RX thread — use blocking recv() so rx_count is incremented immediately
    // when the packet completes the full pipeline (verify → GN → BTP → decode).
    // recv_timeout() would introduce up to 100ms of polling lag, making the
    // spin-wait in the measurement loop measure scheduling jitter rather than
    // actual end-to-end latency.
    {
        let cnt = rx_count.clone();
        let err = rx_errors.clone();
        let stop = stop_flag.clone();
        thread::spawn(move || {
            let coder = CamCoder::new();
            while !stop.load(Ordering::Relaxed) {
                match cam_ind_rx.recv() {
                    Ok(ind) => {
                        match coder.decode(&ind.data) {
                            Ok(_) => { cnt.fetch_add(1, Ordering::Release); }
                            Err(_) => { err.fetch_add(1, Ordering::Relaxed); }
                        }
                    }
                    Err(_) => break, // channel disconnected
                }
            }
        });
    }

    let coder = CamCoder::new();

    // Warm-up
    println!("  Warm-up phase ({}s)...", args.warmup);
    let warmup_end = Instant::now() + Duration::from_secs(args.warmup);
    while Instant::now() < warmup_end {
        if let Ok(data) = coder.encode(&make_cam(station_id)) {
            tx_btp.send_btp_data_request(cam_btp_request(data, security_on));
        }
    }

    // Let pipeline drain after warmup
    thread::sleep(Duration::from_millis(200));

    // Measurement: send packets sequentially, measure full end-to-end TX→RX latency
    // (encode → TX BTP → TX GN → optional sign → TX LL → wire →
    //  RX LL → optional verify → RX GN → RX BTP → decode)
    println!("  Measurement phase ({}s)...", args.duration);
    let mut latencies: Vec<f64> = Vec::with_capacity(500_000);
    wire_counter.store(0, Ordering::SeqCst);
    rx_count.store(0, Ordering::SeqCst);
    rx_errors.store(0, Ordering::SeqCst);

    let bench_start = Instant::now();
    let bench_end = bench_start + Duration::from_secs(args.duration);

    while Instant::now() < bench_end {
        let prev_rx = rx_count.load(Ordering::SeqCst);
        let t0 = Instant::now();
        if let Ok(data) = coder.encode(&make_cam(station_id)) {
            tx_btp.send_btp_data_request(cam_btp_request(data, security_on));
            // Wait for the packet to traverse the full TX→wire→RX pipeline
            while rx_count.load(Ordering::Acquire) == prev_rx {
                std::hint::spin_loop();
            }
            let t1 = Instant::now();
            latencies.push(t1.duration_since(t0).as_secs_f64() * 1e6);
        }
    }

    let tx_total = wire_counter.load(Ordering::SeqCst);
    let rx_total = rx_count.load(Ordering::SeqCst);
    let elapsed = bench_start.elapsed().as_secs_f64();

    stop_flag.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(200));

    let total = latencies.len() as u64;
    let throughput = total as f64 / elapsed;

    println!(
        "  TX (wire): {} CAMs ({:.0}/s), RX: {} CAMs ({:.0}/s)",
        tx_total, tx_total as f64 / elapsed, rx_total, rx_total as f64 / elapsed
    );

    let (lat_mean, lat_std, lat_p50, lat_p95, lat_p99, lat_min, lat_max) =
        compute_stats(&mut latencies);

    BenchmarkResult {
        run_id: args.run_id,
        platform: args.platform.clone(),
        security: args.security.clone(),
        benchmark: "concurrent".to_string(),
        duration_s: elapsed,
        total_cams: total,
        throughput,
        latency_mean: lat_mean,
        latency_std: lat_std,
        latency_p50: lat_p50,
        latency_p95: lat_p95,
        latency_p99: lat_p99,
        latency_min: lat_min,
        latency_max: lat_max,
        sign_latency_mean: 0.0,
    }
}

// ── Benchmark: RX Throughput (receive-only) ─────────────────────────────────
// Listens on the network interface for incoming CAMs sent by a remote sender
// (e.g. another machine running `--mode tx`). No internal TX stack is spawned.
fn bench_rx(args: &Args) -> BenchmarkResult {
    let rx_mac = random_mac();
    let mut rx_mib = Mib::new();
    rx_mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(rx_mac));
    rx_mib.itsGnBeaconServiceRetransmitTimer = 0;
    let security_on = args.security == "on";

    let sign_svc = if security_on { Some(build_security_stack(args.at as usize, &args.certs_dir)) } else { None };
    let (_rx_gn, rx_btp) = spawn_stack(rx_mib, rx_mac, &args.interface, sign_svc, None);

    // Register RX on BTP port 2001
    let (cam_ind_tx, cam_ind_rx) = mpsc::channel::<BTPDataIndication>();
    rx_btp.register_port(2001, cam_ind_tx);

    thread::sleep(Duration::from_millis(50));

    // Warm-up: receive and discard
    println!("  Warm-up phase ({}s) — waiting for packets from remote sender...", args.warmup);
    let warmup_end = Instant::now() + Duration::from_secs(args.warmup);
    let mut warmup_count = 0u64;
    while Instant::now() < warmup_end {
        match cam_ind_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(_) => {
                warmup_count += 1;
                let _ = RX_TIMESTAMPS.lock().unwrap().pop_front();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    
    // Do not clear RX_TIMESTAMPS, as there may be in-flight packets in the pipeline
    // that were dequeued during warmup but haven't reached cam_ind_rx yet.

    println!("  Warm-up received {} packets", warmup_count);

    // Measurement: collect RX decode latencies
    println!("  Measurement phase ({}s)...", args.duration);
    let mut latencies: Vec<f64> = Vec::with_capacity(500_000);
    let coder_rx = CamCoder::new();
    let bench_start = Instant::now();
    let bench_end = bench_start + Duration::from_secs(args.duration);
    let mut rx_errors = 0u64;

    while Instant::now() < bench_end {
        match cam_ind_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ind) => {
                let t0 = RX_TIMESTAMPS.lock().unwrap().pop_front().unwrap_or_else(Instant::now);
                match coder_rx.decode(&ind.data) {
                    Ok(_) => {
                        let t1 = Instant::now();
                        latencies.push(t1.duration_since(t0).as_secs_f64() * 1e6);
                    }
                    Err(_) => {
                        rx_errors += 1;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let elapsed = bench_start.elapsed().as_secs_f64();
    let total = latencies.len() as u64;
    let throughput = total as f64 / elapsed;

    println!("  RX: {} CAMs ({:.0}/s), errors: {}", total, throughput, rx_errors);

    let (lat_mean, lat_std, lat_p50, lat_p95, lat_p99, lat_min, lat_max) =
        compute_stats(&mut latencies);

    BenchmarkResult {
        run_id: args.run_id,
        platform: args.platform.clone(),
        security: args.security.clone(),
        benchmark: "rx".to_string(),
        duration_s: elapsed,
        total_cams: total,
        throughput,
        latency_mean: lat_mean,
        latency_std: lat_std,
        latency_p50: lat_p50,
        latency_p95: lat_p95,
        latency_p99: lat_p99,
        latency_min: lat_min,
        latency_max: lat_max,
        sign_latency_mean: 0.0,
    }
}

// ── Benchmark: Codec ────────────────────────────────────────────────────────
fn bench_codec(args: &Args) -> BenchmarkResult {
    let is_encode = args.mode == "codec-encode";
    let coder = CamCoder::new();
    let station_id = 12345u32;
    let template = make_cam(station_id);

    let encoded = coder
        .encode(&template)
        .expect("Failed to encode template CAM");
    println!("  CAM encoded size: {} bytes", encoded.len());

    // Warm-up
    println!("  Warm-up phase ({}s)...", args.warmup);
    let warmup_end = Instant::now() + Duration::from_secs(args.warmup);
    while Instant::now() < warmup_end {
        if is_encode {
            let _ = coder.encode(&template);
        } else {
            let _ = coder.decode(&encoded);
        }
    }

    // Measurement
    println!("  Measurement phase ({}s)...", args.duration);
    let mut latencies: Vec<f64> = Vec::with_capacity(5_000_000);
    let bench_start = Instant::now();
    let bench_end = bench_start + Duration::from_secs(args.duration);

    while Instant::now() < bench_end {
        let t0 = Instant::now();
        if is_encode {
            let _ = coder.encode(&make_cam(station_id));
        } else {
            let _ = coder.decode(&encoded);
        }
        let t1 = Instant::now();
        latencies.push(t1.duration_since(t0).as_secs_f64() * 1e6);
    }

    let elapsed = bench_start.elapsed().as_secs_f64();
    let total = latencies.len() as u64;
    let throughput = total as f64 / elapsed;

    let (lat_mean, lat_std, lat_p50, lat_p95, lat_p99, lat_min, lat_max) =
        compute_stats(&mut latencies);

    BenchmarkResult {
        run_id: args.run_id,
        platform: args.platform.clone(),
        security: "off".to_string(), // Security N/A for codec
        benchmark: args.mode.clone(),
        duration_s: elapsed,
        total_cams: total,
        throughput,
        latency_mean: lat_mean,
        latency_std: lat_std,
        latency_p50: lat_p50,
        latency_p95: lat_p95,
        latency_p99: lat_p99,
        latency_min: lat_min,
        latency_max: lat_max,
        sign_latency_mean: 0.0,
    }
}

// ── Benchmark: Security Layer (Sign / Verify) ──────────────────────────────
fn bench_security(args: &Args) -> BenchmarkResult {
    let is_sign = args.mode == "security-sign";
    let coder = CamCoder::new();
    let station_id = 12345u32;
    let template = make_cam(station_id);

    let encoded = coder.encode(&template).expect("Failed to encode template CAM");
    println!("  CAM payload size: {} bytes", encoded.len());

    // Build a realistic GN packet payload (CommonHeader + payload) to sign
    // This is what the sign middleware receives: everything after BasicHeader.
    // We use the raw encoded CAM as the tbs_message, matching the real stack path.
    let tbs_message = encoded.clone();

    let sign_svc = build_security_stack(args.at as usize, &args.certs_dir);

    // Pre-sign one message to get a signed envelope for the verify benchmark
    let signed_message = {
        let request = SNSignRequest {
            tbs_message: tbs_message.clone(),
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };
        let mut s = sign_svc.lock().unwrap();
        s.sign_request(&request).sec_message
    };
    println!("  Signed message size: {} bytes", signed_message.len());

    // Warm-up
    println!("  Warm-up phase ({}s)...", args.warmup);
    let warmup_end = Instant::now() + Duration::from_secs(args.warmup);
    if is_sign {
        while Instant::now() < warmup_end {
            let request = SNSignRequest {
                tbs_message: tbs_message.clone(),
                its_aid: 36,
                permissions: vec![],
                generation_location: None,
            };
            let mut s = sign_svc.lock().unwrap();
            let _ = s.sign_request(&request);
        }
    } else {
        while Instant::now() < warmup_end {
            let request = SNVerifyRequest {
                message: signed_message.clone(),
            };
            let mut s = sign_svc.lock().unwrap();
            let s = &mut *s;
            let _ = verify_message(&request, &s.backend, &mut s.cert_library);
        }
    }

    // Measurement
    println!("  Measurement phase ({}s)...", args.duration);
    let mut latencies: Vec<f64> = Vec::with_capacity(500_000);
    let bench_start = Instant::now();
    let bench_end = bench_start + Duration::from_secs(args.duration);

    if is_sign {
        while Instant::now() < bench_end {
            let request = SNSignRequest {
                tbs_message: tbs_message.clone(),
                its_aid: 36,
                permissions: vec![],
                generation_location: None,
            };
            let t0 = Instant::now();
            {
                let mut s = sign_svc.lock().unwrap();
                let _ = s.sign_request(&request);
            }
            let t1 = Instant::now();
            latencies.push(t1.duration_since(t0).as_secs_f64() * 1e6);
        }
    } else {
        while Instant::now() < bench_end {
            let request = SNVerifyRequest {
                message: signed_message.clone(),
            };
            let t0 = Instant::now();
            {
                let mut s = sign_svc.lock().unwrap();
                let s = &mut *s;
                let _ = verify_message(&request, &s.backend, &mut s.cert_library);
            }
            let t1 = Instant::now();
            latencies.push(t1.duration_since(t0).as_secs_f64() * 1e6);
        }
    }

    let elapsed = bench_start.elapsed().as_secs_f64();
    let total = latencies.len() as u64;
    let throughput = total as f64 / elapsed;

    let label = if is_sign { "Sign" } else { "Verify" };
    println!("  {}: {} ops ({:.0}/s)", label, total, throughput);

    let (lat_mean, lat_std, lat_p50, lat_p95, lat_p99, lat_min, lat_max) =
        compute_stats(&mut latencies);

    BenchmarkResult {
        run_id: args.run_id,
        platform: args.platform.clone(),
        security: "on".to_string(), // Security is the thing being measured
        benchmark: args.mode.clone(),
        duration_s: elapsed,
        total_cams: total,
        throughput,
        latency_mean: lat_mean,
        latency_std: lat_std,
        latency_p50: lat_p50,
        latency_p95: lat_p95,
        latency_p99: lat_p99,
        latency_min: lat_min,
        latency_max: lat_max,
        sign_latency_mean: lat_mean,
    }
}

// ── Main ────────────────────────────────────────────────────────────────────
fn main() {
    let args = Args::parse();

    println!("{}", "=".repeat(60));
    println!("FlexStack Benchmark — Rust (release, LTO)");
    println!("{}", "=".repeat(60));
    println!("  Mode     : {}", args.mode);
    println!("  Security : {}", args.security);
    if args.security == "on" {
        println!("  AT index : {}", args.at);
        println!("  Certs    : {}/", args.certs_dir);
    }
    println!("  Duration : {}s", args.duration);
    println!("  Warm-up  : {}s", args.warmup);
    println!("  Platform : {}", args.platform);
    println!("  Interface: {}", args.interface);
    println!("  Run ID   : {}", args.run_id);
    println!("  Output   : {}", args.output);
    println!();

    let result = match args.mode.as_str() {
        "tx" => bench_tx(&args),
        "rx" => bench_rx(&args),
        "concurrent" => bench_concurrent(&args),
        "codec-encode" | "codec-decode" => bench_codec(&args),
        "security-sign" | "security-verify" => bench_security(&args),
        _ => {
            eprintln!("Unknown mode: {}", args.mode);
            std::process::exit(1);
        }
    };

    write_csv_row(&args.output, &result);

    println!();
    println!("  Results:");
    println!("    Total        : {}", result.total_cams);
    println!("    Throughput   : {:.1} CAMs/s", result.throughput);
    println!("    Latency mean : {:.2} μs", result.latency_mean);
    println!("    Latency p50  : {:.2} μs", result.latency_p50);
    println!("    Latency p95  : {:.2} μs", result.latency_p95);
    println!("    Latency p99  : {:.2} μs", result.latency_p99);
    println!("  Written to: {}", args.output);
}
