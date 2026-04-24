// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
//!
//! FlexStack Benchmark — Rust (C-V2X link layer)
//!
//! Adaptation of the FlexStack benchmark harness for Cohda MK6 hardware
//! using the C-V2X radio link layer instead of raw Ethernet.
//!
//! CAMs are transmitted via the SPS (Semi-Persistent Scheduling) flow.
//! The C-V2X radio manages its own interface — no network interface argument
//! is required.
//!
//! # Building (cross-compile for MK6)
//! ```text
//! cd cohda-toolchain && ./build-cv2x.sh --release --bin flexstack-bench-cv2x
//! ```
//!
//! # Running (on MK6 device)
//! ```text
//! ./flexstack-bench-cv2x --mode tx --security off --duration 60
//! ./flexstack-bench-cv2x --mode rx --security off --duration 60
//! ```

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
use rustflexstack::link_layer::cv2x_link_layer::Cv2xLinkLayer;
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
    name = "flexstack-bench-cv2x",
    about = "FlexStack Benchmark — Rust (C-V2X link layer)",
    long_about = "Benchmark harness for RustFlexStack on Cohda MK6 hardware using C-V2X radio.\n\nModes:\n  tx              Send CAMs at max rate over C-V2X, measure wire throughput\n  rx              Receive-only: listen for CAMs over C-V2X and measure RX throughput\n  codec-encode    ASN.1 CAM encode throughput (in-memory)\n  codec-decode    ASN.1 CAM decode throughput (in-memory)\n  security-sign   ECDSA-P256 signing throughput (in-memory)\n  security-verify ECDSA-P256 verification throughput (in-memory)\n\nCross-machine example:\n  Device A (sender):   ./flexstack-bench-cv2x --mode tx\n  Device B (receiver): ./flexstack-bench-cv2x --mode rx"
)]
struct Args {
    /// Benchmark mode
    #[arg(long, value_parser = ["tx", "rx", "codec-encode", "codec-decode", "security-sign", "security-verify"])]
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
    #[arg(long, default_value = "mk6", value_parser = ["mk6", "mk6c", "mk6-ag550"])]
    platform: String,

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
            "{},rust-cv2x,{},{},{},{:.3},{},{:.1},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}",
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

/// Spawn a complete stack: GN + BTP + C-V2X LinkLayer, with optional security middleware.
/// Returns (gn_handle, btp_handle, stop_flag, ll_rx_join, ll_tx_join).
/// Call stop_flag.store(true) then join both handles for a graceful C-V2X flow shutdown.
/// If `tx_wire_counter` is Some, it is incremented each time a packet is handed to the LL (TX).
/// If `rx_wire_counter` is Some, it is incremented each time a raw packet arrives from the radio (RX).
fn spawn_stack(
    mib: Mib,
    _mac: [u8; 6],
    sign_svc: Option<Arc<Mutex<SignService>>>,
    tx_wire_counter: Option<Arc<AtomicU64>>,
    rx_wire_counter: Option<Arc<AtomicU64>>,
) -> (RouterHandle, BTPRouterHandle, Arc<AtomicBool>, thread::JoinHandle<()>, thread::JoinHandle<()>) {
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();

    // The channel that the C-V2X link layer will read from for TX
    let ll_tx_source: mpsc::Receiver<Vec<u8>>;

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
        ll_tx_source = secured_ll_rx;

        // ── RX path: LL → verify → GN ───────────────────────────────────
        let g1 = gn_handle.clone();
        let verify_svc = svc;
        let rx_cnt_sec = rx_wire_counter;
        thread::spawn(move || {
            while let Ok(packet) = ll_to_gn_rx.recv() {
                if let Some(ref c) = rx_cnt_sec { c.fetch_add(1, Ordering::Relaxed); }
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
            let (counted_ll_tx, counted_ll_rx) = mpsc::channel::<Vec<u8>>();
            thread::spawn(move || {
                while let Ok(packet) = gn_to_ll_rx.recv() {
                    cnt.fetch_add(1, Ordering::Relaxed);
                    let _ = counted_ll_tx.send(packet);
                }
            });
            ll_tx_source = counted_ll_rx;
        } else {
            ll_tx_source = gn_to_ll_rx;
        }

        let g1 = gn_handle.clone();
        let rx_cnt_plain = rx_wire_counter;
        thread::spawn(move || {
            while let Ok(p) = ll_to_gn_rx.recv() {
                if let Some(ref c) = rx_cnt_plain { c.fetch_add(1, Ordering::Relaxed); }
                g1.send_incoming_packet(p);
            }
        });
    }

    // Wire C-V2X link layer (no interface argument needed)
    let cv2x_ll = Cv2xLinkLayer::new(ll_to_gn_tx, ll_tx_source);
    let (stop_flag, ll_rx_join, ll_tx_join) = cv2x_ll.start();

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

    (gn_handle, btp_handle, stop_flag, ll_rx_join, ll_tx_join)
}

// ── Security setup ──────────────────────────────────────────────────────────
/// Build the security stack by loading certificate files from `certs_dir`.
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

// ── Benchmark: TX Throughput (C-V2X) ────────────────────────────────────────
fn bench_tx(args: &Args) -> BenchmarkResult {
    let mac = random_mac();
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let security_on = args.security == "on";

    let wire_counter = Arc::new(AtomicU64::new(0));
    let sign_svc = if security_on { Some(build_security_stack(args.at as usize, &args.certs_dir)) } else { None };
    let (gn_handle, btp_handle, stop_flag, ll_rx_join, ll_tx_join) = spawn_stack(mib, mac, sign_svc, Some(Arc::clone(&wire_counter)), None);

    // Seed position vector
    let mut epv = LongPositionVector::decode([0u8; 24]);
    epv.update_from_gps(41.552, 2.134, 0.0, 0.0, true);
    gn_handle.update_position_vector(epv);
    thread::sleep(Duration::from_millis(50));

    let coder = CamCoder::new();
    let template = make_cam(station_id);

    // Warm-up: rate-limited to ~10 Hz so the router queue doesn't overflow and
    // pollute the measurement phase with backlogged packets.
    println!("  Warm-up phase ({}s)...", args.warmup);
    let warmup_end = Instant::now() + Duration::from_secs(args.warmup);
    while Instant::now() < warmup_end {
        if let Ok(data) = coder.encode(&template) {
            btp_handle.send_btp_data_request(cam_btp_request(data, security_on));
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Drain any remaining queued packets from warm-up before measurement.
    thread::sleep(Duration::from_millis(500));

    // Measurement
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

    println!("  TX: {} CAMs ({:.0}/s)", total, throughput);

    let (lat_mean, lat_std, lat_p50, lat_p95, lat_p99, lat_min, lat_max) =
        compute_stats(&mut latencies);

    // Graceful C-V2X shutdown:
    // 1. stop_flag signals the CV2X RX thread (poll loop checks every 100ms).
    // 2. gn_handle.shutdown() sends RouterInput::Shutdown to the GN router, causing it to
    //    exit its run() loop and drop link_layer_tx. This closes the GN→LL TX bridging
    //    thread, which drops the CV2X LL's gn_rx sender → CV2X TX thread exits.
    //    (Simply dropping gn_handle is insufficient because the beacon timer thread holds
    //    a clone of input_tx, keeping the router alive indefinitely.)
    eprintln!("tearing down C-V2X flows...");
    stop_flag.store(true, Ordering::SeqCst);
    gn_handle.shutdown();
    btp_handle.shutdown();
    let _ = ll_rx_join.join(); // exits within ~100ms via poll timeout + stop_flag
    let _ = ll_tx_join.join(); // exits once GN router closes the link_layer_tx chain
    eprintln!("shutdown complete");

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

// ── Benchmark: RX Throughput (C-V2X, receive-only) ──────────────────────────
fn bench_rx(args: &Args) -> BenchmarkResult {
    let rx_mac = random_mac();
    let mut rx_mib = Mib::new();
    rx_mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(rx_mac));
    rx_mib.itsGnBeaconServiceRetransmitTimer = 0;
    let security_on = args.security == "on";

    let sign_svc = if security_on { Some(build_security_stack(args.at as usize, &args.certs_dir)) } else { None };
    let rx_ll_counter = Arc::new(AtomicU64::new(0));
    let (rx_gn, rx_btp, stop_flag, ll_rx_join, ll_tx_join) = spawn_stack(rx_mib, rx_mac, sign_svc, None, Some(Arc::clone(&rx_ll_counter)));

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
            Ok(_) => { warmup_count += 1; }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
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
                let t0 = Instant::now();
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

    let ll_rx_count = rx_ll_counter.load(Ordering::SeqCst);
    println!("  RX radio: {} raw frames from C-V2X radio", ll_rx_count);
    println!("  RX stack: {} CAMs delivered to BTP ({:.0}/s), errors: {}", total, throughput, rx_errors);
    if ll_rx_count == 0 {
        eprintln!("  [WARN] No packets received from C-V2X radio. Is the remote TX device running?");
    } else if total == 0 {
        eprintln!("  [WARN] {} raw frames received but 0 CAMs decoded — GN/BTP may be dropping packets.", ll_rx_count);
    }

    let (lat_mean, lat_std, lat_p50, lat_p95, lat_p99, lat_min, lat_max) =
        compute_stats(&mut latencies);

    // Same shutdown sequence as bench_tx: explicit shutdown() calls are required so the GN
    // router exits despite the beacon timer thread holding a live clone of input_tx.
    eprintln!("tearing down C-V2X flows...");
    stop_flag.store(true, Ordering::SeqCst);
    rx_gn.shutdown();
    rx_btp.shutdown();
    let _ = ll_rx_join.join(); // exits within ~100ms via poll timeout + stop_flag
    let _ = ll_tx_join.join(); // exits once GN router closes the link_layer_tx chain
    eprintln!("shutdown complete");

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
        security: "off".to_string(),
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
        security: "on".to_string(),
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
    println!("FlexStack Benchmark — Rust C-V2X (release, LTO)");
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
    println!("  Run ID   : {}", args.run_id);
    println!("  Output   : {}", args.output);
    println!();

    let result = match args.mode.as_str() {
        "tx" => bench_tx(&args),
        "rx" => bench_rx(&args),
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
