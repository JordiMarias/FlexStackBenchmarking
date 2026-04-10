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
use std::path::PathBuf;
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
use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;
use rustflexstack::security::sn_sap::{ReportVerify, SNSignRequest, SNVerifyRequest, SecurityProfile};

// Security imports
use rustflexstack::security::certificate::OwnCertificate;
use rustflexstack::security::certificate_library::CertificateLibrary;
use rustflexstack::security::ecdsa_backend::EcdsaBackend;
use rustflexstack::security::sign_service::SignService;
use rustflexstack::security::verify_service::{verify_message, VerifyEvent};

// ASN.1 types for certificate generation
use rasn::prelude::*;
use rustflexstack::security::security_asn::ieee1609_dot2::{
    CertificateId, EndEntityType, PsidGroupPermissions, PsidSsp,
    SequenceOfAppExtensions, SequenceOfCertIssueExtensions, SequenceOfCertRequestExtensions,
    SequenceOfPsidGroupPermissions, SequenceOfPsidSsp, SubjectPermissions,
    ToBeSignedCertificate as TbsCert, VerificationKeyIndicator,
};
use rustflexstack::security::security_asn::ieee1609_dot2_base_types::{
    CrlSeries, Duration as AsnDuration, EccP256CurvePoint, HashedId3,
    Psid as AsnPsid, PublicVerificationKey, Time32, Uint16, Uint32, ValidityPeriod,
};

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

    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();

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
            while let Ok(packet) = ll_to_gn_rx.recv() {
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
            // Intercept GN→LL to count packets
            let (counted_ll_tx, counted_ll_rx) = mpsc::channel::<Vec<u8>>();
            thread::spawn(move || {
                while let Ok(packet) = gn_to_ll_rx.recv() {
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
            while let Ok(p) = ll_to_gn_rx.recv() {
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
fn make_root_tbs() -> TbsCert {
    let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(30)));
    let perms = SequenceOfPsidGroupPermissions(vec![PsidGroupPermissions::new(
        SubjectPermissions::all(()),
        Integer::from(1),
        Integer::from(0),
        {
            let mut bits = FixedBitString::<8>::default();
            bits.set(0, true);
            EndEntityType(bits)
        },
    )]);
    let placeholder_pk =
        PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));
    TbsCert::new(
        CertificateId::none(()),
        HashedId3(FixedOctetString::from([0u8; 3])),
        CrlSeries(Uint16(0)),
        validity,
        None, None,
        Some(SequenceOfPsidSsp(vec![PsidSsp::new(AsnPsid(Integer::from(36_i64)), None)])),
        Some(perms),
        None, None, None,
        VerificationKeyIndicator::verificationKey(placeholder_pk),
        None,
        SequenceOfAppExtensions(vec![]),
        SequenceOfCertIssueExtensions(vec![]),
        SequenceOfCertRequestExtensions(vec![]),
    )
}

fn make_at_tbs() -> TbsCert {
    let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(10)));
    let app_perms = SequenceOfPsidSsp(vec![
        PsidSsp::new(AsnPsid(Integer::from(36_i64)), None),
        PsidSsp::new(AsnPsid(Integer::from(37_i64)), None),
    ]);
    let placeholder_pk =
        PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));
    TbsCert::new(
        CertificateId::none(()),
        HashedId3(FixedOctetString::from([0u8; 3])),
        CrlSeries(Uint16(0)),
        validity,
        None, None,
        Some(app_perms),
        None, None, None, None,
        VerificationKeyIndicator::verificationKey(placeholder_pk),
        None,
        SequenceOfAppExtensions(vec![]),
        SequenceOfCertIssueExtensions(vec![]),
        SequenceOfCertRequestExtensions(vec![]),
    )
}

fn setup_security() -> Arc<Mutex<SignService>> {
    let mut backend = EcdsaBackend::new();

    // Generate certificate chain in-memory
    let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
    let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
    let at1 = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &aa);
    let at2 = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &aa);

    let cert_lib = CertificateLibrary::new(
        &backend,
        vec![root.cert],
        vec![aa.cert],
        vec![at1.cert.clone(), at2.cert],
    );

    let mut sign_service = SignService::new(backend, cert_lib);
    sign_service.add_own_certificate(at1);

    Arc::new(Mutex::new(sign_service))
}

/// Create two independent SignService instances sharing the same cert chain.
/// TX gets at1 for signing, RX gets at2. Both can verify each other's packets.
/// Separate backends = no Mutex contention between stacks.
fn setup_security_pair() -> (Arc<Mutex<SignService>>, Arc<Mutex<SignService>>) {
    let mut backend = EcdsaBackend::new();

    let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
    let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
    let at1 = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &aa);
    let at2 = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &aa);

    // TX service — signs with at1
    let tx_cert_lib = CertificateLibrary::new(
        &backend,
        vec![root.cert.clone()],
        vec![aa.cert.clone()],
        vec![at1.cert.clone(), at2.cert.clone()],
    );
    let mut tx_sign = SignService::new(backend, tx_cert_lib);
    tx_sign.add_own_certificate(at1);

    // RX service — independent backend, same cert chain for verification, signs with at2
    let mut rx_backend = EcdsaBackend::new();
    let rx_root = OwnCertificate::initialize_self_signed(&mut rx_backend, make_root_tbs());
    let rx_aa = OwnCertificate::initialize_issued(&mut rx_backend, make_root_tbs(), &rx_root);
    let rx_at2 = OwnCertificate::initialize_issued(&mut rx_backend, make_at_tbs(), &rx_aa);

    let rx_cert_lib = CertificateLibrary::new(
        &rx_backend,
        vec![root.cert, rx_root.cert],
        vec![aa.cert, rx_aa.cert],
        vec![at2.cert, rx_at2.cert.clone()],
    );
    let mut rx_sign = SignService::new(rx_backend, rx_cert_lib);
    rx_sign.add_own_certificate(rx_at2);

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
    let sign_svc = if security_on { Some(setup_security()) } else { None };
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
        let (tx, rx) = setup_security_pair();
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

    // RX thread
    {
        let cnt = rx_count.clone();
        let err = rx_errors.clone();
        let stop = stop_flag.clone();
        thread::spawn(move || {
            let coder = CamCoder::new();
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match cam_ind_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(ind) => {
                        match coder.decode(&ind.data) {
                            Ok(_) => {
                                cnt.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                err.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
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

    let sign_svc = if security_on { Some(setup_security()) } else { None };
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

    let sign_svc = setup_security();

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
