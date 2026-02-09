//! Chaos-style integration tests for HorizonClient reliability.
//!
//! Scenarios:
//! - Hub downtime with queued signal recovery
//! - High-latency hub acknowledgments (non-blocking reporting)
//! - Network partition with inflight requeue

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use tokio_tungstenite::{accept_async, tungstenite::Message};

use synapse_pingora::horizon::{
    ConnectionState, HorizonClient, HorizonConfig, HubMessage, SensorMessage, Severity, SignalType,
    ThreatSignal,
};

struct HubServer {
    addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
    received: Arc<Mutex<Vec<ThreatSignal>>>,
}

impl HubServer {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.handle).await;
    }
}

async fn spawn_hub_server(
    port: Option<u16>,
    ack_delay: Duration,
    disconnect_after_signals: Option<usize>,
) -> HubServer {
    let bind_addr = match port {
        Some(port) => format!("127.0.0.1:{}", port),
        None => "127.0.0.1:0".to_string(),
    };

    let listener = TcpListener::bind(&bind_addr)
        .await
        .expect("bind hub server");
    let addr = listener.local_addr().expect("hub server addr");
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let received = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    break;
                }
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        let received_inner = Arc::clone(&received_clone);
                        let mut connection_shutdown = shutdown_rx.clone();
                        tokio::spawn(async move {
                            if let Ok(ws_stream) = accept_async(stream).await {
                                let (mut sink, mut stream) = ws_stream.split();
                                let mut signal_count: usize = 0;

                                loop {
                                    tokio::select! {
                                        _ = connection_shutdown.changed() => {
                                            let _ = sink.close().await;
                                            break;
                                        }
                                        msg = stream.next() => {
                                            match msg {
                                                Some(Ok(Message::Text(text))) => {
                                                    let parsed = serde_json::from_str::<SensorMessage>(&text);
                                                    if let Ok(sensor_msg) = parsed {
                                                        match sensor_msg {
                                                            SensorMessage::Auth { .. } => {
                                                                let auth_success = HubMessage::AuthSuccess {
                                                                    sensor_id: "sensor-1".to_string(),
                                                                    tenant_id: "tenant-1".to_string(),
                                                                    capabilities: vec!["signals".to_string()],
                                                                    protocol_version: Some("1.0".to_string()),
                                                                };
                                                                let _ = sink.send(Message::Text(serde_json::to_string(&auth_success).unwrap().into())).await;
                                                            }
                                                            SensorMessage::Signal { payload } => {
                                                                signal_count += 1;
                                                                received_inner.lock().await.push(payload);

                                                                if disconnect_after_signals.map_or(false, |limit| signal_count >= limit) {
                                                                    let _ = sink.close().await;
                                                                    break;
                                                                }

                                                                if ack_delay > Duration::from_secs(0) {
                                                                    tokio::time::sleep(ack_delay).await;
                                                                }
                                                                let ack = HubMessage::SignalAck { sequence_id: 1 };
                                                                let _ = sink.send(Message::Text(serde_json::to_string(&ack).unwrap().into())).await;
                                                            }
                                                            SensorMessage::SignalBatch { payload } => {
                                                                let batch_count = payload.len();
                                                                signal_count += batch_count;
                                                                received_inner.lock().await.extend(payload);

                                                                if disconnect_after_signals.map_or(false, |limit| signal_count >= limit) {
                                                                    let _ = sink.close().await;
                                                                    break;
                                                                }

                                                                if ack_delay > Duration::from_secs(0) {
                                                                    tokio::time::sleep(ack_delay).await;
                                                                }
                                                                let ack = HubMessage::BatchAck { count: batch_count as u32, sequence_id: 1 };
                                                                let _ = sink.send(Message::Text(serde_json::to_string(&ack).unwrap().into())).await;
                                                            }
                                                            SensorMessage::BlocklistSync => {
                                                                let snapshot = HubMessage::BlocklistSnapshot { entries: vec![], sequence_id: 1 };
                                                                let _ = sink.send(Message::Text(serde_json::to_string(&snapshot).unwrap().into())).await;
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                }
                                                Some(Ok(Message::Close(_))) => break,
                                                Some(Ok(_)) => {},
                                                Some(Err(_)) | None => break,
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    HubServer {
        addr,
        shutdown_tx,
        handle,
        received,
    }
}

fn test_config(url: &str) -> HorizonConfig {
    let mut config = HorizonConfig::default()
        .with_hub_url(url)
        .with_api_key("test-key")
        .with_sensor_id("sensor-1")
        .with_reconnect_delay_ms(100)
        .with_batch_size(1)
        .with_heartbeat_interval_ms(5_000);
    config.signal_batch_delay_ms = 25;
    config.max_queued_signals = 100;
    config.circuit_breaker_threshold = 0;
    config
}

fn make_signal(ip: &str) -> ThreatSignal {
    ThreatSignal::new(SignalType::IpThreat, Severity::High)
        .with_source_ip(ip)
        .with_confidence(0.9)
}

async fn wait_for_state(
    client: &HorizonClient,
    desired: ConnectionState,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if client.connection_state().await == desired {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn wait_for_received(
    received: &Arc<Mutex<Vec<ThreatSignal>>>,
    expected: usize,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if received.lock().await.len() >= expected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn test_hub_downtime_requeues_signals() {
    let server = spawn_hub_server(None, Duration::from_millis(0), None).await;
    let port = server.addr.port();
    let url = format!("ws://{}", server.addr);

    let mut client = HorizonClient::new(test_config(&url));
    client.start().await.expect("client start");
    assert!(wait_for_state(&client, ConnectionState::Connected, Duration::from_secs(5)).await);

    client.report_signal(make_signal("10.0.0.1"));
    assert!(wait_for_received(&server.received, 1, Duration::from_secs(2)).await);

    server.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    client.report_signal(make_signal("10.0.0.2"));
    client.report_signal(make_signal("10.0.0.3"));

    let server_restarted = spawn_hub_server(Some(port), Duration::from_millis(0), None).await;
    assert!(wait_for_state(&client, ConnectionState::Connected, Duration::from_secs(5)).await);
    assert!(wait_for_received(&server_restarted.received, 2, Duration::from_secs(3)).await);

    let ips: Vec<String> = {
        let received = server_restarted.received.lock().await;
        received
            .iter()
            .filter_map(|signal| signal.source_ip.clone())
            .collect()
    };
    assert!(ips.contains(&"10.0.0.2".to_string()));
    assert!(ips.contains(&"10.0.0.3".to_string()));

    client.stop().await;
    server_restarted.shutdown().await;
}

#[tokio::test]
async fn test_high_latency_hub_does_not_block_reporting() {
    let server = spawn_hub_server(None, Duration::from_millis(300), None).await;
    let url = format!("ws://{}", server.addr);

    let mut client = HorizonClient::new(test_config(&url));
    client.start().await.expect("client start");
    assert!(wait_for_state(&client, ConnectionState::Connected, Duration::from_secs(5)).await);

    let start = Instant::now();
    client.report_signal(make_signal("10.0.1.1"));
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(50),
        "report_signal should be non-blocking"
    );
    assert!(wait_for_received(&server.received, 1, Duration::from_secs(2)).await);

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn test_network_partition_requeues_inflight() {
    let server = spawn_hub_server(None, Duration::from_millis(0), Some(1)).await;
    let port = server.addr.port();
    let url = format!("ws://{}", server.addr);

    let mut client = HorizonClient::new(test_config(&url));
    client.start().await.expect("client start");
    assert!(wait_for_state(&client, ConnectionState::Connected, Duration::from_secs(5)).await);

    client.report_signal(make_signal("10.0.2.1"));
    assert!(wait_for_received(&server.received, 1, Duration::from_secs(2)).await);

    server.shutdown().await;

    let server_restarted = spawn_hub_server(Some(port), Duration::from_millis(0), None).await;
    assert!(wait_for_state(&client, ConnectionState::Connected, Duration::from_secs(5)).await);
    assert!(wait_for_received(&server_restarted.received, 1, Duration::from_secs(3)).await);

    let ips: Vec<String> = {
        let received = server_restarted.received.lock().await;
        received
            .iter()
            .filter_map(|signal| signal.source_ip.clone())
            .collect()
    };
    assert!(ips.contains(&"10.0.2.1".to_string()));

    client.stop().await;
    server_restarted.shutdown().await;
}
