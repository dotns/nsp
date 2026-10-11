//! Netstack backend end to end, without TUN or privileges.
//!
//! A client engine on its own user-space stack serves TCP and UDP echo
//! at its tunnel address. The host reaches it through the backend's
//! SOCKS5 listener (CONNECT and UDP ASSOCIATE, with credentials) and
//! through TCP and UDP port forwards; the client pings the backend's
//! stack address. Everything runs over real UDP on loopback.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use futures::StreamExt;
use nsp_wg_driver::{
    BackendBringUp, BackendKind, BackendPeer, NetstackOptions, PortForward, Socks5Auth,
    UserspaceBackend, WgBackend,
};
use nsplane::{
    AllowedIp, EngineBuilder, MapSink, MapVerdict, PacketBuf, Path, Peer, TransportId, UdpTransport,
};
use nsplane_netstack::{NetStack, NetStackConfig};
use nsplane_packet::checksum::{internet_checksum, ipv4_header_checksum};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const ECHO_PORT: u16 = 7;
const TIMEOUT: Duration = Duration::from_secs(10);

fn free_tcp() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A port free for both TCP and UDP on `ip`.
fn free_port(ip: &str) -> u16 {
    loop {
        let port = TcpListener::bind((ip, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if std::net::UdpSocket::bind((ip, port)).is_ok() {
            return port;
        }
    }
}

fn free_udp() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn tcp_roundtrip(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut back))
        .await
        .expect("TCP echo timed out")
        .unwrap();
    assert_eq!(back, payload);
}

async fn recv_udp(socket: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let len = tokio::time::timeout(TIMEOUT, socket.recv(&mut buf))
        .await
        .expect("UDP echo timed out")
        .unwrap();
    buf.truncate(len);
    buf
}

/// An IPv4 ICMP echo request from the client to the server's stack.
fn echo_request(seq: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"ping payload");
    let sum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let total = (20 + icmp.len()) as u16;
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0, 64, 1, 0, 0]);
    packet.extend_from_slice(&CLIENT_IP.octets());
    packet.extend_from_slice(&SERVER_IP.octets());
    let sum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&icmp);
    packet
}

/// Socks5 greeting, credentials and a request with an IPv4 address;
/// asserts success and returns the bound address.
async fn socks5_request(s: &mut TcpStream, cmd: u8, addr: SocketAddr) -> SocketAddr {
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let mut auth = vec![1, 5];
    auth.extend_from_slice(b"alice");
    auth.push(6);
    auth.extend_from_slice(b"s3cret");
    s.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    s.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0], "SOCKS5 auth rejected");
    let SocketAddr::V4(v4) = addr else {
        unreachable!()
    };
    let mut request = vec![5, cmd, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut reply))
        .await
        .expect("SOCKS5 reply timed out")
        .unwrap();
    assert_eq!(reply[..2], [5, 0], "SOCKS5 request failed: {reply:?}");
    SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_reaches_tunnel_services_and_peers_ping_the_stack() {
    let server_key = StaticSecret::random();
    let client_key = StaticSecret::random();
    let server_udp = free_udp();
    let client_udp = free_udp();
    let socks5 = free_tcp();
    let tcp_forward = free_tcp();
    let udp_forward = free_udp();
    let echo = SocketAddr::from((CLIENT_IP, ECHO_PORT));
    // A whole-address mapping: two ports of 127.0.0.2 to the same ports
    // of the client (its stack echoes on any port).
    let (a, b) = (free_port("127.0.0.2"), free_port("127.0.0.2"));
    let mapped = PortForward::parse_spec(&format!("127.0.0.2:{a},{b}=10.77.0.2")).unwrap();
    assert_eq!(mapped.len(), 2);

    // Server: the netstack backend, owning 10.77.0.1.
    let backend = UserspaceBackend::new().with_netstack(NetstackOptions {
        socks5: Some(socks5),
        socks5_auth: Some(Socks5Auth {
            username: "alice".into(),
            password: SecretString::from("s3cret"),
        }),
        forwards: [
            vec![PortForward {
                listen: tcp_forward,
                target: echo,
            }],
            mapped.clone(),
        ]
        .concat(),
        udp_forwards: [
            vec![PortForward {
                listen: udp_forward,
                target: echo,
            }],
            mapped.clone(),
        ]
        .concat(),
    });
    assert_eq!(backend.kind(), BackendKind::Netstack);
    assert!(backend.availability().available);
    backend
        .up(BackendBringUp {
            interface: "unused".into(),
            listen_port: server_udp.port(),
            server_private_key: server_key.to_bytes(),
            subnet: Some("10.77.0.0/24".parse().unwrap()),
            initial_peers: vec![BackendPeer {
                public_key: PublicKey::from(&client_key).to_bytes(),
                allowed_ip: CLIENT_IP,
                endpoint: Some(client_udp),
                keepalive: None,
                preshared_key: None,
            }],
        })
        .await
        .expect("netstack backend up");

    // Client: an engine on its own stack echoing TCP and UDP on port 7;
    // echo replies (which the stack ignores) are captured on the way in.
    let (stack, net) = NetStack::new(NetStackConfig::new(vec![(CLIENT_IP.into(), 24)], 1420));
    let (source, sink) = stack.split();
    let (pong_tx, mut pongs) = mpsc::unbounded_channel();
    let sink = MapSink::new(sink, move |packet: &mut PacketBuf, _| {
        let bytes = packet.as_packet();
        if bytes.len() > 20 && bytes[9] == 1 && bytes[20] == 0 {
            let _ = pong_tx.send(bytes.to_vec());
            return MapVerdict::Drop;
        }
        MapVerdict::Keep
    });
    let client = EngineBuilder::new(source, sink)
        .private_key(client_key)
        .transport(UdpTransport::bind(TransportId::new(0), client_udp).unwrap())
        .build()
        .unwrap();
    let mut server_peer = Peer::new(PublicKey::from(&server_key));
    server_peer.allowed_ips = vec!["10.77.0.0/24".parse::<AllowedIp>().unwrap()];
    server_peer.path = Some(Path {
        transport: TransportId::new(0),
        addr: SocketAddr::from((Ipv4Addr::LOCALHOST, server_udp.port())),
        ecn: nsplane::Ecn::NotEct,
    });
    let client_handle = client.handle();
    client_handle.add_or_update_peer(server_peer).await.unwrap();
    let mut incoming = net.incoming_tcp();
    tokio::spawn(async move {
        while let Some(mut conn) = incoming.next().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = conn.read(&mut buf).await {
                    if n == 0 || conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let mut flows = net.incoming_udp();
    tokio::spawn(async move {
        while let Some(mut flow) = flows.next().await {
            tokio::spawn(async move {
                while let Some(payload) = flow.recv().await {
                    if flow.send(&payload).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // SOCKS5 CONNECT with credentials; the bound address is the stack's.
    let mut s = TcpStream::connect(socks5).await.unwrap();
    let bound = socks5_request(&mut s, 1, echo).await;
    assert_eq!(bound.ip(), SERVER_IP);
    tcp_roundtrip(&mut s, b"through socks5").await;

    // Wrong credentials are refused.
    let mut bad = TcpStream::connect(socks5).await.unwrap();
    bad.write_all(&[5, 1, 2, 1, 5]).await.unwrap();
    bad.write_all(b"alice").await.unwrap();
    bad.write_all(&[5]).await.unwrap();
    bad.write_all(b"wrong").await.unwrap();
    let mut answer = [0u8; 4];
    bad.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, [5, 2, 1, 1]);

    // SOCKS5 UDP ASSOCIATE.
    let mut control = TcpStream::connect(socks5).await.unwrap();
    let relay = socks5_request(&mut control, 3, SocketAddr::from(([0, 0, 0, 0], 0))).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&CLIENT_IP.octets());
    datagram.extend_from_slice(&ECHO_PORT.to_be_bytes());
    datagram.extend_from_slice(b"udp through socks5");
    udp.send_to(
        &datagram,
        SocketAddr::from((Ipv4Addr::LOCALHOST, relay.port())),
    )
    .await
    .unwrap();
    let back = recv_udp(&udp).await;
    assert_eq!(back, datagram, "reply carries the source header");
    drop(control);

    // TCP and UDP port forwards.
    let mut f = TcpStream::connect(tcp_forward).await.unwrap();
    tcp_roundtrip(&mut f, b"through the TCP forward").await;
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    u.send_to(b"through the UDP forward", udp_forward)
        .await
        .unwrap();
    assert_eq!(recv_udp(&u).await, b"through the UDP forward");

    // 127.0.0.2:{a,b} reach the same ports of the client, TCP and UDP.
    for port in [a, b] {
        let local = SocketAddr::from(([127, 0, 0, 2], port));
        let mut t = TcpStream::connect(local).await.unwrap();
        tcp_roundtrip(&mut t, format!("tcp {port}").as_bytes()).await;
        let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        u.send_to(format!("udp {port}").as_bytes(), local)
            .await
            .unwrap();
        assert_eq!(recv_udp(&u).await, format!("udp {port}").as_bytes());
    }

    // The client pings the server's stack address.
    client_handle
        .inject_outbound(PacketBuf::from_packet(&echo_request(1)))
        .await
        .unwrap();
    let pong = tokio::time::timeout(TIMEOUT, pongs.recv())
        .await
        .expect("no echo reply")
        .unwrap();
    assert_eq!(pong[12..16], SERVER_IP.octets(), "reply from the stack");
    assert_eq!(pong[16..20], CLIENT_IP.octets());
    assert!(pong.ends_with(b"ping payload"));

    let stats = backend.list_peer_stats().await.unwrap();
    assert_eq!(stats.len(), 1);
    assert!(stats[0].rx_bytes > 0 && stats[0].tx_bytes > 0);
    assert!(stats[0].last_handshake.is_some());

    backend.down().await.unwrap();
    assert!(!backend.is_running().await);
    assert!(
        TcpStream::connect(socks5).await.is_err(),
        "SOCKS5 listener closed on down"
    );
}

#[tokio::test]
async fn netstack_backend_needs_a_subnet() {
    let backend = UserspaceBackend::new().with_netstack(NetstackOptions::default());
    let err = backend
        .up(BackendBringUp {
            interface: "unused".into(),
            listen_port: free_udp().port(),
            server_private_key: StaticSecret::random().to_bytes(),
            subnet: None,
            initial_peers: Vec::new(),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("subnet"), "{err}");
}
