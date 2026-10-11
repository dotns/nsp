//! Host-side access to the tunnel for the netstack backend.
//!
//! With no TUN device the host kernel cannot route into the tunnel,
//! so the backend serves it through the user-space stack instead:
//!
//! - a SOCKS5 listener (RFC 1928, optional RFC 1929 username/password)
//!   whose CONNECT and UDP ASSOCIATE requests are served from the stack,
//! - TCP and UDP port forwards from a local address to a tunnel address,
//! - echo replies, so tunnel peers can ping the stack's address.
//!
//! TCP connections the tunnel peers open to the stack are reset and
//! their UDP flows dropped: nothing listens on the stack itself.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nsplane::{
    ChannelSource, MapSink, MapVerdict, MergeSource, PacketBuf, PacketSink, PacketSource,
};
use nsplane_netstack::{NetStack, NetStackHandle};
use nsplane_packet::icmp::{echo_reply_in_place, is_echo_request};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::{Result, WgError};

/// Echo replies waiting for the engine; more are dropped.
const ECHO_QUEUE: usize = 64;

/// A UDP forward session or SOCKS5 association idle this long is closed.
const UDP_IDLE: Duration = Duration::from_mins(1);

/// Datagrams queued per UDP forward session; more are dropped.
const UDP_SESSION_QUEUE: usize = 64;

/// Largest UDP payload relayed.
const UDP_BUFFER: usize = 65_535;

/// What the netstack backend serves on the host.
#[derive(Debug, Clone, Default)]
pub struct NetstackOptions {
    /// SOCKS5 listener.
    pub socks5: Option<SocketAddr>,
    /// Credentials SOCKS5 clients must present; `None` takes anyone.
    pub socks5_auth: Option<Socks5Auth>,
    /// TCP port forwards into the tunnel.
    pub forwards: Vec<PortForward>,
    /// UDP port forwards into the tunnel.
    pub udp_forwards: Vec<PortForward>,
}

/// SOCKS5 username/password (RFC 1929).
#[derive(Debug, Clone)]
pub struct Socks5Auth {
    pub username: String,
    pub password: SecretString,
}

impl Socks5Auth {
    fn accepts(&self, username: &[u8], password: &[u8]) -> bool {
        let user = self.username.as_bytes().ct_eq(username);
        let pass = self.password.expose_secret().as_bytes().ct_eq(password);
        (user & pass).into()
    }
}

/// A port forward: traffic to `listen` on the host is relayed to
/// `target` inside the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortForward {
    pub listen: SocketAddr,
    pub target: SocketAddr,
}

impl PortForward {
    /// Expands a forward spec, `listen=target`:
    ///
    /// - `127.0.0.1:8080=10.255.0.2:80` — one port to another;
    /// - `127.0.0.2:22,80,8000-8100=10.255.0.2` — every listed port to
    ///   the same port of the target;
    /// - `127.0.0.2:8000-8009=10.255.0.2:9000-9009` — the listed ports to
    ///   the target's listed ports, in order (the counts must match).
    ///
    /// Ports are comma-separated numbers or `first-last` ranges; IPv6
    /// addresses are bracketed (`[::1]:80`).
    pub fn parse_spec(spec: &str) -> Result<Vec<Self>> {
        let invalid = |reason: &str| WgError::Invalid(format!("forward `{spec}`: {reason}"));
        let (listen, target) = spec
            .split_once('=')
            .ok_or_else(|| invalid("expected `listen=target`"))?;
        let (listen_ip, listen_ports) =
            split_host(listen.trim()).ok_or_else(|| invalid("listen: expected `ip:ports`"))?;
        let listen_ip: IpAddr = listen_ip
            .parse()
            .map_err(|e| invalid(&format!("listen: {e}")))?;
        let listen_ports = parse_ports(listen_ports.ok_or_else(|| invalid("listen: no ports"))?)
            .map_err(|e| invalid(&format!("listen: {e}")))?;
        let (target_ip, target_ports) =
            split_host(target.trim()).ok_or_else(|| invalid("target: expected `ip[:ports]`"))?;
        let target_ip: IpAddr = target_ip
            .parse()
            .map_err(|e| invalid(&format!("target: {e}")))?;
        let target_ports = match target_ports {
            None => listen_ports.clone(),
            Some(ports) => parse_ports(ports).map_err(|e| invalid(&format!("target: {e}")))?,
        };
        if target_ports.len() != listen_ports.len() {
            return Err(invalid(&format!(
                "{} listen ports but {} target ports",
                listen_ports.len(),
                target_ports.len()
            )));
        }
        Ok(listen_ports
            .into_iter()
            .zip(target_ports)
            .map(|(listen, target)| Self {
                listen: SocketAddr::new(listen_ip, listen),
                target: SocketAddr::new(target_ip, target),
            })
            .collect())
    }
}

/// Splits `ip[:ports]` / `[ip6][:ports]` into the address and the
/// optional port list.
fn split_host(s: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (ip, rest) = rest.split_once(']')?;
        return match rest {
            "" => Some((ip, None)),
            _ => Some((ip, Some(rest.strip_prefix(':')?))),
        };
    }
    match s.split_once(':') {
        // A bare IPv6 address has several colons and no ports.
        Some((_, rest)) if rest.contains(':') => Some((s, None)),
        Some((ip, ports)) => Some((ip, Some(ports))),
        None => Some((s, None)),
    }
}

/// Parses `22,80,8000-8100` into its ports, in order, without
/// duplicates or port 0.
fn parse_ports(s: &str) -> std::result::Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for item in s.split(',').map(str::trim) {
        let (first, last) = match item.split_once('-') {
            Some((first, last)) => (first.trim(), last.trim()),
            None => (item, item),
        };
        let parse = |p: &str| {
            p.parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| format!("bad port `{p}`"))
        };
        let (first, last) = (parse(first)?, parse(last)?);
        if first > last {
            return Err(format!("empty range `{item}`"));
        }
        ports.extend(first..=last);
    }
    let mut seen = std::collections::HashSet::new();
    if let Some(dup) = ports.iter().find(|&&p| !seen.insert(p)) {
        return Err(format!("port {dup} listed twice"));
    }
    Ok(ports)
}

/// The engine's local side: `stack`, plus echo replies for the pings
/// addressed to `addr`, which the stack itself ignores.
pub(crate) fn local_side(
    stack: NetStack,
    addr: Ipv4Addr,
    mtu: u16,
) -> (impl PacketSource, impl PacketSink) {
    let (stack_source, stack_sink) = stack.split();
    let (echo_source, echo_tx, _) = ChannelSource::new(ECHO_QUEUE, mtu);
    let sink = MapSink::new(stack_sink, move |packet: &mut PacketBuf, _| {
        let bytes = packet.as_packet();
        if !is_echo_request(bytes) || destination_v4(bytes) != Some(addr) {
            return MapVerdict::Keep;
        }
        let mut reply = PacketBuf::from_packet(bytes);
        if echo_reply_in_place(reply.as_packet_mut()) {
            // A full queue drops the reply, like any lost ping.
            let _ = echo_tx.try_send(reply);
        }
        MapVerdict::Drop
    });
    let source = MergeSource::new().source(stack_source).source(echo_source);
    (source, sink)
}

fn destination_v4(packet: &[u8]) -> Option<Ipv4Addr> {
    let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
    (packet.first()? >> 4 == 4).then_some(Ipv4Addr::from(dst))
}

/// The running listeners of one bring-up.
pub(crate) struct Services {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl Services {
    /// Binds every listener (failing on the first that cannot bind) and
    /// starts serving them on `net`.
    pub(crate) async fn start(net: &NetStackHandle, options: &NetstackOptions) -> Result<Self> {
        let cancel = CancellationToken::new();
        let mut tasks = vec![tokio::spawn(refuse_inbound(net.clone()))];
        if let Some(addr) = options.socks5 {
            let listener = bind_tcp(addr).await?;
            tracing::info!(
                target: "nsp::wg",
                %addr,
                auth = options.socks5_auth.is_some(),
                "netstack SOCKS5 listening",
            );
            let auth = options.socks5_auth.clone().map(Arc::new);
            tasks.push(tokio::spawn(serve(
                listener,
                cancel.clone(),
                net.clone(),
                move |client, net| {
                    let auth = auth.clone();
                    async move { socks5(client, &net, auth.as_deref()).await }
                },
            )));
        }
        for forward in &options.forwards {
            let listener = bind_tcp(forward.listen).await?;
            tracing::debug!(
                target: "nsp::wg",
                listen = %forward.listen,
                target_addr = %forward.target,
                "netstack TCP forward listening",
            );
            let target = forward.target;
            tasks.push(tokio::spawn(serve(
                listener,
                cancel.clone(),
                net.clone(),
                move |mut client, net| async move {
                    let mut remote = net.connect_tcp(target).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
                    Ok(())
                },
            )));
        }
        for forward in &options.udp_forwards {
            let socket = UdpSocket::bind(forward.listen)
                .await
                .map_err(|e| WgError::Userspace(format!("bind udp {}: {e}", forward.listen)))?;
            tracing::debug!(
                target: "nsp::wg",
                listen = %forward.listen,
                target_addr = %forward.target,
                "netstack UDP forward listening",
            );
            tasks.push(tokio::spawn(udp_forward(
                Arc::new(socket),
                net.clone(),
                forward.target,
                cancel.clone(),
            )));
        }
        if !options.forwards.is_empty() || !options.udp_forwards.is_empty() {
            tracing::info!(
                target: "nsp::wg",
                tcp = options.forwards.len(),
                udp = options.udp_forwards.len(),
                "netstack port forwards listening",
            );
        }
        Ok(Self { cancel, tasks })
    }

    /// Stops accepting. Open relays end when the stack stops.
    pub(crate) async fn stop(self) {
        self.cancel.cancel();
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn bind_tcp(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| WgError::Userspace(format!("bind {addr}: {e}")))
}

/// Accepts on `listener` until cancelled, handling each connection on
/// its own task.
async fn serve<F, Fut>(
    listener: TcpListener,
    cancel: CancellationToken,
    net: NetStackHandle,
    handler: F,
) where
    F: Fn(TcpStream, NetStackHandle) -> Fut,
    Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((client, peer)) => {
                let task = handler(client, net.clone());
                tokio::spawn(async move {
                    if let Err(err) = task.await {
                        tracing::debug!(target: "nsp::wg", %peer, %err, "netstack relay ended");
                    }
                });
            }
            Err(err) => {
                tracing::warn!(target: "nsp::wg", %err, "netstack accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Nothing listens on the stack's own address: reset TCP connections
/// and drop UDP flows the tunnel peers open to it.
async fn refuse_inbound(net: NetStackHandle) {
    let mut tcp = net.incoming_tcp();
    let mut udp = net.incoming_udp();
    loop {
        tokio::select! {
            conn = tcp.next() => match conn {
                Some(conn) => conn.abort(),
                None => return,
            },
            flow = udp.next() => match flow {
                Some(flow) => drop(flow),
                None => return,
            },
        }
    }
}

/// Relays the datagrams arriving on `socket` to `target`, one tunnel
/// socket per sender so replies find their way back.
async fn udp_forward(
    socket: Arc<UdpSocket>,
    net: NetStackHandle,
    target: SocketAddr,
    cancel: CancellationToken,
) {
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; UDP_BUFFER];
    loop {
        let received = tokio::select! {
            _ = cancel.cancelled() => return,
            received = socket.recv_from(&mut buf) => received,
        };
        let (len, client) = match received {
            Ok(received) => received,
            Err(err) => {
                tracing::debug!(target: "nsp::wg", %err, "netstack UDP forward recv failed");
                continue;
            }
        };
        let datagram = buf[..len].to_vec();
        if let Some(tx) = sessions.get(&client).filter(|tx| !tx.is_closed()) {
            let _ = tx.try_send(datagram);
            continue;
        }
        sessions.retain(|_, tx| !tx.is_closed());
        let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE);
        let _ = tx.try_send(datagram);
        sessions.insert(client, tx);
        let (socket, net) = (Arc::clone(&socket), net.clone());
        tokio::spawn(async move {
            if let Err(err) = udp_session(socket, client, rx, net, target).await {
                tracing::debug!(target: "nsp::wg", %client, %err, "netstack UDP session ended");
            }
        });
    }
}

async fn udp_session(
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    net: NetStackHandle,
    target: SocketAddr,
) -> io::Result<()> {
    let mut remote = net.connect_udp(target).await?;
    loop {
        let event = tokio::time::timeout(UDP_IDLE, async {
            tokio::select! {
                datagram = rx.recv() => Event::Out(datagram),
                reply = remote.recv_from() => Event::In(reply),
            }
        })
        .await;
        match event {
            Err(_) | Ok(Event::Out(None)) => return Ok(()),
            Ok(Event::Out(Some(datagram))) => remote.send(&datagram).await?,
            Ok(Event::In(reply)) => {
                let (payload, _) = reply?;
                socket.send_to(&payload, client).await?;
            }
        }
    }
}

/// What woke a UDP relay loop.
enum Event<O, I> {
    /// From the host side.
    Out(O),
    /// From the tunnel side.
    In(I),
}

const SOCKS_VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const USER_PASS: u8 = 2;
const USER_PASS_VERSION: u8 = 1;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;
const REP_SUCCEEDED: u8 = 0;
const REP_GENERAL_FAILURE: u8 = 1;
const REP_HOST_UNREACHABLE: u8 = 4;
const REP_CONNECTION_REFUSED: u8 = 5;
const REP_COMMAND_NOT_SUPPORTED: u8 = 7;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 8;

/// A request the SOCKS5 handshake accepted.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Connect(SocketAddr),
    UdpAssociate,
}

/// Serves one SOCKS5 client: CONNECT and UDP ASSOCIATE to IP targets
/// (the tunnel has no DNS; a domain is accepted when it is an IP
/// literal).
async fn socks5(
    mut client: TcpStream,
    net: &NetStackHandle,
    auth: Option<&Socks5Auth>,
) -> io::Result<()> {
    match socks5_handshake(&mut client, auth).await? {
        None => Ok(()),
        Some(Request::Connect(target)) => {
            let mut remote = match net.connect_tcp(target).await {
                Ok(remote) => remote,
                Err(err) => {
                    let rep = match err.kind() {
                        io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
                        io::ErrorKind::TimedOut => REP_HOST_UNREACHABLE,
                        io::ErrorKind::AddrNotAvailable => REP_ADDRESS_NOT_SUPPORTED,
                        _ => REP_GENERAL_FAILURE,
                    };
                    socks5_reply(&mut client, rep, None).await?;
                    return Err(err);
                }
            };
            socks5_reply(&mut client, REP_SUCCEEDED, Some(remote.local_addr())).await?;
            tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
            Ok(())
        }
        Some(Request::UdpAssociate) => udp_associate(client, net).await,
    }
}

/// Relays a UDP ASSOCIATE until the control connection closes or the
/// association idles: datagrams from the client (only from the control
/// connection's IP) go out of one stack socket, replies come back with
/// the SOCKS5 UDP header of their source.
async fn udp_associate(mut control: TcpStream, net: &NetStackHandle) -> io::Result<()> {
    let client_ip = control.peer_addr()?.ip();
    let relay = match UdpSocket::bind(SocketAddr::new(control.local_addr()?.ip(), 0)).await {
        Ok(relay) => relay,
        Err(err) => {
            socks5_reply(&mut control, REP_GENERAL_FAILURE, None).await?;
            return Err(err);
        }
    };
    let mut remote = match net
        .bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
    {
        Ok(remote) => remote,
        Err(err) => {
            socks5_reply(&mut control, REP_GENERAL_FAILURE, None).await?;
            return Err(err);
        }
    };
    socks5_reply(&mut control, REP_SUCCEEDED, Some(relay.local_addr()?)).await?;

    let mut client: Option<SocketAddr> = None;
    let mut buf = vec![0u8; UDP_BUFFER];
    let mut eof = [0u8; 1];
    loop {
        let event = tokio::time::timeout(UDP_IDLE, async {
            tokio::select! {
                // The association lives as long as the control connection.
                read = control.read(&mut eof) => Err(read),
                received = relay.recv_from(&mut buf) => Ok(Event::Out(received)),
                reply = remote.recv_from() => Ok(Event::In(reply)),
            }
        })
        .await;
        match event {
            Err(_) | Ok(Err(Ok(0))) => return Ok(()),
            Ok(Err(Ok(_))) => {}
            Ok(Err(Err(err))) => return Err(err),
            Ok(Ok(Event::Out(received))) => {
                let (len, from) = received?;
                if from.ip() != client_ip || client.is_some_and(|c| c != from) {
                    continue;
                }
                client = Some(from);
                if let Some((target, header)) = parse_udp_header(&buf[..len]) {
                    remote.send_to(&buf[header..len], target).await?;
                }
            }
            Ok(Ok(Event::In(reply))) => {
                let (payload, from) = reply?;
                if let Some(client) = client {
                    let mut datagram = vec![0, 0, 0];
                    encode_addr(&mut datagram, from);
                    datagram.extend_from_slice(&payload);
                    relay.send_to(&datagram, client).await?;
                }
            }
        }
    }
}

/// Parses the SOCKS5 UDP request header (RSV RSV FRAG ATYP ADDR PORT);
/// returns the target and the payload offset. Fragments and hostnames
/// are not supported.
fn parse_udp_header(datagram: &[u8]) -> Option<(SocketAddr, usize)> {
    let (&[0, 0, 0, atyp], rest) = datagram.split_first_chunk::<4>()? else {
        return None;
    };
    let (ip, len) = match atyp {
        ATYP_IPV4 => (IpAddr::from(*rest.first_chunk::<4>()?), 4),
        ATYP_IPV6 => (IpAddr::from(*rest.first_chunk::<16>()?), 16),
        ATYP_DOMAIN => {
            let name_len = usize::from(*rest.first()?);
            let name = rest.get(1..=name_len)?;
            let ip = std::str::from_utf8(name)
                .ok()?
                .trim_matches(['[', ']'])
                .parse()
                .ok()?;
            (ip, 1 + name_len)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(*rest.get(len..)?.first_chunk::<2>()?);
    Some((SocketAddr::new(ip, port), 4 + len + 2))
}

fn encode_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Negotiates the method (and credentials when `auth` is set) and reads
/// the request. Returns `None` after answering a client or request it
/// does not serve.
async fn socks5_handshake<S>(
    client: &mut S,
    auth: Option<&Socks5Auth>,
) -> io::Result<Option<Request>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 client",
        ));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods).await?;
    let method = if auth.is_some() { USER_PASS } else { NO_AUTH };
    if !methods.contains(&method) {
        client
            .write_all(&[SOCKS_VERSION, NO_ACCEPTABLE_METHOD])
            .await?;
        return Ok(None);
    }
    client.write_all(&[SOCKS_VERSION, method]).await?;
    if let Some(auth) = auth {
        let mut version = [0u8; 2];
        client.read_exact(&mut version).await?;
        let mut username = vec![0u8; usize::from(version[1])];
        client.read_exact(&mut username).await?;
        let mut len = [0u8; 1];
        client.read_exact(&mut len).await?;
        let mut password = vec![0u8; usize::from(len[0])];
        client.read_exact(&mut password).await?;
        let ok = version[0] == USER_PASS_VERSION && auth.accepts(&username, &password);
        client
            .write_all(&[USER_PASS_VERSION, u8::from(!ok)])
            .await?;
        if !ok {
            return Ok(None);
        }
    }

    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS5 request",
        ));
    }
    let ip = match request[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name).await?;
            std::str::from_utf8(&name)
                .ok()
                .and_then(|name| name.trim_matches(['[', ']']).parse().ok())
        }
        _ => {
            socks5_reply(client, REP_ADDRESS_NOT_SUPPORTED, None).await?;
            return Ok(None);
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    match request[1] {
        // The client's announced UDP address is not used: datagrams are
        // taken from the control connection's IP.
        CMD_UDP_ASSOCIATE => Ok(Some(Request::UdpAssociate)),
        CMD_CONNECT => match ip {
            Some(ip) => Ok(Some(Request::Connect(SocketAddr::new(
                ip,
                u16::from_be_bytes(port),
            )))),
            None => {
                socks5_reply(client, REP_ADDRESS_NOT_SUPPORTED, None).await?;
                Ok(None)
            }
        },
        _ => {
            socks5_reply(client, REP_COMMAND_NOT_SUPPORTED, None).await?;
            Ok(None)
        }
    }
}

async fn socks5_reply<S>(client: &mut S, rep: u8, bound: Option<SocketAddr>) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bound = bound.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    let mut reply = vec![SOCKS_VERSION, rep, 0];
    encode_addr(&mut reply, bound);
    client.write_all(&reply).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(s: &str) -> Vec<(String, String)> {
        PortForward::parse_spec(s)
            .unwrap()
            .into_iter()
            .map(|f| (f.listen.to_string(), f.target.to_string()))
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(l, t)| ((*l).to_owned(), (*t).to_owned()))
            .collect()
    }

    #[test]
    fn forward_spec_single_port() {
        assert_eq!(
            spec(" 127.0.0.1:8080 = 10.255.0.2:80 "),
            pairs(&[("127.0.0.1:8080", "10.255.0.2:80")])
        );
        assert_eq!(
            spec("[::1]:8080=[fd00::2]:80"),
            pairs(&[("[::1]:8080", "[fd00::2]:80")])
        );
    }

    #[test]
    fn forward_spec_same_ports_to_a_bare_ip() {
        assert_eq!(
            spec("127.0.0.2:22,80,8000-8002=10.255.0.2"),
            pairs(&[
                ("127.0.0.2:22", "10.255.0.2:22"),
                ("127.0.0.2:80", "10.255.0.2:80"),
                ("127.0.0.2:8000", "10.255.0.2:8000"),
                ("127.0.0.2:8001", "10.255.0.2:8001"),
                ("127.0.0.2:8002", "10.255.0.2:8002"),
            ])
        );
        assert_eq!(
            spec("[::1]:53=fd00::2"),
            pairs(&[("[::1]:53", "[fd00::2]:53")])
        );
        assert_eq!(
            spec("[::1]:53=[fd00::2]"),
            pairs(&[("[::1]:53", "[fd00::2]:53")])
        );
        assert_eq!(
            PortForward::parse_spec("127.0.0.2:1-65535=10.0.0.2")
                .unwrap()
                .len(),
            65535
        );
    }

    #[test]
    fn forward_spec_maps_ranges_in_order() {
        assert_eq!(
            spec("127.0.0.2:8000-8001,9000=10.255.0.2:7000,7100-7101"),
            pairs(&[
                ("127.0.0.2:8000", "10.255.0.2:7000"),
                ("127.0.0.2:8001", "10.255.0.2:7100"),
                ("127.0.0.2:9000", "10.255.0.2:7101"),
            ])
        );
    }

    #[test]
    fn forward_spec_rejects_malformed() {
        for bad in [
            "127.0.0.1:8080",
            "127.0.0.1=10.0.0.2:80",
            "127.0.0.1:8080=example.com:80",
            "127.0.0.1:8000-8001=10.0.0.2:80",
            "127.0.0.1:0=10.0.0.2",
            "127.0.0.1:90-80=10.0.0.2",
            "127.0.0.1:80,80=10.0.0.2",
            "127.0.0.1:80x=10.0.0.2",
            "127.0.0.1:65536=10.0.0.2",
            "[::1=10.0.0.2",
        ] {
            assert!(PortForward::parse_spec(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn udp_header_round_trips() {
        let target: SocketAddr = "10.255.0.2:53".parse().unwrap();
        let mut datagram = vec![0, 0, 0];
        encode_addr(&mut datagram, target);
        datagram.extend_from_slice(b"query");
        let (parsed, offset) = parse_udp_header(&datagram).unwrap();
        assert_eq!(parsed, target);
        assert_eq!(&datagram[offset..], b"query");

        let mut literal = vec![0, 0, 0, ATYP_DOMAIN, 10];
        literal.extend_from_slice(b"10.255.0.2");
        literal.extend_from_slice(&[0, 53]);
        assert_eq!(parse_udp_header(&literal).unwrap().0, target);
    }

    #[test]
    fn udp_header_rejects_fragments_and_short_datagrams() {
        assert!(parse_udp_header(&[0, 0, 1, ATYP_IPV4, 10, 0, 0, 2, 0, 53]).is_none());
        assert!(parse_udp_header(&[0, 0, 0, ATYP_IPV4, 10, 0]).is_none());
        let mut host = vec![0, 0, 0, ATYP_DOMAIN, 11];
        host.extend_from_slice(b"example.com");
        host.extend_from_slice(&[0, 53]);
        assert!(parse_udp_header(&host).is_none());
    }

    #[test]
    fn destination_reads_ipv4_only() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&[10, 255, 0, 1]);
        assert_eq!(destination_v4(&packet), Some(Ipv4Addr::new(10, 255, 0, 1)));
        packet[0] = 0x60;
        assert_eq!(destination_v4(&packet), None);
        assert_eq!(destination_v4(&packet[..10]), None);
    }

    /// Runs the handshake against `request` bytes and returns the
    /// outcome plus everything the server wrote back.
    async fn handshake(
        request: &[u8],
        auth: Option<&Socks5Auth>,
    ) -> (io::Result<Option<Request>>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(request).await.unwrap();
        let result = socks5_handshake(&mut server, auth).await;
        drop(server);
        let mut written = Vec::new();
        client.read_to_end(&mut written).await.unwrap();
        (result, written)
    }

    fn auth() -> Socks5Auth {
        Socks5Auth {
            username: "alice".into(),
            password: SecretString::from("s3cret"),
        }
    }

    fn user_pass(username: &[u8], password: &[u8]) -> Vec<u8> {
        let mut out = vec![USER_PASS_VERSION, username.len() as u8];
        out.extend_from_slice(username);
        out.push(password.len() as u8);
        out.extend_from_slice(password);
        out
    }

    #[tokio::test]
    async fn socks5_connect_ipv4() {
        let (request, written) =
            handshake(&[5, 1, 0, 5, 1, 0, 1, 10, 255, 0, 2, 0x1f, 0x90], None).await;
        assert_eq!(
            request.unwrap(),
            Some(Request::Connect("10.255.0.2:8080".parse().unwrap()))
        );
        assert_eq!(written, [5, 0]);
    }

    #[tokio::test]
    async fn socks5_udp_associate() {
        let (request, _) = handshake(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0], None).await;
        assert_eq!(request.unwrap(), Some(Request::UdpAssociate));
    }

    #[tokio::test]
    async fn socks5_accepts_ip_literal_domains() {
        let mut req = vec![5, 1, 0, 5, 1, 0, 3, 10];
        req.extend_from_slice(b"10.255.0.2");
        req.extend_from_slice(&[0, 80]);
        let (request, _) = handshake(&req, None).await;
        assert_eq!(
            request.unwrap(),
            Some(Request::Connect("10.255.0.2:80".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn socks5_rejects_hostnames() {
        let mut req = vec![5, 1, 0, 5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&[0, 80]);
        let (request, written) = handshake(&req, None).await;
        assert_eq!(request.unwrap(), None);
        assert_eq!(written[..4], [5, NO_AUTH, 5, REP_ADDRESS_NOT_SUPPORTED]);
    }

    #[tokio::test]
    async fn socks5_rejects_bind_and_auth_only_clients() {
        let (request, written) = handshake(&[5, 1, 0, 5, 2, 0, 1, 10, 0, 0, 2, 0, 80], None).await;
        assert_eq!(request.unwrap(), None);
        assert_eq!(written[..4], [5, NO_AUTH, 5, REP_COMMAND_NOT_SUPPORTED]);

        let (request, written) = handshake(&[5, 1, 2], None).await;
        assert_eq!(request.unwrap(), None);
        assert_eq!(written, [5, NO_ACCEPTABLE_METHOD]);
    }

    #[tokio::test]
    async fn socks5_auth_accepts_valid_credentials() {
        let mut req = vec![5, 2, 0, 2];
        req.extend(user_pass(b"alice", b"s3cret"));
        req.extend_from_slice(&[5, 1, 0, 1, 10, 255, 0, 2, 0, 80]);
        let (request, written) = handshake(&req, Some(&auth())).await;
        assert_eq!(
            request.unwrap(),
            Some(Request::Connect("10.255.0.2:80".parse().unwrap()))
        );
        assert_eq!(written, [5, USER_PASS, USER_PASS_VERSION, 0]);
    }

    #[tokio::test]
    async fn socks5_auth_rejects_bad_password_and_no_auth_clients() {
        let mut req = vec![5, 1, 2];
        req.extend(user_pass(b"alice", b"wrong"));
        let (request, written) = handshake(&req, Some(&auth())).await;
        assert_eq!(request.unwrap(), None);
        assert_eq!(written, [5, USER_PASS, USER_PASS_VERSION, 1]);

        let (request, written) = handshake(&[5, 1, 0], Some(&auth())).await;
        assert_eq!(request.unwrap(), None);
        assert_eq!(written, [5, NO_ACCEPTABLE_METHOD]);
    }
}
