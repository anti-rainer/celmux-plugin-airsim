// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! Celmux's AirSIM bridge.
//!
//! Celmux owns the cards, the IMS registrations and the calls. This process
//! speaks the AirSIM VoWLAN protocol so the AirSIM iOS client can dial those
//! lines, and it does so without Celmux having to grow any iOS knowledge: the
//! control API it serves is the client's own contract, and every fact it needs
//! it asks Celmux for over the plugin API.
//!
//! Three listeners, because the protocol has three kinds of traffic that cannot
//! share one:
//!
//! ```text
//! :<port>            the AirSIM-facing API the settings page drives
//! :<control_port>    one per agent: the signed control API the phone calls
//! :<pcm_port>        one per agent: raw PCM, handshake then bare frames
//! ```

mod agents;
mod apns;
mod apns_http;
mod audio_wire;
mod auth;
mod celmux;
mod config;
mod control;
mod control_api;
mod discovery;
mod http;
mod logging;
mod pair_endpoint;
mod pair_probe;
mod pairing;
mod pcm;
mod relay;
mod relay_agent;
mod relay_endpoint;
mod revision;
mod secrets;
mod settings;

use std::collections::BTreeMap;
use std::sync::Arc;

use agents::{Agent, Fleet};
use config::Config;

fn main() {
    // The pairing probe is an operator tool, not a plugin run: it needs no
    // environment and must work before anything else has been configured.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("pair-probe") {
        std::process::exit(pair_probe::main(args.into_iter().skip(1).collect()));
    }
    let mut config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("celmux-plugin-airsim: {error}");
            std::process::exit(2);
        }
    };

    // This plugin's own log, beside its binary rather than in Celmux's log
    // directory: the two processes have separate lives and separate verbosity.
    let root = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let level = logging::Level::parse(
        &std::env::var("CELMUX_PLUGIN_LOG_LEVEL").unwrap_or_else(|_| "info".to_owned()),
    );
    match logging::init(&root, level) {
        Some(path) => eprintln!("celmux-plugin-airsim: 日志 {}", path.display()),
        None => eprintln!("celmux-plugin-airsim: 无法创建日志文件，仅输出到 stderr"),
    }
    let client = Arc::new(celmux::Client::new(
        config.celmux_url.clone(),
        config.celmux_token.clone(),
        config::PLUGIN_ID.to_owned(),
        config.audio_url.clone(),
    ));
    // Fail loudly at startup rather than on the first dial: a wrong token means
    // every call the phone places fails, and the operator would have no clue
    // why from the phone's side.
    match client.config() {
        Ok(value) => {
            // The operator's port lives in Celmux's plugin configuration, which
            // is the one place the settings page writes. The environment is only
            // what Celmux passed at launch and can predate that save.
            if let Some(port) = value
                .get("config")
                .and_then(|config| config.get("port"))
                .and_then(|value| value.as_str())
                .and_then(|value| value.trim().parse::<u16>().ok())
            {
                config.port = port;
            }
            crate::log_info!(
                "celmux-plugin-airsim: Celmux 已连接 ({})，对接端口 {}",
                config.celmux_url,
                config.port
            );
        }
        Err(error) => {
            crate::log_error!("celmux-plugin-airsim: 无法使用插件令牌访问 Celmux: {error}");
            std::process::exit(3);
        }
    }

    let fleet = Arc::new(Fleet::new(&root));
    // The assignment lives in Celmux's plugin configuration, so it survives a
    // restart of this process. Read it before opening any listener: a bridge
    // that starts with no agents accepts connections and answers none of them.
    match settings::load_assignment(&client) {
        Ok(configs) => {
            if let Err(error) = fleet.reconcile(configs.clone()) {
                crate::log_warn!("celmux-plugin-airsim: 无法载入线路分配: {error}");
            }
            crate::log_info!("celmux-plugin-airsim: 已载入 {} 个 agent", configs.len());
        }
        Err(error) => {
            crate::log_warn!("celmux-plugin-airsim: 无法读取插件配置: {error}");
            std::process::exit(5);
        }
    }

    // The cloud path gets a listener of its own. It is the only one an operator
    // is expected to put behind a public reverse proxy, and the settings routes -
    // pairing, logs, configuration - must not travel with it: a proxy opened for
    // the relay would otherwise expose all of them to the internet.
    let relay_context = Arc::new(relay_endpoint::Context {
        state: Arc::new(relay::State::persistent(&root)),
        agent: Arc::new(relay_agent::Agent::new(
            relay_agent::Target::from_mode(
                &config.relay_mode,
                &config.relay_target,
                config.relay_port,
            ),
            relay_agent::Credentials {
                // The phone's credentials are what a relay authenticates an event
                // with. When this process is the relay it registered that phone
                // itself and these are adopted from that registration; an external
                // relay needs the pair the phone registered there with, which
                // arrives in the pairing claim. A manually configured pair is the
                // last resort, for a phone paired before this was captured.
                device_id: config.relay_device_id.clone(),
                device_secret: config.relay_device_secret.clone(),
            },
            "celmux",
        )),
        // Built even when the cloud path is off, so the settings page can report
        // why pushes would not work rather than showing nothing.
        pusher: Arc::new(apns::Pusher::new(
            &config.apns_p8,
            &config.apns_key_id,
            &config.apns_team_id,
            &config.apns_bundle_id,
            config.apns_sandbox,
        )),
        client: Arc::clone(&client),
        agent_id: fleet
            .list()
            .first()
            .map(|agent| agent.id())
            .unwrap_or_else(|| "celmux".to_owned()),
        pcm_port: config.pcm_port,
        plugin_version: relay::VERSION.to_owned(),
        default_line: fleet
            .list()
            .first()
            .map(|agent| agent.config.primary_line().to_owned())
            .unwrap_or_default(),
    });
    let host = local_address().unwrap_or_else(|| "0.0.0.0".to_owned());
    let advertisements = start_agents(
        Arc::clone(&fleet),
        Arc::clone(&client),
        &host,
        &config,
        Some(Arc::clone(&relay_context)),
    );

    // The settings listener is what Celmux's plugin centre relays to: it serves
    // this plugin's own page and its configuration API. A separate port from the
    // phone's control port, because the page is reached through Celmux with a
    // page token, while the phone signs its requests - two different callers,
    // two different credentials, and one of them should never be reachable from
    // the same address the phone uses.
    let listener = match std::net::TcpListener::bind(("0.0.0.0", config.port)) {
        Ok(listener) => listener,
        Err(error) => {
            crate::log_warn!(
                "celmux-plugin-airsim: 无法监听设置接口端口 {}: {error}",
                config.port
            );
            std::process::exit(4);
        }
    };
    crate::log_info!(
        "celmux-plugin-airsim: 设置接口 http://{host}:{}",
        config.port
    );
    let advertisements = Arc::new(std::sync::Mutex::new(advertisements));
    let settings_ports = crate::control::Ports {
        control: config.control_port,
        pcm: config.pcm_port,
    };
    // The heartbeat starts before the listener so the directory is populated the
    // moment anything can read it, not one interval later.
    // The listener is opened only when this installation is its own relay. With an
    // external relay the events travel out and the phone registers there, so a
    // listener here would accept registrations nobody uses and expose a port for
    // no reason. The two modes are exclusive in the running process, not just in
    // the settings form.
    let own_relay = relay_context.agent.target().is_own();
    if config.relay_enabled && own_relay {
        relay_endpoint::spawn_heartbeat(Arc::clone(&relay_context));
        start_relay_listener(
            Arc::clone(&relay_context),
            Arc::clone(&fleet),
            config.relay_port,
        );
    } else if !config.relay_enabled {
        crate::log_info!(
            "celmux-plugin-airsim: Relay 云端已关闭（relay_enabled=false），不监听 {}",
            config.relay_port
        );
    } else {
        crate::log_info!(
            "celmux-plugin-airsim: 使用外部 Relay {}，本机不监听 {}",
            config.relay_target,
            config.relay_port
        );
    }
    let handler = {
        let fleet = Arc::clone(&fleet);
        let client = Arc::clone(&client);
        let host = host.clone();
        let relay_state = Arc::clone(&relay_context.state);
        Arc::new(move |request: http::Request| {
            settings::handle(
                &fleet,
                &client,
                &advertisements,
                &host,
                &settings_ports,
                &relay_state,
                request,
            )
        }) as Arc<dyn Fn(http::Request) -> http::Response + Send + Sync>
    };
    http::serve(listener, handler);
}

/// Serve the AirSIM cloud path on its own port.
///
/// Bound on every interface because a reverse proxy has to reach it; the phone
/// requires `https`, and terminating TLS is the proxy's job, not this process's.
/// Every route here authenticates with the credentials the phone registered, so an
/// open port is not an open interface.
fn start_relay_listener(context: Arc<relay_endpoint::Context>, fleet: Arc<Fleet>, port: u16) {
    let listener = match std::net::TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => listener,
        Err(error) => {
            crate::log_warn!("celmux-plugin-airsim: 无法监听 Relay 端口 {port}: {error}");
            return;
        }
    };
    crate::log_info!("celmux-plugin-airsim: Relay 云端接口 http://0.0.0.0:{port}");
    let handler = Arc::new(move |request: http::Request| {
        relay_endpoint::handle(&context, &fleet, &request).unwrap_or_else(|| {
            http::Response::error(404, "Not Found", "not_found", "Relay 路由不存在")
        })
    }) as Arc<dyn Fn(http::Request) -> http::Response + Send + Sync>;
    std::thread::spawn(move || http::serve(listener, handler));
}

/// Bring up one control listener and one PCM listener per configured agent.
///
/// Returns the advertisements so the pairing window can join them: a window is
/// a second Bonjour service on the same agent's daemon.
fn start_agents(
    fleet: Arc<Fleet>,
    client: Arc<celmux::Client>,
    host: &str,
    config: &crate::config::Config,
    relay_context: Option<Arc<relay_endpoint::Context>>,
) -> BTreeMap<String, discovery::Advertisement> {
    let mut advertisements = BTreeMap::new();
    let agents = fleet.list();
    // The ports come up even with no lines configured: pairing is what creates a
    // line, and it happens over the control port. Returning early here meant a
    // freshly cleared installation had no port to pair against.
    // One control port and one PCM port for every line.
    //
    // The ports are shared because every request already carries the identity
    // that tells the lines apart: it is signed with one line's secret, and
    // verifying against each known secret names the line. Giving each line its
    // own port would spend a port per line, put a listener per line in every
    // firewall rule, and make the phone's saved endpoints change whenever a
    // line was added - for information the signature already provides.
    let ports = crate::control::Ports {
        control: config.control_port,
        pcm: config.pcm_port,
    };
    let advertise = config.advertise;
    for agent in &agents {
        if !agent.paired() {
            crate::log_info!("celmux-plugin-airsim: agent {} 尚未配对", agent.id());
        }
    }
    // The control listener starts whether or not any line has paired: pairing
    // happens over HTTP, so the phone has to reach it *before* there is a
    // secret. Which routes it answers is decided per request, from whether a
    // secret exists at that moment.
    start_shared_control_listener(
        Arc::clone(&fleet),
        Arc::clone(&client),
        host,
        ports,
        // Only when the cloud path is on: a push needs a listener to land on, and
        // an operator who turned the cloud path off has nothing to push to.
        relay_context.clone(),
    );
    start_shared_pcm_listener(Arc::clone(&fleet), Arc::clone(&client), ports.pcm);
    // Each line follows Celmux's event stream. Without this the phone's long
    // poll only ever answers on its timeout, so an incoming call or a received
    // message looks like it never arrived until something else asks.
    for agent in &agents {
        let control = crate::control::Control {
            client: Arc::clone(&client),
            agent: Arc::clone(agent),
            revision: agent.revision(),
            ports,
            // The per-agent follower has no cloud path of its own: one shared
            // control instance owns the event stream, so an incoming call is
            // pushed once rather than once per line.
            relay_context: None,
            call_push: Arc::new(std::sync::Mutex::new(control::CallPush::default())),
            acked_messages: agent.acked_messages(),
        };
        Arc::new(control).follow_celmux();
    }
    for agent in &agents {
        advertise_agent(agent, host, advertise, ports, &mut advertisements);
    }
    advertisements
}

/// The fleet as the listeners see it: a request is routed to the line whose
/// secret signed it.
fn start_shared_control_listener(
    fleet: Arc<Fleet>,
    client: Arc<celmux::Client>,
    host: &str,
    ports: crate::control::Ports,
    relay_context: Option<Arc<relay_endpoint::Context>>,
) {
    let port = ports.control;
    let listener = match std::net::TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => listener,
        Err(error) => {
            crate::log_error!("celmux-plugin-airsim: 无法监听控制端口 {port}: {error}");
            return;
        }
    };
    crate::log_info!("celmux-plugin-airsim: 控制接口 http://{host}:{port}（全部线路共用）");
    let handler = {
        let fleet = Arc::clone(&fleet);
        let client = Arc::clone(&client);
        Arc::new(move |request: http::Request| {
            control::handle_shared(&fleet, &client, &ports, relay_context.clone(), request)
        }) as Arc<dyn Fn(http::Request) -> http::Response + Send + Sync>
    };
    std::thread::spawn(move || http::serve(listener, handler));
}

fn start_shared_pcm_listener(fleet: Arc<Fleet>, client: Arc<celmux::Client>, pcm_port: u16) {
    let listener = match std::net::TcpListener::bind(("0.0.0.0", pcm_port)) {
        Ok(listener) => listener,
        Err(error) => {
            crate::log_warn!(
                "celmux-plugin-airsim: 无法监听 PCM {pcm_port}: {error}（通话将没有声音）"
            );
            return;
        }
    };
    crate::log_info!("celmux-plugin-airsim: PCM 网关 tcp://0.0.0.0:{pcm_port}（全部线路共用）");
    std::thread::spawn(move || pcm::serve_shared(listener, client, fleet));
}

/// Advertise one agent and keep the handle.
///
/// The handle is what a pairing window is later added to: `_airsim-pair._tcp`
/// is a second service on the same daemon, so the daemon has to outlive the
/// call that created it.
fn advertise_agent(
    agent: &Arc<Agent>,
    host: &str,
    advertise: bool,
    ports: crate::control::Ports,
    advertisements: &mut BTreeMap<String, discovery::Advertisement>,
) {
    if !advertise {
        return;
    }
    match discovery::Advertisement::register(
        // The TXT `device_name` the phone shows, so it is the line as it is
        // now rather than the name stored when the line was exposed.
        &crate::control::line_display_name(agent),
        &agent.id(),
        host,
        ports.control,
        ports.pcm,
    ) {
        Ok(advertisement) => {
            crate::log_info!(
                "celmux-plugin-airsim: 已广播 {}",
                advertisement.primary().unwrap_or("")
            );
            // Kept alive for the process lifetime: dropping it unregisters.
            advertisements.insert(agent.id(), advertisement);
        }
        Err(error) => {
            crate::log_info!("celmux-plugin-airsim: {error}（仍可手动填写地址连接）");
        }
    }
}

/// The address a phone on the same network can reach.
///
/// Not the address a route lookup returns. On a router the interface that wins
/// a lookup toward the internet is the uplink - here a VoWiFi tunnel exit - and
/// a phone on the LAN cannot reach it. What the phone needs is the address of
/// the interface the LAN segment is on, so a private address on a non-tunnel
/// interface is preferred, and the lookup is only a last resort.
fn local_address() -> Option<String> {
    if let Some(address) = lan_address() {
        return Some(address);
    }
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("223.5.5.5:53").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

/// The address of an interface a phone on the LAN could actually reach.
///
/// Read from `/proc/net/route` rather than from a route lookup: a lookup toward
/// the internet picks the uplink, and on a router with a VoWiFi tunnel that is
/// the tunnel's exit address, which nothing on the LAN can dial. The default
/// route's interface is skipped for the same reason, and what is left is
/// ranked so a bridge address wins over a point-to-point link.
fn lan_address() -> Option<String> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in routes.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        let (Some(interface), Some(destination), Some(mask), Some(flags)) =
            (fields.first(), fields.get(1), fields.get(7), fields.get(3))
        else {
            continue;
        };
        // Only interfaces with the link up, and only real subnet routes: a /32
        // is one host, which is a tunnel endpoint rather than a segment.
        let Ok(flags) = u16::from_str_radix(flags, 16) else {
            continue;
        };
        if flags & 0x1 == 0 {
            continue;
        }
        if *mask == "FFFFFFFF" {
            continue;
        }
        if looks_like_exit(interface) {
            continue;
        }
        let Some(address) = interface_address(interface) else {
            continue;
        };
        if is_lan_candidate(&address) {
            return Some(address);
        }
        let _ = destination;
    }
    None
}

/// Whether an interface name marks a cellular or overlay exit.
///
/// A phone is on the LAN, not on the host's uplink and not on an overlay: these
/// are the names this installation gives such interfaces, plus the common
/// tunnel prefixes.
fn looks_like_exit(interface: &str) -> bool {
    const EXITS: [&str; 8] = [
        "sipa",
        "qmimux",
        "wwan",
        "rmnet",
        "tun",
        "wg",
        "tailscale",
        "ppp",
    ];
    EXITS.iter().any(|prefix| interface.starts_with(prefix))
}

/// The IPv4 address of one interface, via the netlink-free `SIOCGIFADDR` call.
fn interface_address(interface: &str) -> Option<String> {
    use std::os::fd::AsRawFd;
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // struct ifreq: 16-byte name, then the addresses as a union.
    let mut request = [0_u8; 40];
    let name = interface.as_bytes();
    if name.len() >= 16 {
        return None;
    }
    request[..name.len()].copy_from_slice(name);
    // SIOCGIFADDR = 0x8915
    let result = unsafe { libc_ioctl(socket.as_raw_fd(), 0x8915, request.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // sockaddr_in starts at offset 16: family (2), port (2), then the address.
    let address = [request[20], request[21], request[22], request[23]];
    Some(format!(
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    ))
}

/// `ioctl(2)`, which the standard library does not expose.
#[cfg(target_os = "linux")]
unsafe fn libc_ioctl(fd: std::os::fd::RawFd, request: u64, argument: *mut u8) -> i32 {
    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
    }
    unsafe { ioctl(fd, request, argument) }
}

/// Whether an address could be the LAN side a phone sits on.
fn is_lan_candidate(address: &str) -> bool {
    let Ok(std::net::IpAddr::V4(v4)) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    // 198.18.0.0/15 is the benchmark range a transparent proxy hands out for
    // fake addresses: reachable from this host, meaningless to a phone.
    let octets = v4.octets();
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    v4.is_private() && !v4.is_loopback() && !v4.is_link_local()
}
