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
//! :7593              settings page + pairing (plain HTTP)
//! :<control_port>    one per agent: the signed control API the phone calls
//! :<pcm_port>        one per agent: raw PCM, handshake then bare frames
//! ```

mod agents;
mod auth;
mod celmux;
mod config;
mod control;
mod discovery;
mod http;
mod pair_endpoint;
mod pairing;
mod pcm;
mod settings;

use std::sync::Arc;

use agents::{Agent, Fleet};
use config::Config;

fn main() {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("celmux-plugin-airsim: {error}");
            std::process::exit(2);
        }
    };
    let client = Arc::new(celmux::Client::new(
        config.celmux_url.clone(),
        config.celmux_token.clone(),
        config::PLUGIN_ID.to_owned(),
    ));
    // Fail loudly at startup rather than on the first dial: a wrong token means
    // every call the phone places fails, and the operator would have no clue
    // why from the phone's side.
    match client.config() {
        Ok(_) => eprintln!(
            "celmux-plugin-airsim: Celmux 已连接 ({})",
            config.celmux_url
        ),
        Err(error) => {
            eprintln!("celmux-plugin-airsim: 无法使用插件令牌访问 Celmux: {error}");
            std::process::exit(3);
        }
    }

    let fleet = Arc::new(Fleet::default());
    // The assignment lives in Celmux's plugin configuration, so it survives a
    // restart of this process. Read it before opening any listener: a bridge
    // that starts with no agents accepts connections and answers none of them.
    match settings::load_assignment(&client) {
        Ok(configs) => {
            if let Err(error) = fleet.reconcile(configs.clone()) {
                eprintln!("celmux-plugin-airsim: 无法载入线路分配: {error}");
            }
            eprintln!("celmux-plugin-airsim: 已载入 {} 个 agent", configs.len());
        }
        Err(error) => {
            eprintln!("celmux-plugin-airsim: 无法读取插件配置: {error}");
            std::process::exit(5);
        }
    }

    let host = local_address().unwrap_or_else(|| "0.0.0.0".to_owned());
    start_agents(
        Arc::clone(&fleet),
        Arc::clone(&client),
        &host,
        config.advertise,
    );

    // The settings listener is what the operator reaches: it serves this
    // plugin's own page and the pairing endpoints. A busy port is fatal because
    // without it nothing can be configured or paired.
    let listener = match std::net::TcpListener::bind(("0.0.0.0", config.port)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "celmux-plugin-airsim: 无法监听插件端口 {}: {error}",
                config.port
            );
            std::process::exit(4);
        }
    };
    eprintln!(
        "celmux-plugin-airsim: 设置与配对 http://{host}:{}",
        config.port
    );
    let handler = {
        let fleet = Arc::clone(&fleet);
        let client = Arc::clone(&client);
        let host = host.clone();
        Arc::new(move |request: http::Request| settings::handle(&fleet, &client, &host, request))
            as Arc<dyn Fn(http::Request) -> http::Response + Send + Sync>
    };
    http::serve(listener, handler);
}

/// Bring up one control listener and one PCM listener per configured agent.
fn start_agents(fleet: Arc<Fleet>, client: Arc<celmux::Client>, host: &str, advertise: bool) {
    for agent in fleet.list() {
        let id = agent.id();
        let control_port = agent.config.control_port;
        let pcm_port = agent.config.pcm_port;

        // The control listener starts whether or not the agent has paired:
        // pairing happens over HTTP by port, so the phone has to reach it
        // *before* there is a secret. Which routes it will answer is decided
        // per request, from whether a secret exists at that moment.
        if !agent.paired() {
            eprintln!("celmux-plugin-airsim: agent {id} 尚未配对（控制端口 {control_port}）");
        }
        start_control_listener(Arc::clone(&agent), Arc::clone(&client), host);
        start_pcm_listener(Arc::clone(&agent), Arc::clone(&client), pcm_port);
        advertise_agent(&agent, host, advertise);
    }
}

fn start_control_listener(agent: Arc<Agent>, client: Arc<celmux::Client>, host: &str) {
    let port = agent.config.control_port;
    let listener = match std::net::TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "celmux-plugin-airsim: agent {} 无法监听 {port}: {error}",
                agent.id()
            );
            return;
        }
    };
    let control = Arc::new(control::Control {
        client,
        agent: Arc::clone(&agent),
        host: host.to_owned(),
    });
    eprintln!(
        "celmux-plugin-airsim: agent {} 控制接口 http://{host}:{port}",
        agent.id()
    );
    let handler = {
        let control = Arc::clone(&control);
        Arc::new(move |request: http::Request| control.handle(request))
            as Arc<dyn Fn(http::Request) -> http::Response + Send + Sync>
    };
    std::thread::spawn(move || http::serve(listener, handler));
}

fn start_pcm_listener(agent: Arc<Agent>, client: Arc<celmux::Client>, pcm_port: u16) {
    let listener = match std::net::TcpListener::bind(("0.0.0.0", pcm_port)) {
        Ok(listener) => listener,
        Err(error) => {
            // The control API is still useful without audio - the phone can
            // list devices and place calls - so a busy PCM port is reported
            // rather than fatal.
            eprintln!(
                "celmux-plugin-airsim: agent {} 无法监听 PCM {pcm_port}: {error}（通话将没有声音）",
                agent.id()
            );
            return;
        }
    };
    eprintln!(
        "celmux-plugin-airsim: agent {} PCM 网关 tcp://0.0.0.0:{pcm_port}",
        agent.id()
    );
    std::thread::spawn(move || pcm::serve(listener, client, agent));
}

fn advertise_agent(agent: &Arc<Agent>, host: &str, advertise: bool) {
    if !advertise {
        return;
    }
    match discovery::Advertisement::register(
        &agent.name(),
        &agent.id(),
        host,
        agent.config.control_port,
        agent.config.pcm_port,
    ) {
        Ok(advertisement) => eprintln!(
            "celmux-plugin-airsim: 已广播 {}",
            advertisement.primary().unwrap_or("")
        ),
        Err(error) => {
            eprintln!("celmux-plugin-airsim: {error}（仍可手动填写地址连接）");
        }
    }
}

/// The address a phone on the same network can reach.
///
/// Picked by connecting a UDP socket toward a public address: no packet is
/// sent, but the kernel chooses the interface it would use, which is the one
/// the LAN can see.
fn local_address() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("223.5.5.5:53").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}
