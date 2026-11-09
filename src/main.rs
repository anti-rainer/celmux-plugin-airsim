// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! Celmux's AirSIM bridge.
//!
//! Celmux owns the cards, the IMS registrations and the calls. This process
//! speaks the AirSIM VoWLAN protocol so the AirSIM iOS client can dial those
//! lines, and it does so without Celmux having to grow any iOS knowledge: the
//! control API it serves is the client's own contract, and every fact it needs
//! it asks Celmux for over the plugin API.

mod auth;
mod celmux;
mod config;
mod control;
mod discovery;
mod http;

use std::sync::Arc;

use config::Config;

fn main() {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("celmux-plugin-airsim: {error}");
            std::process::exit(2);
        }
    };
    let client = celmux::Client::new(
        config.celmux_url.clone(),
        config.celmux_token.clone(),
        config::PLUGIN_ID.to_owned(),
    );
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

    let listener = match std::net::TcpListener::bind(("0.0.0.0", config.control_port)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "celmux-plugin-airsim: 无法监听控制端口 {}: {error}",
                config.control_port
            );
            std::process::exit(4);
        }
    };

    let control = Arc::new(control::Control {
        client,
        verifier: auth::Verifier::new(config.pairing_key()),
        agent_id: config.agent_id.clone(),
        host: local_address().unwrap_or_else(|| "0.0.0.0".to_owned()),
        control_port: config.control_port,
        pcm_port: config.pcm_port,
    });

    // Advertising is best-effort: a network without mDNS still works when the
    // phone is given the address by hand, and a bridge that refuses to start
    // over a discovery failure would be worse than one that is merely quiet.
    let _advertisement = if config.advertise {
        match discovery::Advertisement::register(
            &config.agent_id,
            &control.host,
            config.control_port,
            config.pcm_port,
        ) {
            Ok(advertisement) => {
                eprintln!(
                    "celmux-plugin-airsim: 已广播 {} 控制端口 {} PCM 端口 {}",
                    advertisement.fullname(),
                    config.control_port,
                    config.pcm_port
                );
                Some(advertisement)
            }
            Err(error) => {
                eprintln!("celmux-plugin-airsim: {error}（仍可手动填写地址连接）");
                None
            }
        }
    } else {
        eprintln!("celmux-plugin-airsim: 已关闭 Bonjour 广播");
        None
    };

    eprintln!(
        "celmux-plugin-airsim: 控制接口 http://{}:{}",
        control.host, config.control_port
    );
    let handler = {
        let control = Arc::clone(&control);
        Arc::new(move |request: http::Request| control.handle(request))
            as Arc<dyn Fn(http::Request) -> http::Response + Send + Sync>
    };
    http::serve(listener, handler);
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
