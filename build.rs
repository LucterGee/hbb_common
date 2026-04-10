use serde::Deserialize;
use std::{env, fs, path::Path, path::PathBuf};

const DEFAULT_RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];
const DEFAULT_RS_PUB_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";
const DEFAULT_API_SERVER: &str = "https://admin.rustdesk.com";
const DEFAULT_RENDEZVOUS_PORT: i32 = 21116;
const DEFAULT_RELAY_PORT: i32 = 21117;
const DEFAULT_WS_RENDEZVOUS_PORT: i32 = 21118;
const DEFAULT_WS_RELAY_PORT: i32 = 21119;

const BUILD_CONFIG_PATH_ENV: &str = "HBB_CONFIG_PATH";
const RENDEZVOUS_SERVER_ENV: &str = "RENDEZVOUS_SERVER";
const RENDEZVOUS_SERVERS_ENV: &str = "RENDEZVOUS_SERVERS";
const RS_PUB_KEY_ENV: &str = "RS_PUB_KEY";
const API_SERVER_ENV: &str = "API_SERVER";
const RENDEZVOUS_PORT_ENV: &str = "RENDEZVOUS_PORT";
const RELAY_PORT_ENV: &str = "RELAY_PORT";
const WS_RENDEZVOUS_PORT_ENV: &str = "WS_RENDEZVOUS_PORT";
const WS_RELAY_PORT_ENV: &str = "WS_RELAY_PORT";

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ExternalBuildConfig {
    rendezvous_server: Option<String>,
    rendezvous_servers: Option<Vec<String>>,
    rs_pub_key: Option<String>,
    api_server: Option<String>,
    rendezvous_port: Option<i32>,
    relay_port: Option<i32>,
    ws_rendezvous_port: Option<i32>,
    ws_relay_port: Option<i32>,
}

#[derive(Debug)]
struct BuildConfig {
    rendezvous_servers: Vec<String>,
    rs_pub_key: String,
    api_server: String,
    rendezvous_port: i32,
    relay_port: i32,
    ws_rendezvous_port: i32,
    ws_relay_port: i32,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            rendezvous_servers: DEFAULT_RENDEZVOUS_SERVERS
                .iter()
                .map(|server| server.to_string())
                .collect(),
            rs_pub_key: DEFAULT_RS_PUB_KEY.to_string(),
            api_server: DEFAULT_API_SERVER.to_string(),
            rendezvous_port: DEFAULT_RENDEZVOUS_PORT,
            relay_port: DEFAULT_RELAY_PORT,
            ws_rendezvous_port: DEFAULT_WS_RENDEZVOUS_PORT,
            ws_relay_port: DEFAULT_WS_RELAY_PORT,
        }
    }
}

impl BuildConfig {
    fn load() -> Self {
        let mut config = Self::default();

        if let Some(path) = read_env_string(BUILD_CONFIG_PATH_ENV) {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            config.apply_file(&path);
        }

        config.apply_env();
        config
    }

    fn apply_file(&mut self, path: &Path) {
        let raw = fs::read_to_string(path).unwrap_or_else(|err| {
            panic!(
                "Failed to read build config file '{}': {err}",
                path.display()
            )
        });
        let file_config: ExternalBuildConfig = toml::from_str(&raw).unwrap_or_else(|err| {
            panic!(
                "Failed to parse build config file '{}': {err}",
                path.display()
            )
        });

        if let Some(servers) = file_config.rendezvous_servers {
            self.rendezvous_servers = sanitize_servers(servers, "rendezvous_servers");
        } else if let Some(server) = file_config.rendezvous_server {
            self.rendezvous_servers = sanitize_servers(vec![server], "rendezvous_server");
        }

        if let Some(value) = file_config.rs_pub_key {
            self.rs_pub_key = require_non_empty(value, "rs_pub_key");
        }
        if let Some(value) = file_config.api_server {
            self.api_server = require_non_empty(value, "api_server");
        }
        if let Some(value) = file_config.rendezvous_port {
            self.rendezvous_port = validate_port(value, "rendezvous_port");
        }
        if let Some(value) = file_config.relay_port {
            self.relay_port = validate_port(value, "relay_port");
        }
        if let Some(value) = file_config.ws_rendezvous_port {
            self.ws_rendezvous_port = validate_port(value, "ws_rendezvous_port");
        }
        if let Some(value) = file_config.ws_relay_port {
            self.ws_relay_port = validate_port(value, "ws_relay_port");
        }
    }

    fn apply_env(&mut self) {
        if let Some(value) = read_env_string(RENDEZVOUS_SERVERS_ENV) {
            self.rendezvous_servers = sanitize_servers(
                value.split(',').map(|server| server.to_string()).collect(),
                RENDEZVOUS_SERVERS_ENV,
            );
        } else if let Some(value) = read_env_string(RENDEZVOUS_SERVER_ENV) {
            self.rendezvous_servers = sanitize_servers(vec![value], RENDEZVOUS_SERVER_ENV);
        }

        if let Some(value) = read_env_string(RS_PUB_KEY_ENV) {
            self.rs_pub_key = value;
        }
        if let Some(value) = read_env_string(API_SERVER_ENV) {
            self.api_server = value;
        }
        if let Some(value) = read_env_i32(RENDEZVOUS_PORT_ENV) {
            self.rendezvous_port = value;
        }
        if let Some(value) = read_env_i32(RELAY_PORT_ENV) {
            self.relay_port = value;
        }
        if let Some(value) = read_env_i32(WS_RENDEZVOUS_PORT_ENV) {
            self.ws_rendezvous_port = value;
        }
        if let Some(value) = read_env_i32(WS_RELAY_PORT_ENV) {
            self.ws_relay_port = value;
        }
    }
}

fn sanitize_servers(servers: Vec<String>, source: &str) -> Vec<String> {
    let servers: Vec<String> = servers
        .into_iter()
        .map(|server| server.trim().to_string())
        .filter(|server| !server.is_empty())
        .collect();
    if servers.is_empty() {
        panic!("{} must contain at least one non-empty server", source);
    }
    servers
}

fn require_non_empty(value: String, name: &str) -> String {
    let value = value.trim().to_string();
    if value.is_empty() {
        panic!("{} must not be empty", name);
    }
    value
}

fn validate_port(value: i32, name: &str) -> i32 {
    if value <= 0 {
        panic!("{} must be a positive integer", name);
    }
    value
}

fn read_env_string(name: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={name}");
    match env::var(name) {
        Ok(value) => {
            let value = value.trim().to_string();
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            panic!("{} must be valid UTF-8", name);
        }
    }
}

fn read_env_i32(name: &str) -> Option<i32> {
    read_env_string(name).map(|value| {
        value.parse::<i32>().unwrap_or_else(|err| {
            panic!("{} must be a valid integer: {}", name, err);
        })
    })
}

fn render_build_config(config: &BuildConfig) -> String {
    let rendezvous_servers = config
        .rendezvous_servers
        .iter()
        .map(|server| format!("{server:?}"))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "pub const RENDEZVOUS_SERVERS: &[&str] = &[{rendezvous_servers}];\n\
pub const RS_PUB_KEY: &str = {rs_pub_key:?};\n\
pub const API_SERVER: &str = {api_server:?};\n\
\n\
pub const RENDEZVOUS_PORT: i32 = {rendezvous_port};\n\
pub const RELAY_PORT: i32 = {relay_port};\n\
pub const WS_RENDEZVOUS_PORT: i32 = {ws_rendezvous_port};\n\
pub const WS_RELAY_PORT: i32 = {ws_relay_port};\n",
        rs_pub_key = config.rs_pub_key,
        rendezvous_port = config.rendezvous_port,
        relay_port = config.relay_port,
        ws_rendezvous_port = config.ws_rendezvous_port,
        ws_relay_port = config.ws_relay_port,
        api_server = config.api_server,
    )
}

fn generate_build_config() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let config = BuildConfig::load();
    let target = out_dir.join("build_config.rs");

    fs::write(&target, render_build_config(&config)).unwrap_or_else(|err| {
        panic!(
            "Failed to write generated build config '{}': {err}",
            target.display()
        )
    });
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    generate_build_config();

    let out_dir = format!("{}/protos", env::var("OUT_DIR").unwrap());
    fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["protos/rendezvous.proto", "protos/message.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Codegen failed.");
}
