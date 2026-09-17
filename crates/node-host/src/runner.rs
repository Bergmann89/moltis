//! WebSocket client that connects to a gateway as a headless node.

use std::{path::PathBuf, process::Stdio, time::Duration};

use {
    base64::Engine,
    futures::{SinkExt, StreamExt},
    tokio::{
        io::{AsyncRead, AsyncReadExt},
        process::Command,
    },
    tokio_tungstenite::{connect_async, tungstenite::Message},
    tracing::{debug, error, info, warn},
};

use crate::{
    error::{Error, Result},
    identity::NodeIdentity,
};

use {
    moltis_common::process_tree::OwnedProcessTree,
    moltis_protocol::{
        ClientInfo, ConnectAuth, ConnectParamsV4, GatewayFrame, PROTOCOL_VERSION, ProtocolRange,
        RequestFrame, ResponseFrame, SYSTEM_EXEC_COMMAND, SystemExecRequest,
        is_safe_remote_env_key, roles,
    },
};

// Keep the worst-case JSON expansion of both streams below the protocol's
// payload ceiling (a control byte may serialize as six ASCII bytes).
const MAX_OUTPUT_BYTES: usize = 32 * 1024;

/// Default liveness deadline, in seconds.
///
/// One value, used by [`NodeConfig::default`], by the persisted
/// [`crate::ServiceConfig`] and by the `--pong-deadline` flag, so the three
/// cannot drift apart.
pub const DEFAULT_PONG_DEADLINE_SECS: u64 = 20;

async fn read_output_limited(mut reader: impl AsyncRead + Unpin) -> std::io::Result<String> {
    let mut output = Vec::with_capacity(MAX_OUTPUT_BYTES.min(64 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let keep = read.min(MAX_OUTPUT_BYTES.saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    let mut output = String::from_utf8_lossy(&output).into_owned();
    if output.len() > MAX_OUTPUT_BYTES {
        output.truncate(output.floor_char_boundary(MAX_OUTPUT_BYTES));
        truncated = true;
    }
    if truncated {
        output.push_str("\n... [output truncated]");
    }
    Ok(output)
}

/// Configuration for connecting a node to a gateway.
#[derive(Debug)]
pub struct NodeConfig {
    /// Gateway WebSocket URL (e.g. `ws://localhost:9090/ws`).
    pub gateway_url: String,
    /// Device token obtained from the pairing flow (legacy, deprecated).
    pub device_token: String,
    /// Ed25519 identity for challenge-response authentication.
    pub identity: Option<NodeIdentity>,
    /// Unique node identifier.
    pub node_id: String,
    /// Human-readable display name.
    pub display_name: Option<String>,
    /// Platform string (e.g. "macos", "linux").
    pub platform: String,
    /// Capabilities this node advertises (e.g. "system.exec.v1").
    pub caps: Vec<String>,
    /// Commands this node supports (e.g. "system.exec.v1", "system.which").
    pub commands: Vec<String>,
    /// Maximum time for a single command execution.
    pub exec_timeout: Duration,
    /// Working directory for commands (defaults to $HOME).
    pub working_dir: Option<String>,
    /// Executable paths or names that this node permits the gateway to run.
    pub allowed_programs: Vec<String>,
    /// How often the node reports telemetry to the gateway.
    pub telemetry_interval: Duration,
    /// How long the node waits for any frame from the gateway before it sends a
    /// liveness Ping, and how long it then waits for the Pong before it gives
    /// up on the link. Detection therefore costs between one and two of these.
    pub pong_deadline: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            gateway_url: "ws://localhost:9090/ws".into(),
            device_token: String::new(),
            identity: None,
            node_id: uuid::Uuid::new_v4().to_string(),
            display_name: None,
            platform: std::env::consts::OS.into(),
            caps: vec![
                SYSTEM_EXEC_COMMAND.into(),
                "system.which".into(),
                "system.providers".into(),
            ],
            commands: vec![
                SYSTEM_EXEC_COMMAND.into(),
                "system.which".into(),
                "system.providers".into(),
            ],
            exec_timeout: Duration::from_secs(300),
            working_dir: None,
            allowed_programs: Vec::new(),
            telemetry_interval: Duration::from_secs(30),
            pong_deadline: Duration::from_secs(DEFAULT_PONG_DEADLINE_SECS),
        }
    }
}

/// Detect installed runtimes using `which`.
fn detect_runtimes() -> Vec<String> {
    let candidates = ["python3", "python", "node", "ruby", "go", "rustc", "java"];
    let mut found = Vec::new();
    for name in candidates {
        // Skip "python" if we already found "python3".
        if name == "python" && found.contains(&"python3".to_string()) {
            continue;
        }
        if which::which(name).is_ok() {
            found.push(name.to_string());
        }
    }
    found
}

/// Collect system telemetry using `sysinfo`.
fn collect_system_telemetry(node_id: &str) -> serde_json::Value {
    use sysinfo::{Disks, System};

    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();

    let uptime = System::uptime();

    // Disk: find the root partition.
    let disks = Disks::new_with_refreshed_list();
    let root_disk = disks
        .iter()
        .find(|d| d.mount_point() == std::path::Path::new("/"));
    let disk_total = root_disk.map(|d| d.total_space());
    let disk_available = root_disk.map(|d| d.available_space());

    let runtimes = detect_runtimes();

    serde_json::json!({
        "nodeId": node_id,
        "mem": {
            "total": sys.total_memory(),
            "available": sys.available_memory(),
        },
        "cpuCount": sys.cpus().len(),
        "cpuUsage": sys.global_cpu_usage(),
        "uptime": uptime,
        "services": [],
        "disk": {
            "total": disk_total,
            "available": disk_available,
        },
        "runtimes": runtimes,
    })
}

/// A headless node host that connects to a gateway and handles commands.
pub struct NodeHost {
    config: NodeConfig,
}

impl NodeHost {
    pub fn new(config: NodeConfig) -> Self {
        Self { config }
    }

    /// Connect to the gateway and run the message loop until disconnected.
    ///
    /// Returns `Ok(())` on clean shutdown, `Err` on connection/protocol errors.
    pub async fn run(&self) -> Result<()> {
        // Install a rustls CryptoProvider before any TLS connection.
        // Without this, `connect_async` on a `wss://` URL panics because
        // tokio-tungstenite uses rustls under the hood and no provider is
        // registered in the node-host code path (the gateway sets its own
        // in `gateway.rs`). See #744.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Validate URL first, then pass string to connect_async.
        let _url = url::Url::parse(&self.config.gateway_url)?;
        info!(url = %self.config.gateway_url, node_id = %self.config.node_id, "connecting to gateway");

        let (ws_stream, _response) = connect_async(&self.config.gateway_url).await?;
        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        info!("websocket connected, sending handshake");

        // Build and send connect request (v4 format).
        let connect_id = uuid::Uuid::new_v4().to_string();
        let connect_params = ConnectParamsV4 {
            protocol: ProtocolRange {
                min: PROTOCOL_VERSION,
                max: PROTOCOL_VERSION,
            },
            client: ClientInfo {
                id: self.config.node_id.clone(),
                display_name: self.config.display_name.clone(),
                version: moltis_config::VERSION.into(),
                platform: self.config.platform.clone(),
                device_family: None,
                model_identifier: None,
                mode: "headless".into(),
                instance_id: None,
            },
            role: Some(roles::NODE.into()),
            scopes: None,
            auth: Some(ConnectAuth {
                token: None,
                password: None,
                api_key: None,
                device_token: if self.config.device_token.is_empty() {
                    None
                } else {
                    Some(self.config.device_token.clone())
                },
                public_key: self
                    .config
                    .identity
                    .as_ref()
                    .map(|id| id.public_key_base64()),
            }),
            locale: None,
            timezone: None,
            extensions: {
                let mut ext = std::collections::HashMap::new();
                ext.insert(
                    "moltis".into(),
                    serde_json::json!({
                        "caps": self.config.caps,
                        "commands": self.config.commands,
                    }),
                );
                ext
            },
        };

        let connect_req = RequestFrame {
            r#type: "req".into(),
            id: connect_id.clone(),
            method: "connect".into(),
            params: Some(serde_json::to_value(&connect_params)?),
            channel: None,
        };

        let connect_json = serde_json::to_string(&connect_req)?;
        ws_tx.send(Message::Text(connect_json.into())).await?;

        // Wait for hello-ok, handling challenge-response if the gateway sends one.
        // Timeout is generous to allow for operator approval of pending pair requests.
        let handshake_timeout = if self.config.identity.is_some() {
            Duration::from_secs(310) // 5 min approval window + 10s buffer
        } else {
            Duration::from_secs(10)
        };
        let hello = self
            .complete_handshake(&connect_id, &mut ws_tx, &mut ws_rx, handshake_timeout)
            .await?;

        info!(
            server_version = hello
                .payload
                .as_ref()
                .and_then(|p| p.get("server"))
                .and_then(|s| s.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            "handshake complete, node registered"
        );

        self.run_loop(&mut ws_tx, &mut ws_rx).await;

        info!("node disconnected");
        Ok(())
    }

    /// Drive an already-connected socket until the link ends.
    ///
    /// Split out of [`NodeHost::run`] on purpose: `run` can only be driven by a
    /// real gateway, while this takes any sink and stream pair, so the states a
    /// real socket cannot be put into - a send that fails while the read side
    /// stays pending - are reachable from a test.
    async fn run_loop(
        &self,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        ws_rx: &mut (
                 impl StreamExt<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin
             ),
    ) {
        // Main message loop with telemetry and liveness tickers.
        let mut telemetry_interval = tokio::time::interval(self.config.telemetry_interval);
        // Skip the immediate first tick — send telemetry after the first interval.
        telemetry_interval.tick().await;

        let mut liveness_interval = tokio::time::interval(self.config.pong_deadline);
        liveness_interval.tick().await;
        // True once a liveness Ping has gone out with nothing heard since.
        let mut awaiting_pong = false;

        loop {
            tokio::select! {
                msg = ws_rx.next() => {
                    match msg {
                        Some(Ok(message)) => {
                            // Any frame at all proves the peer is still there.
                            awaiting_pong = false;
                            match message {
                                Message::Text(text) => {
                                    self.handle_message(&text, ws_tx).await;
                                },
                                Message::Ping(data) => {
                                    if let Err(e) = ws_tx.send(Message::Pong(data)).await {
                                        warn!(error = %e, "failed to send pong");
                                        break;
                                    }
                                },
                                Message::Close(_) => {
                                    info!("gateway closed connection");
                                    break;
                                },
                                _ => {},
                            }
                        },
                        Some(Err(e)) => {
                            error!(error = %e, "websocket error");
                            break;
                        },
                        None => {
                            info!("websocket stream ended");
                            break;
                        },
                    }
                },
                _ = telemetry_interval.tick() => {
                    // A telemetry send that fails means the route is gone. The
                    // read side can stay pending forever in that state, so the
                    // write side is the only thing that notices: end the loop
                    // and let the supervisor dial again.
                    if let Err(e) = self.send_telemetry(ws_tx).await {
                        warn!(error = %e, "telemetry send failed, link is dead");
                        break;
                    }
                },
                _ = liveness_interval.tick() => {
                    // A live route with a dead peer: the socket still accepts
                    // writes, so nothing above notices. The previous Ping went
                    // unanswered for a full deadline, so give up on the link.
                    if awaiting_pong {
                        warn!("no reply within the pong deadline, link is dead");
                        break;
                    }
                    if let Err(e) = ws_tx.send(Message::Ping(Default::default())).await {
                        warn!(error = %e, "failed to send liveness ping");
                        break;
                    }
                    awaiting_pong = true;
                },
            }
        }
    }

    /// Drive the handshake to completion, handling an optional challenge-response
    /// round if the gateway requests Ed25519 signature verification.
    ///
    /// The gateway may send:
    /// 1. A direct `hello-ok` response (token auth or already-approved key).
    /// 2. A `node.auth.challenge` event with a nonce to sign.
    /// 3. A `node.pair.pending` event while waiting for operator approval,
    ///    followed eventually by a challenge or auth-failed.
    async fn complete_handshake(
        &self,
        connect_id: &str,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        ws_rx: &mut (
                 impl StreamExt<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin
             ),
        timeout: Duration,
    ) -> Result<ResponseFrame> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Protocol("handshake timeout".into()));
            }

            let msg = match tokio::time::timeout(remaining, ws_rx.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => text,
                Ok(Some(Ok(Message::Ping(_)))) => continue,
                Ok(Some(Ok(_))) => {
                    return Err(Error::Protocol(
                        "unexpected non-text message during handshake".into(),
                    ));
                },
                Ok(Some(Err(e))) => {
                    return Err(Error::Protocol(format!(
                        "websocket error during handshake: {e}"
                    )));
                },
                Ok(None) => {
                    return Err(Error::Protocol("connection closed during handshake".into()));
                },
                Err(_) => return Err(Error::Protocol("handshake timeout".into())),
            };

            // Try parsing as a response frame first (hello-ok or auth-failed).
            if let Ok(resp) = serde_json::from_str::<ResponseFrame>(&msg)
                && resp.id == connect_id
            {
                if !resp.ok {
                    let err_msg = resp
                        .error
                        .map(|e| format!("{}: {}", e.code, e.message))
                        .unwrap_or_else(|| "unknown error".into());
                    return Err(Error::Protocol(format!("handshake failed: {err_msg}")));
                }
                return Ok(resp);
            }

            // Try parsing as an event frame (challenge or pending notification).
            if let Ok(frame) = serde_json::from_str::<GatewayFrame>(&msg) {
                match frame {
                    GatewayFrame::Event(event) if event.event == "node.auth.challenge" => {
                        self.handle_challenge(&event.payload, ws_tx).await?;
                    },
                    GatewayFrame::Event(event) if event.event == "node.pair.pending" => {
                        info!("pairing request pending — waiting for operator approval");
                    },
                    _ => {
                        debug!("ignoring unexpected frame during handshake");
                    },
                }
            }
        }
    }

    /// Sign a challenge nonce and send the response back to the gateway.
    async fn handle_challenge(
        &self,
        payload: &Option<serde_json::Value>,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ) -> Result<()> {
        let identity = self.config.identity.as_ref().ok_or_else(|| {
            Error::Protocol("gateway sent challenge but no Ed25519 identity is configured".into())
        })?;

        let nonce_b64 = payload
            .as_ref()
            .and_then(|p| p.get("nonce"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Protocol("challenge event missing nonce".into()))?;

        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(nonce_b64)
            .map_err(|e| Error::Protocol(format!("invalid challenge nonce encoding: {e}")))?;

        debug!(nonce_len = nonce_bytes.len(), "signing challenge nonce");

        let signature = identity.sign(&nonce_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let response_frame = serde_json::json!({
            "type": "req",
            "id": uuid::Uuid::new_v4().to_string(),
            "method": "node.auth.challenge-response",
            "params": {
                "signature": sig_b64,
            }
        });

        let json = serde_json::to_string(&response_frame)?;
        ws_tx
            .send(Message::Text(json.into()))
            .await
            .map_err(|e| Error::Protocol(format!("failed to send challenge response: {e}")))?;

        info!("challenge response sent");
        Ok(())
    }

    async fn handle_message(
        &self,
        text: &str,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ) {
        // Try to parse as a GatewayFrame to determine the type.
        let frame: GatewayFrame = match serde_json::from_str(text) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "failed to parse frame, ignoring");
                return;
            },
        };

        match frame {
            GatewayFrame::Event(event) => {
                if event.event == "node.invoke.request" {
                    self.handle_invoke(event.payload, ws_tx).await;
                } else {
                    debug!(event = %event.event, "ignoring event");
                }
            },
            GatewayFrame::Request(req) => {
                debug!(method = %req.method, id = %req.id, "ignoring server request");
            },
            GatewayFrame::Response(_) => {
                debug!("ignoring response frame");
            },
        }
    }

    async fn handle_invoke(
        &self,
        payload: Option<serde_json::Value>,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ) {
        let payload = match payload {
            Some(p) => p,
            None => return,
        };

        let invoke_id = match payload.get("invokeId").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => {
                warn!("invoke request missing invokeId");
                return;
            },
        };

        let command = match payload.get("command").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => {
                warn!(invoke_id = %invoke_id, "invoke request missing command");
                self.send_invoke_error(&invoke_id, "missing command", ws_tx)
                    .await;
                return;
            },
        };

        let args = payload.get("args").cloned().unwrap_or_default();

        info!(invoke_id = %invoke_id, command = %command, "handling invoke");

        let result = match command {
            SYSTEM_EXEC_COMMAND => self.handle_system_exec(&args).await,
            "system.which" => self.handle_system_which(&args).await,
            "system.providers" => self.handle_system_providers().await,
            other => {
                warn!(command = %other, "unsupported invoke command");
                Err(Error::Command(format!("unsupported command: {other}")))
            },
        };

        match result {
            Ok(value) => {
                self.send_invoke_result(&invoke_id, value, ws_tx).await;
            },
            Err(e) => {
                self.send_invoke_error(&invoke_id, &e.to_string(), ws_tx)
                    .await;
            },
        }
    }

    async fn handle_system_exec(&self, args: &serde_json::Value) -> Result<serde_json::Value> {
        let request: SystemExecRequest = serde_json::from_value(args.clone())
            .map_err(|error| Error::Command(format!("invalid system.exec.v1 request: {error}")))?;
        if let Some(argument) = request.args.iter().find(|argument| argument.contains('\0')) {
            return Err(Error::Command(format!(
                "process argument contains NUL: {argument:?}"
            )));
        }
        if request.cwd.as_deref().is_some_and(|cwd| cwd.contains('\0'))
            || request.env.values().any(|value| value.contains('\0'))
        {
            return Err(Error::Command(
                "working directory and environment values must not contain NUL".into(),
            ));
        }
        let program = self.resolve_allowed_program(&request.program)?;
        let cwd = self.resolve_cwd(request.cwd.as_deref()).await?;
        let configured_timeout_ms =
            u64::try_from(self.config.exec_timeout.as_millis()).unwrap_or(u64::MAX);
        let timeout_ms = request.timeout_ms.min(configured_timeout_ms).max(1);
        let timeout = Duration::from_millis(timeout_ms);

        if let Some(key) = request.env.keys().find(|key| !is_safe_remote_env_key(key)) {
            return Err(Error::Command(format!(
                "environment variable '{key}' is not allowed for node execution"
            )));
        }

        info!(program = %program.display(), timeout_ms, "system.exec.v1");

        let mut cmd = Command::new(program);
        cmd.args(&request.args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.stdin(Stdio::null());
        cmd.current_dir(cwd);
        cmd.env_clear();
        cmd.envs(request.env);

        let mut child = OwnedProcessTree::spawn(cmd)?;
        let stdout = child
            .take_stdout()
            .ok_or_else(|| Error::Command("failed to capture command stdout".into()))?;
        let stderr = child
            .take_stderr()
            .ok_or_else(|| Error::Command("failed to capture command stderr".into()))?;
        let result = tokio::time::timeout(timeout, async {
            tokio::try_join!(
                child.wait(),
                read_output_limited(stdout),
                read_output_limited(stderr)
            )
        })
        .await;

        match result {
            Ok(Ok((status, stdout, stderr))) => {
                let exit_code = status.code().unwrap_or(-1);

                Ok(serde_json::json!({
                    "stdout": stdout,
                    "stderr": stderr,
                    "exitCode": exit_code,
                }))
            },
            Ok(Err(e)) => Err(Error::Command(format!("failed to execute command: {e}"))),
            Err(_) => {
                child.kill().await?;
                Err(Error::Command(format!(
                    "command timed out after {timeout_ms}ms"
                )))
            },
        }
    }

    fn resolve_allowed_program(&self, requested: &str) -> Result<PathBuf> {
        if requested.is_empty() || requested.contains('\0') {
            return Err(Error::Command(
                "program must not be empty or contain NUL".into(),
            ));
        }

        let path = which::which(requested).map_err(|error| {
            Error::Command(format!("cannot resolve program '{requested}': {error}"))
        })?;
        let resolved = std::fs::canonicalize(&path).map_err(|error| {
            Error::Command(format!(
                "cannot canonicalize program '{}': {error}",
                path.display()
            ))
        })?;

        let allowed = self.config.allowed_programs.iter().any(|program| {
            which::which(program)
                .ok()
                .and_then(|path| std::fs::canonicalize(path).ok())
                .is_some_and(|path| path == resolved)
        });
        if !allowed {
            return Err(Error::Command(format!(
                "program '{}' is not allowed by this node",
                resolved.display()
            )));
        }

        Ok(resolved)
    }

    async fn resolve_cwd(&self, requested: Option<&str>) -> Result<PathBuf> {
        let root = self
            .config
            .working_dir
            .as_deref()
            .map(PathBuf::from)
            .or_else(moltis_config::home_dir)
            .ok_or_else(|| Error::Command("cannot determine node execution root".into()))?;
        let root = tokio::fs::canonicalize(&root).await.map_err(|error| {
            Error::Command(format!(
                "cannot resolve execution root '{}': {error}",
                root.display()
            ))
        })?;
        let requested = requested.map(PathBuf::from).unwrap_or_else(|| root.clone());
        let requested = if requested.is_absolute() {
            requested
        } else {
            root.join(requested)
        };
        let cwd = tokio::fs::canonicalize(&requested).await.map_err(|error| {
            Error::Command(format!(
                "cannot resolve working directory '{}': {error}",
                requested.display()
            ))
        })?;
        if !cwd.starts_with(&root) {
            return Err(Error::Command(format!(
                "working directory '{}' is outside execution root '{}'",
                cwd.display(),
                root.display()
            )));
        }
        Ok(cwd)
    }

    async fn handle_system_which(&self, args: &serde_json::Value) -> Result<serde_json::Value> {
        let binary = args
            .get("binary")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Command("missing 'binary' in args".into()))?;

        let output = Command::new("which").arg(binary).output().await?;

        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let found = output.status.success();

        Ok(serde_json::json!({
            "found": found,
            "path": if found { Some(path) } else { None },
        }))
    }

    async fn handle_system_providers(&self) -> Result<serde_json::Value> {
        let mut providers = Vec::new();

        // Check Ollama at localhost:11434.
        if let Ok(resp) = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .timeout(Duration::from_secs(3))
            .send()
            .await
            && resp.status().is_success()
            && let Ok(body) = resp.json::<serde_json::Value>().await
        {
            let models: Vec<String> = body
                .get("models")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            providers.push(serde_json::json!({
                "provider": "ollama",
                "models": models,
            }));
        }

        // Check for known API key env vars (presence only, never the values).
        let api_key_checks = [
            ("OPENAI_API_KEY", "openai"),
            ("ANTHROPIC_API_KEY", "anthropic"),
            ("GOOGLE_API_KEY", "google"),
            ("MISTRAL_API_KEY", "mistral"),
            ("GROQ_API_KEY", "groq"),
            ("TOGETHER_API_KEY", "together"),
        ];
        for (env_var, provider_name) in api_key_checks {
            if std::env::var(env_var).is_ok_and(|v| !v.is_empty()) {
                providers.push(serde_json::json!({
                    "provider": provider_name,
                    "models": [],
                }));
            }
        }

        Ok(serde_json::json!({ "providers": providers }))
    }

    async fn send_invoke_result(
        &self,
        invoke_id: &str,
        result: serde_json::Value,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ) {
        let frame = serde_json::json!({
            "type": "req",
            "id": uuid::Uuid::new_v4().to_string(),
            "method": "node.invoke.result",
            "params": {
                "invokeId": invoke_id,
                "result": result,
            }
        });

        if let Ok(json) = serde_json::to_string(&frame)
            && let Err(e) = ws_tx.send(Message::Text(json.into())).await
        {
            warn!(invoke_id = %invoke_id, error = %e, "failed to send invoke result");
        }
    }

    /// Send one telemetry frame.
    ///
    /// Returns `Err` when the frame could not be handed to the sink. A failed
    /// write means the link is gone: the caller must not keep looping on a
    /// sink that can no longer deliver anything.
    async fn send_telemetry(
        &self,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ) -> Result<()> {
        let telemetry = collect_system_telemetry(&self.config.node_id);
        let frame = serde_json::json!({
            "type": "req",
            "id": uuid::Uuid::new_v4().to_string(),
            "method": "node.event",
            "params": {
                "event": "node.telemetry",
                "payload": telemetry,
            }
        });

        let json = serde_json::to_string(&frame)?;
        if let Err(e) = ws_tx.send(Message::Text(json.into())).await {
            debug!(error = %e, "failed to send telemetry");
            return Err(e.into());
        }

        Ok(())
    }

    async fn send_invoke_error(
        &self,
        invoke_id: &str,
        error: &str,
        ws_tx: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ) {
        let frame = serde_json::json!({
            "type": "req",
            "id": uuid::Uuid::new_v4().to_string(),
            "method": "node.invoke.result",
            "params": {
                "invokeId": invoke_id,
                "result": { "error": error },
            }
        });

        if let Ok(json) = serde_json::to_string(&frame)
            && let Err(e) = ws_tx.send(Message::Text(json.into())).await
        {
            warn!(invoke_id = %invoke_id, error = %e, "failed to send invoke error");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn default_config_has_structured_exec_cap() {
        let config = NodeConfig::default();
        assert!(config.caps.contains(&SYSTEM_EXEC_COMMAND.to_string()));
        assert!(config.commands.contains(&SYSTEM_EXEC_COMMAND.to_string()));
    }

    #[test]
    fn default_config_platform_is_current_os() {
        let config = NodeConfig::default();
        assert_eq!(config.platform, std::env::consts::OS);
    }

    #[tokio::test]
    async fn command_output_is_bounded() {
        let input = vec![b'x'; MAX_OUTPUT_BYTES + 1024];
        let output = read_output_limited(input.as_slice()).await.unwrap();
        assert!(output.ends_with("... [output truncated]"));
        assert!(output.len() <= MAX_OUTPUT_BYTES + 24);
    }

    #[test]
    fn worst_case_output_fits_protocol_payload() {
        let stream = "\0".repeat(MAX_OUTPUT_BYTES);
        let payload = serde_json::to_vec(&serde_json::json!({
            "stdout": stream,
            "stderr": stream,
            "exitCode": 0,
        }))
        .unwrap();
        assert!(payload.len() < moltis_protocol::MAX_PAYLOAD_BYTES);
    }

    #[tokio::test]
    async fn system_which_finds_sh() {
        let config = NodeConfig::default();
        let host = NodeHost::new(config);
        let args = serde_json::json!({ "binary": "sh" });
        let result = host.handle_system_which(&args).await.unwrap();
        assert_eq!(result["found"], true);
        assert!(result["path"].as_str().unwrap().contains("sh"));
    }

    #[tokio::test]
    async fn system_which_missing_binary() {
        let config = NodeConfig::default();
        let host = NodeHost::new(config);
        let args = serde_json::json!({ "binary": "definitely_not_a_real_binary_123456" });
        let result = host.handle_system_which(&args).await.unwrap();
        assert_eq!(result["found"], false);
    }

    #[tokio::test]
    async fn system_exec_preserves_metacharacter_argument_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let printf = which::which("printf").unwrap();
        let config = NodeConfig {
            working_dir: Some(temp.path().to_string_lossy().into_owned()),
            allowed_programs: vec![printf.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let host = NodeHost::new(config);
        let literal = "a b; touch sentinel && $(id) | * > output";
        let args = serde_json::to_value(SystemExecRequest {
            program: printf.to_string_lossy().into_owned(),
            args: vec!["%s".into(), literal.into()],
            cwd: None,
            env: std::collections::HashMap::new(),
            timeout_ms: 5000,
        })
        .unwrap();

        let result = host.handle_system_exec(&args).await.unwrap();
        assert_eq!(result["stdout"], literal);
        assert_eq!(result["exitCode"], 0);
        assert!(!temp.path().join("sentinel").exists());
        assert!(!temp.path().join("output").exists());
    }

    #[tokio::test]
    async fn system_exec_rejects_dangerous_environment() {
        let temp = tempfile::tempdir().unwrap();
        let printf = which::which("printf").unwrap();
        let config = NodeConfig {
            working_dir: Some(temp.path().to_string_lossy().into_owned()),
            allowed_programs: vec![printf.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let host = NodeHost::new(config);
        let args = serde_json::json!({
            "program": printf,
            "args": ["hello"],
            "env": { "LD_PRELOAD": "/tmp/evil.so" },
            "timeoutMs": 5000,
        });
        let error = host.handle_system_exec(&args).await.unwrap_err();
        assert!(error.to_string().contains("LD_PRELOAD"));
    }

    #[tokio::test]
    async fn system_exec_rejects_program_outside_allowlist() {
        let temp = tempfile::tempdir().unwrap();
        let printf = which::which("printf").unwrap();
        let config = NodeConfig {
            working_dir: Some(temp.path().to_string_lossy().into_owned()),
            allowed_programs: Vec::new(),
            ..Default::default()
        };
        let host = NodeHost::new(config);
        let args = serde_json::json!({
            "program": printf,
            "args": ["hello"],
            "timeoutMs": 5000,
        });

        let error = host.handle_system_exec(&args).await.unwrap_err();
        assert!(error.to_string().contains("not allowed by this node"));
    }

    /// Regression test for #744: `connect_async("wss://...")` panicked on
    /// Windows because no rustls `CryptoProvider` was installed in the
    /// node-host code path.  After the fix, `run()` returns a connection
    /// error instead of panicking.
    #[tokio::test]
    async fn wss_url_does_not_panic_without_crypto_provider() {
        let config = NodeConfig {
            gateway_url: "wss://127.0.0.1:1/ws".into(),
            device_token: "test-token".into(),
            ..Default::default()
        };
        let node = NodeHost::new(config);
        // Should return Err (unreachable host), NOT panic.
        // Wrap in a timeout so the test doesn't hang if a firewall silently
        // drops packets to 127.0.0.1:1 instead of refusing immediately.
        let result = tokio::time::timeout(Duration::from_secs(5), node.run())
            .await
            .expect("timed out — possible firewall drop on 127.0.0.1:1");
        assert!(result.is_err(), "expected connection error, got Ok");
    }

    #[tokio::test]
    async fn system_exec_rejects_cwd_outside_execution_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let printf = which::which("printf").unwrap();
        let config = NodeConfig {
            working_dir: Some(root.path().to_string_lossy().into_owned()),
            allowed_programs: vec![printf.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let host = NodeHost::new(config);
        let args = serde_json::to_value(SystemExecRequest {
            program: printf.to_string_lossy().into_owned(),
            args: vec!["hello".into()],
            cwd: Some(outside.path().to_string_lossy().into_owned()),
            env: std::collections::HashMap::new(),
            timeout_ms: 5000,
        })
        .unwrap();

        let error = host.handle_system_exec(&args).await.unwrap_err();
        assert!(error.to_string().contains("outside execution root"));
    }

    /// A sink that rejects every send, the way a socket behaves once its route
    /// is gone: the write never leaves the host.
    struct DeadLinkSink;

    impl futures::Sink<Message> for DeadLinkSink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(
            self: std::pin::Pin<&mut Self>,
            _item: Message,
        ) -> std::result::Result<(), Self::Error> {
            Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn send_telemetry_reports_a_failed_send() {
        let host = NodeHost::new(NodeConfig::default());
        let mut sink = DeadLinkSink;

        let result = host.send_telemetry(&mut sink).await;

        assert!(
            result.is_err(),
            "a telemetry send that never left the host must be reported to the caller"
        );
    }

    /// A stream that never yields, the way a black-holed read side behaves:
    /// nothing arrives and nothing closes.
    struct PendingStream;

    impl futures::Stream for PendingStream {
        type Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Pending
        }
    }

    /// The state a real socket cannot be put into, which is why `run_loop` is a
    /// seam: the write side is gone while the read side stays pending, so the
    /// loop's read arm never fires and only the telemetry arm can end it.
    #[tokio::test]
    async fn run_loop_ends_when_telemetry_cannot_be_sent() {
        let config = NodeConfig {
            telemetry_interval: Duration::from_millis(100),
            ..Default::default()
        };
        let host = NodeHost::new(config);
        let mut ws_tx = DeadLinkSink;
        let mut ws_rx = PendingStream;

        let ended = tokio::time::timeout(
            Duration::from_secs(3),
            host.run_loop(&mut ws_tx, &mut ws_rx),
        )
        .await;

        assert!(
            ended.is_ok(),
            "the run loop must end once telemetry can no longer be delivered"
        );
    }

    /// A gateway that completes the v4 handshake and then stops answering.
    ///
    /// Replying `hello-ok` is the point: `run()` blocks in `complete_handshake`
    /// before the loop is ever reached, so a server that merely accepts the
    /// socket would end `run()` through the handshake timeout - red and green
    /// for the wrong reason.
    async fn gateway_that_goes_silent_after_hello() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            while let Some(Ok(message)) = ws.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                if frame.get("method").and_then(serde_json::Value::as_str) != Some("connect") {
                    continue;
                }
                let hello = serde_json::json!({
                    "type": "res",
                    "id": frame.get("id").and_then(serde_json::Value::as_str).unwrap_or_default(),
                    "ok": true,
                    "payload": { "server": { "version": "test" } },
                });
                ws.send(Message::Text(hello.to_string().into()))
                    .await
                    .unwrap();
                break;
            }

            // Go silent: hold the socket open and never poll it again, so an
            // inbound Ping is never answered. Dropping `ws` would close the
            // connection and end the loop through the read arm instead.
            std::future::pending::<()>().await;
        });

        format!("ws://{addr}/ws")
    }

    #[tokio::test]
    async fn run_ends_when_the_peer_stops_answering() {
        let config = NodeConfig {
            gateway_url: gateway_that_goes_silent_after_hello().await,
            // `identity: None` keeps the handshake timeout at 10 s; an identity
            // raises it to 310 s, which would look exactly like the hang this
            // test exists to rule out.
            identity: None,
            // Long enough that the telemetry break cannot be what ends the run.
            telemetry_interval: Duration::from_secs(60),
            pong_deadline: Duration::from_millis(200),
            ..Default::default()
        };
        let host = NodeHost::new(config);

        let ended = tokio::time::timeout(Duration::from_secs(5), host.run()).await;

        assert!(
            ended.is_ok(),
            "the run loop must end when the peer stops answering liveness pings"
        );
    }
}
