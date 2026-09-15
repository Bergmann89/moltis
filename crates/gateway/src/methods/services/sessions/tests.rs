//! The forced-sandbox flag as the browser and the write path actually meet it.
//!
//! The router unit tests one layer down build an `AgentSandboxPolicy` in code
//! and assert `is_sandboxed` beats a session override. They were green while
//! the flag never reached the browser and the write path took the override
//! anyway, because neither of them loads a preset: the seam they miss is
//! *which* config instance answers the question and *when* it was loaded.
//!
//! So these start from a preset file written after the gateway state exists.
//! That is not a contrived order - `ctrl update` recreates the container and
//! then provisions, so on a real deployment the presets land a second after
//! the gateway started, every time.

use {
    super::*,
    crate::{
        auth::{AuthMode, ResolvedAuth},
        services::GatewayServices,
        session::LiveSessionService,
        state::GatewayState,
    },
    moltis_protocol::ResponseFrame,
    moltis_sessions::{metadata::SqliteSessionMetadata, store::SessionStore},
    std::sync::Arc,
};

/// Points `data_dir()` at a temporary directory for the length of one test and
/// puts it back afterwards, panic or not: the override is process-global.
///
/// Holds the crate's config-override lock while it lives, which is what keeps
/// it apart from every *other* test that repoints the same global - a
/// `serial_test` key only orders the tests that name it.
struct DataDirGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
}

impl DataDirGuard {
    fn new() -> Self {
        let lock = crate::config_override_test_lock();
        let dir = tempfile::tempdir().expect("a temp data dir");
        moltis_config::set_data_dir(dir.path().to_path_buf());
        Self { _lock: lock, dir }
    }

    /// Write a markdown agent definition, the way provisioning does.
    fn write_agent_def(&self, name: &str, frontmatter: &str) {
        let agents = self.dir.path().join("agents");
        std::fs::create_dir_all(&agents).expect("the agents dir");
        std::fs::write(
            agents.join(format!("{name}.md")),
            format!("---\nname: {name}\n{frontmatter}---\nBe careful.\n"),
        )
        .expect("the agent definition");
    }
}

impl Drop for DataDirGuard {
    fn drop(&mut self) {
        moltis_config::clear_data_dir();
    }
}

async fn sqlite_pool() -> sqlx::SqlitePool {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("an in-memory database");
    moltis_projects::run_migrations(&pool)
        .await
        .expect("the project migrations");
    SqliteSessionMetadata::init(&pool)
        .await
        .expect("the session schema");
    pool
}

/// A gateway state whose only session belongs to `agent_id`.
///
/// The temp dir comes back with it so the session store outlives the call.
async fn state_with_session(
    key: &str,
    agent_id: &str,
) -> (
    Arc<GatewayState>,
    Arc<SqliteSessionMetadata>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("a session store dir");
    let store = Arc::new(SessionStore::new(dir.path().to_path_buf()));
    let metadata = Arc::new(SqliteSessionMetadata::new(sqlite_pool().await));
    metadata.upsert(key, None).await.expect("the session");
    metadata
        .set_agent_id(key, Some(agent_id))
        .await
        .expect("the session's agent");
    let service = LiveSessionService::new(store, Arc::clone(&metadata));
    let state = GatewayState::new(
        ResolvedAuth {
            mode: AuthMode::Token,
            token: None,
            password: None,
        },
        GatewayServices::noop().with_session(Arc::new(service)),
    );
    (state, metadata, dir)
}

async fn dispatch(
    state: Arc<GatewayState>,
    method: &str,
    params: serde_json::Value,
) -> ResponseFrame {
    MethodRegistry::new()
        .dispatch(MethodContext {
            request_id: String::from("test"),
            method: method.to_string(),
            params,
            client_conn_id: String::from("conn-1"),
            client_role: String::from("operator"),
            client_scopes: vec![String::from("operator.admin")],
            state,
            channel: None,
        })
        .await
}

fn entry_in_list(response: &ResponseFrame, key: &str) -> serde_json::Value {
    response
        .payload
        .as_ref()
        .and_then(|payload| payload.as_array())
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.get("key").and_then(|k| k.as_str()) == Some(key))
        })
        .cloned()
        .unwrap_or_else(|| panic!("sessions.list must list {key}: {response:?}"))
}

#[tokio::test]
async fn sessions_list_reports_a_preset_written_after_the_gateway_started() {
    let guard = DataDirGuard::new();
    // State first, preset second - the deployment's own order.
    let (state, _metadata, _dir) = state_with_session("session:walter", "walter").await;
    guard.write_agent_def("walter", "sandbox_force: true\n");

    let response = dispatch(Arc::clone(&state), "sessions.list", serde_json::json!({})).await;

    assert!(response.ok, "sessions.list must succeed: {response:?}");
    let entry = entry_in_list(&response, "session:walter");
    assert_eq!(
        entry.get("sandbox_forced"),
        Some(&serde_json::Value::Bool(true)),
        "the flag the UI reads must come from the presets on disk, not from a \
         snapshot taken before they were written: {entry}"
    );
}

#[tokio::test]
async fn sessions_list_does_not_force_an_agent_that_only_configures_its_sandbox() {
    let guard = DataDirGuard::new();
    let (state, _metadata, _dir) = state_with_session("session:walter", "walter").await;
    guard.write_agent_def(
        "walter",
        "sandbox_mounts: \"/srv/vault:/srv/vault:ro\"\nrun_as: \"1000:1000\"\n",
    );

    let response = dispatch(Arc::clone(&state), "sessions.list", serde_json::json!({})).await;

    let entry = entry_in_list(&response, "session:walter");
    assert_eq!(
        entry.get("sandbox_forced"),
        Some(&serde_json::Value::Bool(false)),
        "mounts and a run_as configure the sandbox; only force takes the \
         toggle away: {entry}"
    );
}

#[tokio::test]
async fn sessions_patch_refuses_to_disable_a_forced_sandbox() {
    let guard = DataDirGuard::new();
    let (state, metadata, _dir) = state_with_session("session:walter", "walter").await;
    guard.write_agent_def("walter", "sandbox_force: true\n");

    let response = dispatch(
        Arc::clone(&state),
        "sessions.patch",
        serde_json::json!({ "key": "session:walter", "sandboxEnabled": false }),
    )
    .await;

    assert!(
        !response.ok,
        "disabling a forced agent's sandbox must be refused, not accepted and \
         then ignored by the router: {response:?}"
    );
    let message = response
        .error
        .as_ref()
        .map(|error| error.message.clone())
        .unwrap_or_default();
    assert!(
        message.contains("force"),
        "the refusal must say why, got: {message}"
    );
    assert_ne!(
        metadata
            .get("session:walter")
            .await
            .and_then(|entry| entry.sandbox_enabled),
        Some(false),
        "a refused patch must not have written the override anyway"
    );
}

#[tokio::test]
async fn sessions_patch_still_enables_and_clears_a_forced_sandbox() {
    // Only switching it *off* is refused. Turning it on, and clearing the
    // override so the session follows the global mode again, stay open.
    let guard = DataDirGuard::new();
    let (state, _metadata, _dir) = state_with_session("session:walter", "walter").await;
    guard.write_agent_def("walter", "sandbox_force: true\n");

    for value in [serde_json::json!(true), serde_json::Value::Null] {
        let response = dispatch(
            Arc::clone(&state),
            "sessions.patch",
            serde_json::json!({ "key": "session:walter", "sandboxEnabled": value }),
        )
        .await;
        assert!(
            response.ok,
            "sandboxEnabled={value} must stay allowed for a forced agent: {response:?}"
        );
    }
}

#[tokio::test]
async fn sessions_switch_stamps_the_forced_flag_on_its_entry() {
    // The entry `sessions.switch` returns is what the UI restores session state
    // from on a cold load. Unstamped, it overwrote the flag the rendered
    // snapshot had already got right.
    let guard = DataDirGuard::new();
    let (state, _metadata, _dir) = state_with_session("session:walter", "walter").await;
    guard.write_agent_def("walter", "sandbox_force: true\n");

    let response = dispatch(
        Arc::clone(&state),
        "sessions.switch",
        serde_json::json!({ "key": "session:walter", "include_history": false }),
    )
    .await;

    assert!(response.ok, "sessions.switch must succeed: {response:?}");
    let entry = response
        .payload
        .as_ref()
        .and_then(|payload| payload.get("entry"))
        .cloned()
        .unwrap_or_else(|| panic!("sessions.switch must return an entry: {response:?}"));
    assert_eq!(
        entry.get("sandbox_forced"),
        Some(&serde_json::Value::Bool(true)),
        "the switch entry must carry the flag too: {entry}"
    );
}
