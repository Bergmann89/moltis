use std::sync::Arc;

use {
    async_trait::async_trait,
    secrecy::{ExposeSecret, Secret},
    tracing::{info, warn},
};

use crate::auth;

use crate::server::CoreStartupProfile;

pub(super) fn gateway_credentials_allowed(
    profile: CoreStartupProfile,
    network: &moltis_tools::sandbox::NetworkPolicy,
) -> bool {
    !profile.is_headless() && *network != moltis_tools::sandbox::NetworkPolicy::Blocked
}

pub(super) struct CredentialEnvVarProvider {
    pub(super) store: Arc<auth::CredentialStore>,
    pub(super) gateway_url: Option<String>,
    pub(super) sandbox_api_key: Option<Secret<String>>,
}

#[async_trait]
impl moltis_tools::exec::EnvVarProvider for CredentialEnvVarProvider {
    async fn get_env_vars(&self) -> Vec<(String, Secret<String>)> {
        let mut vars = match self.store.get_all_env_values().await {
            Ok(values) => values
                .into_iter()
                .filter(|(key, _)| !key.starts_with("__MOLTIS_"))
                .map(|(key, value)| (key, Secret::new(value)))
                .collect(),
            Err(error) => {
                warn!(error = %error, "failed to load runtime env overrides for tools");
                Vec::new()
            },
        };

        if let Some(ref url) = self.gateway_url {
            vars.push(("MOLTIS_GATEWAY_URL".into(), Secret::new(url.clone())));
        }
        if let Some(ref key) = self.sandbox_api_key {
            vars.push((
                "MOLTIS_API_KEY".into(),
                Secret::new(key.expose_secret().clone()),
            ));
        }

        vars
    }
}

/// Label every sandbox API key is minted under.
const SANDBOX_API_KEY_LABEL: &str = "sandbox-ctl";

/// Env var the current sandbox API key is cached in.
///
/// Versioned, and that version bump is the whole point. The v1 name cached a
/// key minted with `operator.write`, and this function returns the cached key
/// before it ever looks at the scope list - so narrowing the mint on its own
/// would have fixed fresh installs and left every existing one holding a
/// read+write key forever. A new name means an install that has only the v1
/// entry falls through to the mint path exactly once, on its next startup,
/// with no operator action anywhere.
const SANDBOX_API_KEY_ENV: &str = "__MOLTIS_SANDBOX_API_KEY_V2";

/// The pre-rotation name. Read only to notice it and retire what it points at.
const SANDBOX_API_KEY_ENV_V1: &str = "__MOLTIS_SANDBOX_API_KEY";

pub(super) async fn ensure_sandbox_api_key(store: &auth::CredentialStore) -> Option<String> {
    // A read failure is not "there is no cached key". `if let Ok(..)` fell
    // through on any store error straight into retire-and-mint, which revokes
    // the key every running sandbox is still holding over a transient sqlite
    // hiccup. Give up for this startup instead: a sandbox without
    // `MOLTIS_API_KEY` loses `moltis-ctl`, while a revoked live key breaks
    // every sandbox already up.
    let vals = match store.get_all_env_values().await {
        Ok(vals) => vals,
        Err(e) => {
            warn!(error = %e, "failed to read credential store, leaving the sandbox API key alone");
            return None;
        },
    };
    if let Some((_, key)) = vals.iter().find(|(k, _)| k == SANDBOX_API_KEY_ENV) {
        return Some(key.clone());
    }

    retire_old_sandbox_api_keys(store).await;

    let scopes = auth::SANDBOX_API_KEY_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    match store
        .create_api_key(SANDBOX_API_KEY_LABEL, Some(&scopes))
        .await
    {
        Ok((_id, raw_key)) => {
            if let Err(e) = store.set_env_var(SANDBOX_API_KEY_ENV, &raw_key).await {
                warn!(error = %e, "failed to persist sandbox API key");
            }
            info!(scopes = ?scopes, "created sandbox-ctl API key for moltis-ctl");
            Some(raw_key)
        },
        Err(e) => {
            warn!(error = %e, "failed to create sandbox API key");
            None
        },
    }
}

/// Revoke every previously minted sandbox key and drop the v1 cache entry.
///
/// Revoked rather than merely orphaned: the raw v1 key was handed to every
/// sandbox that ever ran, so leaving the row live would leave a read+write
/// credential valid on the gateway for anything that kept a copy. Best effort
/// throughout - a failure here must not stop the narrower key being minted,
/// because a startup that gives up leaves the old key in place, which is the
/// state this is here to end.
async fn retire_old_sandbox_api_keys(store: &auth::CredentialStore) {
    match store.list_api_keys().await {
        Ok(keys) => {
            for entry in keys.iter().filter(|e| e.label == SANDBOX_API_KEY_LABEL) {
                if let Err(e) = store.revoke_api_key(entry.id).await {
                    warn!(error = %e, id = entry.id, "failed to revoke old sandbox API key");
                } else {
                    info!(id = entry.id, "revoked pre-rotation sandbox-ctl API key");
                }
            }
        },
        Err(e) => warn!(error = %e, "failed to list API keys while rotating the sandbox key"),
    }

    match store.list_env_vars().await {
        Ok(vars) => {
            for var in vars.iter().filter(|v| v.key == SANDBOX_API_KEY_ENV_V1) {
                if let Err(e) = store.delete_env_var(var.id).await {
                    warn!(error = %e, "failed to drop the pre-rotation sandbox key env var");
                }
            }
        },
        Err(e) => warn!(error = %e, "failed to list env vars while rotating the sandbox key"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use sqlx::SqlitePool;

    async fn memory_store() -> auth::CredentialStore {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite");
        auth::CredentialStore::new(pool)
            .await
            .expect("credential store")
    }

    async fn sandbox_key_scopes(
        store: &auth::CredentialStore,
        raw_key: &str,
    ) -> Option<Vec<String>> {
        store
            .verify_api_key(raw_key)
            .await
            .expect("verify")
            .map(|verification| verification.scopes)
    }

    #[tokio::test]
    async fn existing_install_with_a_read_write_sandbox_key_is_rotated_to_read_only() {
        // An install from before the fix: a sandbox key minted with
        // operator.write, already cached under the v1 env name. Nothing about
        // it is touched by an operator - the next startup has to retire it on
        // its own, or narrowing the mint only ever helps fresh installs.
        let store = memory_store().await;
        let legacy_scopes = vec!["operator.read".to_string(), "operator.write".to_string()];
        let (_legacy_id, legacy_key) = store
            .create_api_key("sandbox-ctl", Some(&legacy_scopes))
            .await
            .expect("legacy key");
        store
            .set_env_var("__MOLTIS_SANDBOX_API_KEY", &legacy_key)
            .await
            .expect("cache legacy key");

        let key = ensure_sandbox_api_key(&store).await.expect("sandbox key");

        assert_eq!(
            sandbox_key_scopes(&store, &key).await,
            Some(
                auth::SANDBOX_API_KEY_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_string())
                    .collect::<Vec<_>>()
            ),
            "the key handed to the sandbox must carry the minted scopes"
        );
        assert!(
            !key.eq(&legacy_key),
            "the read+write key must not be handed out again"
        );
        assert!(
            sandbox_key_scopes(&store, &legacy_key).await.is_none(),
            "the read+write key must be revoked, not merely unused"
        );
    }

    #[tokio::test]
    async fn the_rotated_sandbox_key_is_stable_across_startups() {
        let store = memory_store().await;
        let first = ensure_sandbox_api_key(&store).await.expect("first key");
        let second = ensure_sandbox_api_key(&store).await.expect("second key");
        assert_eq!(
            first, second,
            "a settled install must not re-mint every boot"
        );
        assert_eq!(
            store
                .list_api_keys()
                .await
                .expect("list")
                .iter()
                .filter(|entry| entry.label == "sandbox-ctl")
                .count(),
            1,
            "re-minting on every startup would leak a key per boot"
        );
    }

    #[test]
    fn headless_profiles_never_create_gateway_credentials() {
        assert!(!gateway_credentials_allowed(
            CoreStartupProfile::Headless,
            &moltis_tools::sandbox::NetworkPolicy::Trusted,
        ));
        assert!(!gateway_credentials_allowed(
            CoreStartupProfile::Headless,
            &moltis_tools::sandbox::NetworkPolicy::Bypass,
        ));
    }
}
