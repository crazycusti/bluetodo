use axum::{
    Form, Router,
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, Redirect},
    routing::{get, post},
};
use base64::Engine;
use bytes::Bytes;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use chrono::{Datelike, NaiveDate, NaiveDateTime, Utc};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use portable_atomic::AtomicU64;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnectOptions};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{ErrorKind, Write},
    net::SocketAddr,
    path::{Path as StdPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use zip::ZipArchive;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    metrics: MetricsState,
}

type AppResult<T> = Result<T, (StatusCode, String)>;

const SCHEMA_VERSION: i64 = 6;
const APP_ID: &str = "BLUETODO";
const LEGACY_APP_ID_WINTODO: &str = "WINTODO";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTO_DEFAULT_PORT: u16 = 5877;
const PROTO_VERSION: i64 = 2;
const RUSTC_VERSION: &str = env!("BLUETODO_RUSTC_VERSION");
const WIN16_UPDATE_TARGET: &str = "win16";
const NTPPC_UPDATE_TARGET_LEGACY: &str = "ntppc";
const NT4PPC_UPDATE_TARGET: &str = "nt4ppc";
const CLIENT_UPDATE_ARTIFACT_CLIENT: &str = "client";
const CLIENT_UPDATE_ARTIFACT_UPDATER: &str = "updater";
const CLIENT_UPDATE_CHUNK_SIZE: usize = 256;
const SECRET_STORAGE_META_KEY: &str = "secret_storage_version";
const SECRET_STORAGE_MIGRATED_AT_KEY: &str = "secret_storage_migrated_at";
const SECRET_STORAGE_VERSION: &str = "1";
const SECRET_VALUE_PREFIX: &str = "enc:v1:";
const SECRET_MASTER_KEY_ENV: &str = "BLUETODO_MASTER_KEY";
const SECRET_MASTER_KEY_FILE_ENV: &str = "BLUETODO_MASTER_KEY_FILE";
const SECRET_MASTER_KEY_LEN: usize = 32;
const SECRET_NONCE_LEN: usize = 24;
const SECRET_SETTING_KEYS: [&str; 4] = [
    "proto_token",
    "metrics_token",
    "metrics_v1_password",
    "update_password",
];

type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

mod paths;
mod secrets;
mod startup_backup;

use self::paths::{
    DbPathSource, default_secret_key_path, load_app_config, resolve_db_path, storage_dir,
    write_db_path_config,
};
use self::secrets::{
    SecretStorageInfo, decrypt_secret_value, encrypt_secret_value, inspect_secret_key_runtime,
    is_encrypted_secret_value, is_secret_setting_key, secret_storage_error,
};
use self::startup_backup::{DbStartupBackup, prepare_db_startup_backup};

#[derive(Clone)]
struct MetricsState {
    http_inflight: Arc<AtomicUsize>,
    http_requests_total: Arc<AtomicU64>,
    proto_connections: Arc<AtomicUsize>,
    proto_requests_total: Arc<AtomicU64>,
    client_request_counts: Arc<Mutex<HashMap<String, u64>>>,
    proto_client_connections: Arc<Mutex<HashMap<String, usize>>>,
    proto_command_counts: Arc<Mutex<HashMap<String, u64>>>,
    v1_db_checked: Arc<Mutex<HashSet<String>>>,
}

impl MetricsState {
    fn new() -> Self {
        MetricsState {
            http_inflight: Arc::new(AtomicUsize::new(0)),
            http_requests_total: Arc::new(AtomicU64::new(0)),
            proto_connections: Arc::new(AtomicUsize::new(0)),
            proto_requests_total: Arc::new(AtomicU64::new(0)),
            client_request_counts: Arc::new(Mutex::new(HashMap::new())),
            proto_client_connections: Arc::new(Mutex::new(HashMap::new())),
            proto_command_counts: Arc::new(Mutex::new(HashMap::new())),
            v1_db_checked: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn http_start(&self) {
        self.http_inflight.fetch_add(1, Ordering::Relaxed);
    }

    fn http_end(&self) {
        self.http_inflight.fetch_sub(1, Ordering::Relaxed);
    }

    async fn http_request(&self) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
        self.bump_client_request("web").await;
    }

    async fn bump_client_request(&self, label: &str) {
        let mut guard = self.client_request_counts.lock().await;
        let counter = guard.entry(label.to_string()).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    async fn proto_connect(&self, label: &str) {
        self.proto_connections.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.proto_client_connections.lock().await;
        let counter = guard.entry(label.to_string()).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    async fn proto_update_label(&self, old: &str, new: &str) {
        if old == new {
            return;
        }
        let mut guard = self.proto_client_connections.lock().await;
        if let Some(value) = guard.get_mut(old) {
            if *value > 0 {
                *value -= 1;
            }
            if *value == 0 {
                guard.remove(old);
            }
        }
        let entry = guard.entry(new.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    async fn proto_disconnect(&self, label: &str) {
        self.proto_connections.fetch_sub(1, Ordering::Relaxed);
        let mut guard = self.proto_client_connections.lock().await;
        if let Some(value) = guard.get_mut(label) {
            if *value > 0 {
                *value -= 1;
            }
            if *value == 0 {
                guard.remove(label);
            }
        }
    }

    async fn proto_request(&self, label: &str, command: &str) {
        self.proto_requests_total.fetch_add(1, Ordering::Relaxed);
        self.bump_client_request(label).await;
        let mut guard = self.proto_command_counts.lock().await;
        let entry = guard.entry(command.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_app_config();
    let db_path = config.db_path;
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let startup_backup = prepare_db_startup_backup(&db_path).await?;
    let options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePool::connect_with(options).await?;
    init_db(&pool, startup_backup.as_ref()).await?;

    let metrics = MetricsState::new();
    let state = AppState { pool, metrics };

    let metrics_state = state.clone();
    tokio::spawn(async move {
        run_metrics_loop(metrics_state).await;
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/todos", post(create_todo))
        .route("/todos/:id/update", post(update_todo))
        .route("/todos/:id/delete", post(delete_todo))
        .route("/todos/:id/archive", post(archive_todo))
        .route("/todos/:id/unarchive", post(unarchive_todo))
        .route("/todos/:id/pdf", get(get_todo_pdf))
        .route("/todos/:id/upload", post(upload_todo_pdf))
        .route("/todos/:id/tasks", post(add_task))
        .route("/tasks/:id/toggle", post(toggle_task))
        .route("/tasks/:id/update", post(update_task))
        .route("/config", get(show_config))
        .route("/archive", get(show_archive))
        .route("/config/auth", post(update_auth))
        .route("/config/currency", post(update_currency))
        .route("/config/db", post(update_db_path))
        .route("/config/text", post(update_ui_text))
        .route("/config/proto", post(update_proto))
        .route("/config/metrics", post(update_metrics))
        .route("/config/update", post(update_update_config))
        .route("/config/update-check", post(update_check))
        .route("/config/update-apply", post(update_apply))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            metrics_middleware,
        ));

    let addr = SocketAddr::from(([0, 0, 0, 0], 5876));
    println!("BlueTodo läuft auf http://{addr}");

    let proto_config = match load_proto_config(&state.pool).await {
        Ok(config) => config,
        Err((_status, message)) => {
            eprintln!("Proto-Config Fehler: {message}");
            ProtoConfig {
                enabled: false,
                port: PROTO_DEFAULT_PORT,
                token: String::new(),
            }
        }
    };
    if proto_config.enabled {
        let proto_state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = run_proto_server(proto_state, proto_config).await {
                eprintln!("Proto-Server Fehler: {err}");
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

async fn init_db(
    pool: &SqlitePool,
    startup_backup: Option<&DbStartupBackup>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    let app_id_row = sqlx::query("SELECT value FROM app_meta WHERE key = 'app_id'")
        .fetch_optional(pool)
        .await?;
    let stored_app_id = app_id_row.and_then(|row| row.try_get::<String, _>("value").ok());
    if let Some(existing) = stored_app_id.as_deref() {
        if existing != APP_ID && existing != LEGACY_APP_ID_WINTODO {
            return Err(sqlx::Error::Protocol(format!(
                "Datenbank gehört zu {}",
                existing
            )));
        }
        if existing != APP_ID {
            set_app_id(pool, APP_ID).await?;
        }
    } else {
        set_app_id(pool, APP_ID).await?;
    }

    let mut version = load_schema_version(pool).await?.unwrap_or(0);
    let legacy_manual_budget_upgrade =
        stored_app_id.as_deref() == Some(APP_ID) && version > 0 && version < 4;
    if version > SCHEMA_VERSION {
        return Err(sqlx::Error::Protocol(
            "Schema-Version ist neuer als der Server".to_string(),
        ));
    }

    if version < 1 {
        migrate_0_to_1(pool).await?;
        set_schema_version(pool, 1).await?;
        version = 1;
    }

    if version < 2 {
        migrate_1_to_2(pool).await?;
        set_schema_version(pool, 2).await?;
        version = 2;
    }

    if version < 3 {
        migrate_2_to_3(pool).await?;
        set_schema_version(pool, 3).await?;
        version = 3;
    }

    if version < 4 {
        migrate_3_to_4(pool).await?;
        set_schema_version(pool, 4).await?;
        version = 4;
    }

    if version < 5 {
        migrate_4_to_5(pool).await?;
        set_schema_version(pool, 5).await?;
        version = 5;
    }

    if version < 6 {
        migrate_5_to_6(pool).await?;
        set_schema_version(pool, 6).await?;
    }

    if legacy_manual_budget_upgrade {
        sqlx::query("UPDATE todos SET budget_manual = 1 WHERE budget_manual = 0")
            .execute(pool)
            .await?;
    }

    ensure_setting(pool, "auth_enabled", "0").await?;
    ensure_setting(pool, "currency_code", "EUR").await?;
    ensure_setting(pool, "currency_custom", "").await?;
    ensure_setting(pool, "dashboard_title", "BlueTodo Dashboard").await?;
    ensure_setting(
        pool,
        "dashboard_description",
        "Auftrags- und Todo-Board mit Fortschritt, Budget und Terminen.",
    )
    .await?;
    ensure_setting(pool, "proto_enabled", "0").await?;
    ensure_setting(pool, "proto_port", &PROTO_DEFAULT_PORT.to_string()).await?;
    ensure_setting(pool, "proto_token", "").await?;
    ensure_setting(pool, "metrics_enabled", "0").await?;
    ensure_setting(pool, "metrics_version", "v2").await?;
    ensure_setting(pool, "metrics_url", "").await?;
    ensure_setting(pool, "metrics_token", "").await?;
    ensure_setting(pool, "metrics_v1_url", "").await?;
    ensure_setting(pool, "metrics_v1_db", "").await?;
    ensure_setting(pool, "metrics_v1_user", "").await?;
    ensure_setting(pool, "metrics_v1_password", "").await?;
    ensure_setting(pool, "metrics_v1_autocreate", "1").await?;
    ensure_setting(pool, "metrics_interval", "30").await?;
    ensure_setting(pool, "metrics_instance", "").await?;
    ensure_setting(pool, "update_enabled", "0").await?;
    ensure_setting(pool, "update_url", "").await?;
    ensure_setting(pool, "update_user", "").await?;
    ensure_setting(pool, "update_password", "").await?;
    ensure_setting(pool, "update_channel", "stable").await?;
    ensure_setting(pool, "update_last_checked", "").await?;
    ensure_setting(pool, "update_last_status", "").await?;
    ensure_setting(pool, "update_available", "0").await?;
    ensure_setting(pool, "update_latest_version", "").await?;
    ensure_setting(pool, "update_latest_notes", "").await?;
    ensure_setting(pool, "update_latest_url", "").await?;
    ensure_setting(pool, "update_latest_sha256", "").await?;
    ensure_setting(pool, "update_latest_size", "").await?;
    migrate_secret_settings(pool).await?;
    set_app_version(pool, APP_VERSION).await?;
    set_proto_version(pool, PROTO_VERSION).await?;
    if let Some(backup) = startup_backup {
        record_startup_backup(pool, backup).await?;
    }
    normalize_update_status(pool).await?;

    Ok(())
}

async fn normalize_update_status(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let row = sqlx::query("SELECT value FROM settings WHERE key = 'update_last_status'")
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(());
    };
    let status: String = row.try_get("value").unwrap_or_default();
    if status.starts_with("Update installiert") {
        sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_last_status'")
            .bind("Aktuell")
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn ensure_column(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    alter_statement: &str,
) -> Result<(), sqlx::Error> {
    let pragma = format!("PRAGMA table_info({})", table);
    let rows = sqlx::query(&pragma).fetch_all(pool).await?;
    let exists = rows
        .iter()
        .any(|row| row.get::<String, _>("name") == column);
    if !exists {
        sqlx::query(alter_statement).execute(pool).await?;
    }
    Ok(())
}

async fn load_app_meta_value_raw(
    pool: &SqlitePool,
    key: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT value FROM app_meta WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|row| row.try_get::<String, _>("value").ok()))
}

async fn load_app_meta_i64_raw(pool: &SqlitePool, key: &str) -> Result<Option<i64>, sqlx::Error> {
    Ok(load_app_meta_value_raw(pool, key)
        .await?
        .and_then(|value| value.parse::<i64>().ok()))
}

async fn ensure_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO NOTHING
        "#,
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

async fn load_schema_version(pool: &SqlitePool) -> Result<Option<i64>, sqlx::Error> {
    let row = sqlx::query("SELECT value FROM app_meta WHERE key = 'schema_version'")
        .fetch_optional(pool)
        .await?;
    Ok(row
        .and_then(|row| row.try_get::<String, _>("value").ok())
        .and_then(|value| value.parse::<i64>().ok()))
}

async fn set_app_meta_value(pool: &SqlitePool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO app_meta (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        "#,
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

async fn set_schema_version(pool: &SqlitePool, version: i64) -> Result<(), sqlx::Error> {
    set_app_meta_value(pool, "schema_version", &version.to_string()).await
}

async fn set_app_version(pool: &SqlitePool, version: &str) -> Result<(), sqlx::Error> {
    set_app_meta_value(pool, "app_version", version).await
}

async fn set_proto_version(pool: &SqlitePool, version: i64) -> Result<(), sqlx::Error> {
    set_app_meta_value(pool, "proto_version", &version.to_string()).await
}

async fn set_app_id(pool: &SqlitePool, app_id: &str) -> Result<(), sqlx::Error> {
    set_app_meta_value(pool, "app_id", app_id).await
}

async fn record_startup_backup(
    pool: &SqlitePool,
    backup: &DbStartupBackup,
) -> Result<(), sqlx::Error> {
    set_app_meta_value(pool, "last_upgrade_backup_at", &backup.created_at).await?;
    set_app_meta_value(
        pool,
        "last_upgrade_backup_path",
        &backup.backup_path.to_string_lossy(),
    )
    .await?;
    set_app_meta_value(pool, "last_upgrade_reason", &backup.reason).await?;
    set_app_meta_value(
        pool,
        "last_upgrade_from_app_id",
        backup.from_app_id.as_deref().unwrap_or(""),
    )
    .await?;
    set_app_meta_value(
        pool,
        "last_upgrade_from_app_version",
        backup.from_app_version.as_deref().unwrap_or(""),
    )
    .await?;
    set_app_meta_value(
        pool,
        "last_upgrade_from_schema_version",
        &backup
            .from_schema_version
            .map(|value| value.to_string())
            .unwrap_or_default(),
    )
    .await?;
    set_app_meta_value(
        pool,
        "last_upgrade_from_proto_version",
        &backup
            .from_proto_version
            .map(|value| value.to_string())
            .unwrap_or_default(),
    )
    .await?;
    Ok(())
}

async fn migrate_0_to_1(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            order_number TEXT,
            purchaser TEXT,
            order_date TEXT,
            order_pdf TEXT,
            description TEXT,
            budget_spent REAL NOT NULL DEFAULT 0,
            budget_planned REAL NOT NULL DEFAULT 0,
            budget_manual INTEGER NOT NULL DEFAULT 0,
            deadline TEXT,
            archived_at TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            todo_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            amount REAL NOT NULL DEFAULT 0,
            done INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(todo_id) REFERENCES todos(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO settings (key, value)
        VALUES ('auth_enabled', '0')
        ON CONFLICT(key) DO NOTHING;
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn migrate_1_to_2(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    ensure_column(
        pool,
        "tasks",
        "description",
        "ALTER TABLE tasks ADD COLUMN description TEXT",
    )
    .await?;

    Ok(())
}

async fn migrate_2_to_3(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    ensure_column(
        pool,
        "todos",
        "archived_at",
        "ALTER TABLE todos ADD COLUMN archived_at TEXT",
    )
    .await?;

    Ok(())
}

async fn migrate_3_to_4(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    ensure_column(
        pool,
        "todos",
        "order_number",
        "ALTER TABLE todos ADD COLUMN order_number TEXT",
    )
    .await?;
    ensure_column(
        pool,
        "todos",
        "purchaser",
        "ALTER TABLE todos ADD COLUMN purchaser TEXT",
    )
    .await?;
    ensure_column(
        pool,
        "todos",
        "order_date",
        "ALTER TABLE todos ADD COLUMN order_date TEXT",
    )
    .await?;
    ensure_column(
        pool,
        "tasks",
        "amount",
        "ALTER TABLE tasks ADD COLUMN amount REAL NOT NULL DEFAULT 0",
    )
    .await?;

    Ok(())
}

async fn migrate_4_to_5(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    ensure_column(
        pool,
        "todos",
        "order_pdf",
        "ALTER TABLE todos ADD COLUMN order_pdf TEXT",
    )
    .await?;

    Ok(())
}

async fn migrate_5_to_6(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    ensure_column(
        pool,
        "todos",
        "budget_manual",
        "ALTER TABLE todos ADD COLUMN budget_manual INTEGER NOT NULL DEFAULT 0",
    )
    .await?;

    Ok(())
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
}

async fn index(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> AppResult<Html<String>> {
    let query_raw = params.q.unwrap_or_default();
    let query = query_raw.trim().to_string();
    let search = if query.is_empty() {
        None
    } else {
        Some(query.as_str())
    };
    let todos = load_active_todos(&state.pool, search).await?;
    let auth_enabled = load_auth_enabled(&state.pool).await?;
    let currency = load_currency_config(&state.pool).await?;
    let currency_label =
        resolve_currency_label(normalize_currency_code(&currency.code), &currency.custom);
    let currency_hint = currency_label_hint(&currency_label);
    let ui_text = load_ui_text(&state.pool).await?;
    let footer_text = build_footer_text(&ui_text.title, APP_VERSION);

    let mut body = String::new();
    body.push_str("<section class=\"top-bar\">");
    body.push_str("<div>");
    body.push_str(&format!("<h1>{}</h1>", escape_html(&ui_text.title)));
    if !ui_text.description.is_empty() {
        let description = escape_html(&ui_text.description).replace('\n', "<br>");
        body.push_str(&format!("<p>{}</p>", description));
    }
    body.push_str("</div>");
    body.push_str("<div class=\"status\">");
    body.push_str("<div class=\"status-line\">");
    if auth_enabled {
        body.push_str("Zugriffskontrolle: <strong>aktiv</strong>");
    } else {
        body.push_str("Zugriffskontrolle: <strong>deaktiviert</strong>");
    }
    body.push_str("</div>");
    body.push_str("<a class=\"btn\" href=\"/archive\">Archiv</a>");
    body.push_str("<a class=\"btn\" href=\"/config\">Konfiguration</a>");
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str(&render_search_panel(&query, "active"));

    body.push_str("<section class=\"panel\">");
    body.push_str("<h2>Neue Bestellung</h2>");
    body.push_str("<form class=\"todo-form\" method=\"post\" action=\"/todos\">");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Titel</label>");
    body.push_str("<input name=\"title\" required placeholder=\"z.B. Server-Hardware\" />");
    body.push_str("</div>");
    body.push_str("<div class=\"grid\">");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Bestellnummer</label>");
    body.push_str("<input name=\"order_number\" required placeholder=\"z.B. PO-2026-001\" />");
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Besteller</label>");
    body.push_str("<input name=\"purchaser\" required placeholder=\"z.B. Max Mustermann\" />");
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Bestelldatum</label>");
    body.push_str("<input name=\"order_date\" type=\"date\" required />");
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str(&format!("<label>Budget geplant{}</label>", currency_hint));
    body.push_str(
        "<input name=\"budget_planned\" type=\"number\" step=\"0.01\" placeholder=\"0,00\" />",
    );
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Deadline</label>");
    body.push_str("<input name=\"deadline\" type=\"date\" />");
    body.push_str("</div>");
    body.push_str("</div>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Bestellung anlegen</button>");
    body.push_str("</form>");
    body.push_str("</section>");

    body.push_str("<section class=\"todos\">");
    if todos.is_empty() {
        body.push_str("<div class=\"empty\">");
        body.push_str("<h3>Noch keine Bestellungen</h3>");
        body.push_str("<p>Lege oben deine erste Bestellung an, um Fortschritte zu verfolgen.</p>");
        body.push_str("</div>");
    } else {
        for todo in todos {
            body.push_str(&render_todo_card(&todo, &currency_label));
        }
    }
    body.push_str("</section>");

    Ok(Html(page_layout(&ui_text.title, body, &footer_text)))
}

async fn show_config(State(state): State<AppState>) -> AppResult<Html<String>> {
    let auth_enabled = load_auth_enabled(&state.pool).await?;
    let currency = load_currency_config(&state.pool).await?;
    let ui_text = load_ui_text(&state.pool).await?;
    let stored_app_version = load_app_version(&state.pool)
        .await?
        .unwrap_or_else(|| APP_VERSION.to_string());
    let stored_proto_version = load_proto_version(&state.pool)
        .await?
        .unwrap_or_else(|| PROTO_VERSION.to_string());
    let stored_app_id = load_app_id(&state.pool)
        .await?
        .unwrap_or_else(|| "—".to_string());
    let last_upgrade_backup_at = load_app_meta_value(&state.pool, "last_upgrade_backup_at")
        .await?
        .unwrap_or_else(|| "—".to_string());
    let last_upgrade_backup_path = load_app_meta_value(&state.pool, "last_upgrade_backup_path")
        .await?
        .unwrap_or_else(|| "—".to_string());
    let last_upgrade_reason = load_app_meta_value(&state.pool, "last_upgrade_reason")
        .await?
        .unwrap_or_else(|| "—".to_string());
    let last_upgrade_from_app_id = load_app_meta_value(&state.pool, "last_upgrade_from_app_id")
        .await?
        .unwrap_or_else(|| "—".to_string());
    let last_upgrade_from_app_version =
        load_app_meta_value(&state.pool, "last_upgrade_from_app_version")
            .await?
            .unwrap_or_else(|| "—".to_string());
    let last_upgrade_from_schema_version =
        load_app_meta_value(&state.pool, "last_upgrade_from_schema_version")
            .await?
            .unwrap_or_else(|| "—".to_string());
    let last_upgrade_from_proto_version =
        load_app_meta_value(&state.pool, "last_upgrade_from_proto_version")
            .await?
            .unwrap_or_else(|| "—".to_string());
    let db_schema_version = load_schema_version(&state.pool)
        .await
        .map_err(internal_error)?
        .unwrap_or(0);
    let sqlite_version = load_sqlite_version(&state.pool).await?;
    let sqlite_size_bytes = load_sqlite_size_bytes(&state.pool).await?;
    let sqlite_size = format_bytes(sqlite_size_bytes);
    let db_file_path = load_db_file_path(&state.pool).await?;
    let config_info = load_app_config();
    let config_path_display = config_info.config_path.to_string_lossy().to_string();
    let configured_path_display = config_info
        .configured_db_path
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let effective_source = match config_info.source {
        DbPathSource::Env => "Umgebung (BLUETODO_DB_PATH)",
        DbPathSource::Config => "Config-Datei",
        DbPathSource::Default => "Standard",
    };
    let proto_config = load_proto_config(&state.pool).await?;
    let metrics_config = load_metrics_config(&state.pool).await?;
    let update_config = load_update_config(&state.pool).await?;
    let update_status = load_update_status(&state.pool).await?;
    let secret_storage = load_secret_storage_info(&state.pool).await?;
    let proto_token_set = !proto_config.token.trim().is_empty();
    let metrics_token_set = !metrics_config.token.trim().is_empty();
    let metrics_v1_password_set = !metrics_config.v1_password.trim().is_empty();
    let update_password_set = !update_config.password.trim().is_empty();
    let currency_code = normalize_currency_code(&currency.code);
    let currency_label = resolve_currency_label(currency_code, &currency.custom);
    let currency_preview = format_currency_value("1.250,00", &currency_label);
    let currency_custom_value = escape_html(&currency.custom);
    let footer_text = build_footer_text(&ui_text.title, APP_VERSION);

    let mut body = String::new();
    body.push_str("<section class=\"top-bar\">");
    body.push_str("<div>");
    body.push_str("<h1>Global Konfiguration</h1>");
    body.push_str("<p>Geplante Zugriffskontrolle ist aktuell nicht erzwungen.</p>");
    body.push_str("</div>");
    body.push_str("<div class=\"status\">");
    body.push_str("<a class=\"btn\" href=\"/\">Zurück</a>");
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str(
        "<section class=\"panel\">\
        <h2>Zugriffskontrolle</h2>\
        <p>Diese Funktion ist vorbereitet, aber noch nicht im UI erzwungen.</p>\
    ",
    );
    body.push_str("<form class=\"config-form\" method=\"post\" action=\"/config/auth\">");
    body.push_str("<label class=\"toggle\">");
    if auth_enabled {
        body.push_str("<input type=\"checkbox\" name=\"enabled\" value=\"1\" checked />");
    } else {
        body.push_str("<input type=\"checkbox\" name=\"enabled\" value=\"1\" />");
    }
    body.push_str("<span>Aktivieren</span>");
    body.push_str("</label>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Speichern</button>");
    body.push_str("</form>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\">");
    body.push_str("<h2>Dashboard-Texte</h2>");
    body.push_str("<p>Hier kannst du Titel und Beschreibung des Dashboards anpassen.</p>");
    body.push_str("<form class=\"text-form\" method=\"post\" action=\"/config/text\">");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Titel</label>");
    body.push_str(&format!(
        "<input name=\"title\" required value=\"{}\" />",
        escape_html(&ui_text.title)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Beschreibung</label>");
    body.push_str(&format!(
        "<textarea name=\"description\" rows=\"3\">{}</textarea>",
        escape_html(&ui_text.description)
    ));
    body.push_str("</div>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Speichern</button>");
    body.push_str("</form>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\">");
    body.push_str("<h2>Währung</h2>");
    body.push_str("<p>Steuert die Anzeige von Budgets im Dashboard.</p>");
    body.push_str("<p class=\"muted\">Vorschau: ");
    body.push_str(&currency_preview);
    body.push_str("</p>");
    body.push_str("<form class=\"currency-form\" method=\"post\" action=\"/config/currency\">");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Währung auswählen</label>");
    body.push_str("<select name=\"currency_code\">");
    body.push_str(&format!(
        "<option value=\"EUR\" {}>Euro (€)</option>",
        if currency_code == "EUR" {
            "selected"
        } else {
            ""
        }
    ));
    body.push_str(&format!(
        "<option value=\"USD\" {}>US-Dollar ($)</option>",
        if currency_code == "USD" {
            "selected"
        } else {
            ""
        }
    ));
    body.push_str(&format!(
        "<option value=\"CHF\" {}>Schweizer Franken (CHF)</option>",
        if currency_code == "CHF" {
            "selected"
        } else {
            ""
        }
    ));
    body.push_str(&format!(
        "<option value=\"GBP\" {}>Britisches Pfund (£)</option>",
        if currency_code == "GBP" {
            "selected"
        } else {
            ""
        }
    ));
    body.push_str(&format!(
        "<option value=\"CUSTOM\" {}>Eigenes Symbol/Kürzel</option>",
        if currency_code == "CUSTOM" {
            "selected"
        } else {
            ""
        }
    ));
    body.push_str("</select>");
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Eigenes Symbol/Kürzel</label>");
    body.push_str(&format!(
        "<input name=\"currency_custom\" placeholder=\"z. B. € oder EUR\" value=\"{}\" />",
        currency_custom_value
    ));
    body.push_str("</div>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Speichern</button>");
    body.push_str("</form>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\">");
    body.push_str("<h2>Versionen</h2>");
    body.push_str("<div class=\"info-grid\">");
    body.push_str(&format!(
        "<div><span>App-Version</span><strong>{}</strong></div>",
        escape_html(APP_VERSION)
    ));
    body.push_str(&format!(
        "<div><span>App-ID (Server)</span><strong>{}</strong></div>",
        escape_html(APP_ID)
    ));
    body.push_str(&format!(
        "<div><span>App-ID (Datenbank)</span><strong>{}</strong></div>",
        escape_html(&stored_app_id)
    ));
    body.push_str(&format!(
        "<div><span>DB-Schema (Datenbank)</span><strong>{}</strong></div>",
        db_schema_version
    ));
    body.push_str(&format!(
        "<div><span>DB-Schema (App)</span><strong>{}</strong></div>",
        SCHEMA_VERSION
    ));
    body.push_str(&format!(
        "<div><span>Proto (Datenbank)</span><strong>{}</strong></div>",
        escape_html(&stored_proto_version)
    ));
    body.push_str(&format!(
        "<div><span>Proto (App)</span><strong>{}</strong></div>",
        PROTO_VERSION
    ));
    body.push_str(&format!(
        "<div><span>DB-App-Version</span><strong>{}</strong></div>",
        escape_html(&stored_app_version)
    ));
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\">");
    body.push_str("<h2>Upgrade-Backups</h2>");
    body.push_str("<p>Vor automatischen Versions-, Schema- oder Proto-Upgrades wird die SQLite-Datei einmal nach <code>backups/</code> neben der produktiven DB kopiert.</p>");
    body.push_str("<div class=\"info-grid path-grid\">");
    body.push_str(&format!(
        "<div><span>Letztes Backup</span><strong>{}</strong></div>",
        escape_html(&last_upgrade_backup_at)
    ));
    body.push_str(&format!(
        "<div><span>Backup-Datei</span><strong class=\"path-value\">{}</strong></div>",
        escape_html(&last_upgrade_backup_path)
    ));
    body.push_str(&format!(
        "<div><span>Von App-ID</span><strong>{}</strong></div>",
        escape_html(&last_upgrade_from_app_id)
    ));
    body.push_str(&format!(
        "<div><span>Von App-Version</span><strong>{}</strong></div>",
        escape_html(&last_upgrade_from_app_version)
    ));
    body.push_str(&format!(
        "<div><span>Von Schema</span><strong>{}</strong></div>",
        escape_html(&last_upgrade_from_schema_version)
    ));
    body.push_str(&format!(
        "<div><span>Von Proto</span><strong>{}</strong></div>",
        escape_html(&last_upgrade_from_proto_version)
    ));
    body.push_str("</div>");
    body.push_str(&format!(
        "<p class=\"muted\">Letzter Upgrade-Grund: {}</p>",
        escape_html(&last_upgrade_reason)
    ));
    body.push_str("</section>");

    body.push_str("<section class=\"panel\" id=\"secret-storage\">");
    body.push_str("<h2>Secret-Speicher</h2>");
    body.push_str("<p>Server-Secrets werden verschlüsselt in SQLite gespeichert. Bevorzugt ist ein externer Dateischlüssel über <code>BLUETODO_MASTER_KEY_FILE</code>.</p>");
    body.push_str("<div class=\"info-grid path-grid\">");
    body.push_str(&format!(
        "<div><span>Storage-Version</span><strong>{}</strong></div>",
        escape_html(&secret_storage.storage_version)
    ));
    body.push_str(&format!(
        "<div><span>Migration abgeschlossen</span><strong>{}</strong></div>",
        escape_html(&secret_storage.migrated_at)
    ));
    body.push_str(&format!(
        "<div><span>Secrets konfiguriert</span><strong>{}</strong></div>",
        secret_storage.configured_secrets
    ));
    body.push_str(&format!(
        "<div><span>Secrets verschlüsselt</span><strong>{}</strong></div>",
        secret_storage.encrypted_secrets
    ));
    body.push_str(&format!(
        "<div><span>Master-Key Quelle</span><strong>{}</strong></div>",
        escape_html(&secret_storage.key_source)
    ));
    body.push_str(&format!(
        "<div><span>Master-Key Status</span><strong>{}</strong></div>",
        escape_html(&secret_storage.key_status)
    ));
    body.push_str(&format!(
        "<div><span>Master-Key Ort</span><strong class=\"path-value\">{}</strong></div>",
        escape_html(&secret_storage.key_location)
    ));
    body.push_str(&format!(
        "<div><span>Bevorzugtes Setup</span><strong class=\"path-value\">{}</strong></div>",
        escape_html(&secret_storage.preferred_setup)
    ));
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\">");
    body.push_str("<h2>SQLite</h2>");
    body.push_str("<div class=\"info-grid\">");
    body.push_str(&format!(
        "<div><span>SQLite-Version</span><strong>{}</strong></div>",
        escape_html(&sqlite_version)
    ));
    body.push_str(&format!(
        "<div><span>Datenbankgröße</span><strong>{}</strong></div>",
        escape_html(&sqlite_size)
    ));
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\" id=\"db-path\">");
    body.push_str("<h2>Datenbankpfad</h2>");
    body.push_str("<p>Änderungen am DB-Pfad erfordern einen Neustart.</p>");
    body.push_str("<div class=\"info-grid path-grid\">");
    body.push_str(&format!(
        "<div><span>Aktiver DB-Pfad</span><strong class=\"path-value\">{}</strong></div>",
        escape_html(&db_file_path)
    ));
    body.push_str(&format!(
        "<div><span>Config-Datei</span><strong class=\"path-value\">{}</strong></div>",
        escape_html(&config_path_display)
    ));
    body.push_str(&format!(
        "<div><span>Konfiguriert</span><strong class=\"path-value\">{}</strong></div>",
        escape_html(&configured_path_display)
    ));
    body.push_str(&format!(
        "<div><span>Quelle</span><strong>{}</strong></div>",
        escape_html(effective_source)
    ));
    body.push_str("</div>");
    if let Some(env_override) = config_info.env_override {
        if !env_override.is_empty() {
            body.push_str(
                "<p class=\"muted\">Hinweis: BLUETODO_DB_PATH ist gesetzt und überschreibt die Config.</p>",
            );
        }
    }
    body.push_str("<form class=\"text-form\" method=\"post\" action=\"/config/db\">");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>DB-Pfad</label>");
    body.push_str(&format!(
        "<input name=\"db_path\" placeholder=\"/pfad/zu/bluetodo.db\" value=\"{}\" />",
        escape_html(config_info.configured_db_path.as_deref().unwrap_or(""))
    ));
    body.push_str("<p class=\"muted\">Leer lassen, um den Standardpfad zu verwenden.</p>");
    body.push_str("</div>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Speichern</button>");
    body.push_str("</form>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\" id=\"metrics\">");
    body.push_str("<h2>Metrics (InfluxDB)</h2>");
    body.push_str(
        "<p>Optionaler Export via Influx Line Protocol. Änderungen greifen ohne Neustart.</p>",
    );
    body.push_str(
        "<p class=\"muted\">Es werden nur die Felder der gewählten Version verwendet.</p>",
    );
    body.push_str("<form class=\"proto-form\" method=\"post\" action=\"/config/metrics\">");
    body.push_str("<label class=\"toggle\">");
    if metrics_config.enabled {
        body.push_str("<input type=\"checkbox\" id=\"metrics-enabled\" name=\"enabled\" value=\"1\" checked />");
    } else {
        body.push_str(
            "<input type=\"checkbox\" id=\"metrics-enabled\" name=\"enabled\" value=\"1\" />",
        );
    }
    body.push_str("<span>Aktivieren</span>");
    body.push_str("</label>");
    body.push_str("<input type=\"hidden\" id=\"metrics-version-current\" value=\"");
    body.push_str(&escape_html(&metrics_config.version));
    body.push_str("\" />");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Influx Version</label>");
    body.push_str("<select name=\"version\" id=\"metrics-version\">");
    body.push_str(&format!(
        "<option value=\"v2\" {}>InfluxDB v2</option>",
        if metrics_config.version == "v1" {
            ""
        } else {
            "selected"
        }
    ));
    body.push_str(&format!(
        "<option value=\"v1\" {}>InfluxDB v1</option>",
        if metrics_config.version == "v1" {
            "selected"
        } else {
            ""
        }
    ));
    body.push_str("</select>");
    body.push_str("</div>");
    if metrics_config.enabled
        && metrics_config.version != "v1"
        && metrics_config.url.trim().is_empty()
    {
        body.push_str("<p class=\"warning metrics-warning\" data-version=\"v2\">Für InfluxDB v2 ist eine Write-URL nötig.</p>");
    }
    if metrics_config.enabled
        && metrics_config.version == "v1"
        && (metrics_config.v1_url.trim().is_empty() || metrics_config.v1_db.trim().is_empty())
    {
        body.push_str("<p class=\"warning metrics-warning\" data-version=\"v1\">Für InfluxDB v1 sind Base-URL und Database nötig.</p>");
    }

    body.push_str("<div class=\"metrics-group\" data-version=\"v2\">");
    body.push_str("<h3>InfluxDB v2</h3>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Write-URL (v2)</label>");
    body.push_str(&format!(
        "<input name=\"url\" placeholder=\"http://localhost:8086/api/v2/write?org=...&bucket=...&precision=s\" value=\"{}\" />",
        escape_html(&metrics_config.url)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Token (v2, optional)</label>");
    body.push_str(&format!(
        "<input name=\"token\" type=\"password\" autocomplete=\"new-password\" placeholder=\"{}\" />",
        if metrics_token_set {
            "Gesetzt - leer lassen zum Behalten"
        } else {
            "Influx Token"
        }
    ));
    body.push_str("</div>");
    body.push_str("<label class=\"toggle\">");
    if metrics_token_set {
        body.push_str("<input type=\"checkbox\" name=\"clear_token\" value=\"1\" />");
    } else {
        body.push_str("<input type=\"checkbox\" name=\"clear_token\" value=\"1\" />");
    }
    body.push_str("<span>Gespeicherten v2-Token löschen</span>");
    body.push_str("</label>");
    body.push_str("</div>");
    body.push_str("<div class=\"metrics-group\" data-version=\"v1\">");
    body.push_str("<h3>InfluxDB v1</h3>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Base-URL (v1)</label>");
    body.push_str(&format!(
        "<input name=\"v1_url\" placeholder=\"http://localhost:8086\" value=\"{}\" />",
        escape_html(&metrics_config.v1_url)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Database (v1)</label>");
    body.push_str(&format!(
        "<input name=\"v1_db\" placeholder=\"bluetodo\" value=\"{}\" />",
        escape_html(&metrics_config.v1_db)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>User (v1)</label>");
    body.push_str(&format!(
        "<input name=\"v1_user\" placeholder=\"optional\" value=\"{}\" />",
        escape_html(&metrics_config.v1_user)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Password (v1)</label>");
    body.push_str(&format!(
        "<input name=\"v1_password\" type=\"password\" autocomplete=\"new-password\" placeholder=\"{}\" />",
        if metrics_v1_password_set {
            "Gesetzt - leer lassen zum Behalten"
        } else {
            "optional"
        }
    ));
    body.push_str("</div>");
    body.push_str("<label class=\"toggle\">");
    body.push_str("<input type=\"checkbox\" name=\"clear_v1_password\" value=\"1\" />");
    body.push_str("<span>Gespeichertes v1-Passwort löschen</span>");
    body.push_str("</label>");
    body.push_str("<label class=\"toggle\">");
    if metrics_config.v1_autocreate {
        body.push_str("<input type=\"checkbox\" name=\"v1_autocreate\" value=\"1\" checked />");
    } else {
        body.push_str("<input type=\"checkbox\" name=\"v1_autocreate\" value=\"1\" />");
    }
    body.push_str("<span>DB automatisch anlegen (v1)</span>");
    body.push_str("</label>");
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Instance-Tag (optional)</label>");
    body.push_str(&format!(
        "<input name=\"instance\" placeholder=\"host-01\" value=\"{}\" />",
        escape_html(&metrics_config.instance)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Intervall (Sekunden)</label>");
    body.push_str(&format!(
        "<input name=\"interval\" type=\"number\" min=\"5\" value=\"{}\" />",
        metrics_config.interval_seconds
    ));
    body.push_str("</div>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Speichern</button>");
    body.push_str("</form>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\" id=\"update\">");
    body.push_str("<h2>Auto-Update</h2>");
    body.push_str(
        "<p>Prüft eine Manifest-Datei auf neue Versionen. Update wird manuell gestartet.</p>",
    );
    body.push_str("<form class=\"config-form\" method=\"post\" action=\"/config/update\">");
    body.push_str("<label class=\"toggle\">");
    if update_config.enabled {
        body.push_str("<input type=\"checkbox\" name=\"enabled\" value=\"1\" checked />");
    } else {
        body.push_str("<input type=\"checkbox\" name=\"enabled\" value=\"1\" />");
    }
    body.push_str("<span>Aktivieren</span>");
    body.push_str("</label>");
    body.push_str("<div class=\"grid\">");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Manifest-URL</label>");
    body.push_str(&format!(
        "<input name=\"url\" placeholder=\"https://.../manifest.json\" value=\"{}\" />",
        escape_html(&update_config.url)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>User (Basic-Auth)</label>");
    body.push_str(&format!(
        "<input name=\"user\" placeholder=\"optional\" value=\"{}\" />",
        escape_html(&update_config.user)
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Passwort (Basic-Auth)</label>");
    body.push_str(&format!(
        "<input name=\"password\" type=\"password\" autocomplete=\"new-password\" placeholder=\"{}\" />",
        if update_password_set {
            "Gesetzt - leer lassen zum Behalten"
        } else {
            "optional"
        }
    ));
    body.push_str("</div>");
    body.push_str("<label class=\"toggle\">");
    body.push_str("<input type=\"checkbox\" name=\"clear_password\" value=\"1\" />");
    body.push_str("<span>Gespeichertes Update-Passwort löschen</span>");
    body.push_str("</label>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Kanal</label>");
    body.push_str(&format!(
        "<input name=\"channel\" placeholder=\"stable\" value=\"{}\" />",
        escape_html(&update_config.channel)
    ));
    body.push_str("</div>");
    body.push_str("</div>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Speichern</button>");
    body.push_str("</form>");
    body.push_str("<div class=\"info-grid\">");
    body.push_str(&format!(
        "<div><span>Letzte Prüfung</span><strong>{}</strong></div>",
        escape_html(&update_status.last_checked)
    ));
    body.push_str(&format!(
        "<div><span>Status</span><strong>{}</strong></div>",
        escape_html(&update_status.last_status)
    ));
    body.push_str(&format!(
        "<div><span>Update verfügbar</span><strong>{}</strong></div>",
        if update_status.available {
            "Ja"
        } else {
            "Nein"
        }
    ));
    body.push_str(&format!(
        "<div><span>Neueste Version</span><strong>{}</strong></div>",
        escape_html(&update_status.latest_version)
    ));
    body.push_str(&format!(
        "<div><span>Ziel</span><strong>{} / {}</strong></div>",
        escape_html(std::env::consts::OS),
        escape_html(std::env::consts::ARCH)
    ));
    body.push_str("</div>");
    if !update_status.latest_notes.trim().is_empty() {
        let notes = escape_html(&update_status.latest_notes).replace('\n', "<br>");
        body.push_str(&format!(
            "<div class=\"notes\"><strong>Changelog</strong><p class=\"muted\">{}</p></div>",
            notes
        ));
    }
    body.push_str("<div class=\"action-row\">");
    body.push_str("<form method=\"post\" action=\"/config/update-check\">");
    body.push_str("<button class=\"btn\" type=\"submit\">Auf Updates prüfen</button>");
    body.push_str("</form>");
    body.push_str("<form method=\"post\" action=\"/config/update-apply\">");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Update installieren</button>");
    body.push_str("</form>");
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\" id=\"build-info\">");
    body.push_str("<h2>Build</h2>");
    body.push_str("<div class=\"info-grid\">");
    body.push_str(&format!(
        "<div><span>rustc</span><strong>{}</strong></div>",
        escape_html(RUSTC_VERSION)
    ));
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str("<section class=\"panel\">");
    body.push_str("<h2>Win31-Protokoll (optional)</h2>");
    body.push_str("<p>Aktiviert eine einfache TCP-Schnittstelle für Legacy-Clients. Neustart erforderlich.</p>");
    body.push_str("<form class=\"proto-form\" method=\"post\" action=\"/config/proto\">");
    body.push_str("<label class=\"toggle\">");
    if proto_config.enabled {
        body.push_str("<input type=\"checkbox\" name=\"enabled\" value=\"1\" checked />");
    } else {
        body.push_str("<input type=\"checkbox\" name=\"enabled\" value=\"1\" />");
    }
    body.push_str("<span>Aktivieren</span>");
    body.push_str("</label>");
    body.push_str("<div class=\"grid\">");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Port</label>");
    body.push_str(&format!(
        "<input name=\"port\" type=\"number\" min=\"1\" max=\"65535\" value=\"{}\" />",
        proto_config.port
    ));
    body.push_str("</div>");
    body.push_str("<div class=\"field\">");
    body.push_str("<label>Token (optional)</label>");
    body.push_str(&format!(
        "<input name=\"token\" type=\"password\" autocomplete=\"new-password\" placeholder=\"{}\" />",
        if proto_token_set {
            "Gesetzt - leer lassen zum Behalten"
        } else {
            "Shared Secret"
        }
    ));
    body.push_str("</div>");
    body.push_str("<label class=\"toggle\">");
    body.push_str("<input type=\"checkbox\" name=\"clear_token\" value=\"1\" />");
    body.push_str("<span>Gespeicherten Proto-Token löschen</span>");
    body.push_str("</label>");
    body.push_str("</div>");
    body.push_str("<button class=\"btn primary\" type=\"submit\">Speichern</button>");
    body.push_str("</form>");
    body.push_str("</section>");

    let page_title = format!("Konfiguration · {}", ui_text.title);
    Ok(Html(page_layout(&page_title, body, &footer_text)))
}

async fn show_archive(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> AppResult<Html<String>> {
    let query_raw = params.q.unwrap_or_default();
    let query = query_raw.trim().to_string();
    let search = if query.is_empty() {
        None
    } else {
        Some(query.as_str())
    };
    let archived_todos = load_archived_todos(&state.pool, search).await?;
    let currency = load_currency_config(&state.pool).await?;
    let currency_label =
        resolve_currency_label(normalize_currency_code(&currency.code), &currency.custom);
    let ui_text = load_ui_text(&state.pool).await?;
    let footer_text = build_footer_text(&ui_text.title, APP_VERSION);

    let mut body = String::new();
    body.push_str("<section class=\"top-bar\">");
    body.push_str("<div>");
    body.push_str(&format!(
        "<h1>Archiv · {}</h1>",
        escape_html(&ui_text.title)
    ));
    body.push_str("<p>Abgeschlossene Bestellungen werden hier gesammelt.</p>");
    body.push_str("</div>");
    body.push_str("<div class=\"status\">");
    body.push_str("<a class=\"btn\" href=\"/\">Zurück</a>");
    body.push_str("<a class=\"btn\" href=\"/config\">Konfiguration</a>");
    body.push_str("</div>");
    body.push_str("</section>");

    body.push_str(&render_search_panel(&query, "archive"));

    body.push_str("<section class=\"panel archive\" id=\"archive\">");
    body.push_str(&format!(
        "<h2>Archiv <span class=\"archive-count\">{}</span></h2>",
        archived_todos.len()
    ));
    if archived_todos.is_empty() {
        body.push_str("<p class=\"muted\">Noch kein Archiv.</p>");
    } else {
        body.push_str("<div class=\"archive-list\">");
        for todo in archived_todos {
            body.push_str(&render_archive_item(&todo, &currency_label));
        }
        body.push_str("</div>");
    }
    body.push_str("</section>");

    let page_title = format!("Archiv · {}", ui_text.title);
    Ok(Html(page_layout(&page_title, body, &footer_text)))
}

#[derive(Deserialize)]
struct NewTodoForm {
    title: String,
    order_number: Option<String>,
    purchaser: Option<String>,
    order_date: Option<String>,
    budget_planned: Option<String>,
    deadline: Option<String>,
}

async fn create_todo(
    State(state): State<AppState>,
    Form(form): Form<NewTodoForm>,
) -> AppResult<Redirect> {
    let budget_planned = parse_optional_money(form.budget_planned.as_deref());
    let deadline = normalize_optional_date(form.deadline.as_deref());
    let order_number = normalize_optional_string(form.order_number.as_deref());
    let purchaser = normalize_optional_string(form.purchaser.as_deref());
    let order_date = normalize_optional_date(form.order_date.as_deref());

    if form.title.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Titel fehlt".to_string()));
    }
    if order_number.as_deref().unwrap_or("").trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Bestellnummer fehlt".to_string()));
    }
    if purchaser.as_deref().unwrap_or("").trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Besteller fehlt".to_string()));
    }
    if order_date.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Bestelldatum fehlt".to_string()));
    }

    let result = sqlx::query(
        r#"
        INSERT INTO todos (title, order_number, purchaser, order_date, budget_spent, budget_planned, deadline)
        VALUES (?, ?, ?, ?, 0, ?, ?)
        "#,
    )
    .bind(form.title.trim())
    .bind(order_number)
    .bind(purchaser)
    .bind(order_date)
    .bind(budget_planned)
    .bind(deadline)
    .execute(&state.pool)
    .await
    .map_err(internal_error)?;

    let location = todo_anchor(result.last_insert_rowid());
    Ok(Redirect::to(&location))
}

#[derive(Deserialize)]
struct UpdateTodoForm {
    title: String,
    order_number: Option<String>,
    purchaser: Option<String>,
    order_date: Option<String>,
    budget_planned: Option<String>,
    deadline: Option<String>,
}

async fn update_todo(
    State(state): State<AppState>,
    Path(todo_id): Path<i64>,
    Form(form): Form<UpdateTodoForm>,
) -> AppResult<Redirect> {
    let active = match load_todo_active(&state.pool, todo_id).await? {
        Some(active) => active,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "Bestellung nicht gefunden".to_string(),
            ));
        }
    };
    if !active {
        return Ok(Redirect::to(archive_anchor()));
    }

    let budget_planned = parse_optional_money(form.budget_planned.as_deref());
    let deadline = normalize_optional_date(form.deadline.as_deref());
    let order_number = normalize_optional_string(form.order_number.as_deref());
    let purchaser = normalize_optional_string(form.purchaser.as_deref());
    let order_date = normalize_optional_date(form.order_date.as_deref());

    if form.title.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Titel fehlt".to_string()));
    }
    if order_number.as_deref().unwrap_or("").trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Bestellnummer fehlt".to_string()));
    }
    if purchaser.as_deref().unwrap_or("").trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Besteller fehlt".to_string()));
    }
    if order_date.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Bestelldatum fehlt".to_string()));
    }

    sqlx::query(
        r#"
        UPDATE todos
        SET title = ?, order_number = ?, purchaser = ?, order_date = ?, budget_planned = ?, deadline = ?
        WHERE id = ?
        "#,
    )
    .bind(form.title.trim())
    .bind(order_number)
    .bind(purchaser)
    .bind(order_date)
    .bind(budget_planned)
    .bind(deadline)
    .bind(todo_id)
    .execute(&state.pool)
    .await
    .map_err(internal_error)?;

    let location = todo_anchor(todo_id);
    Ok(Redirect::to(&location))
}

const MAX_PDF_BYTES: usize = 10 * 1024 * 1024;

async fn upload_todo_pdf(
    State(state): State<AppState>,
    Path(todo_id): Path<i64>,
    mut multipart: Multipart,
) -> AppResult<Redirect> {
    let exists = sqlx::query("SELECT id FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal_error)?;
    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "Bestellung nicht gefunden".to_string(),
        ));
    }

    let mut data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;

    while let Some(mut field) = multipart.next_field().await.map_err(internal_error)? {
        let name = field.name().unwrap_or("");
        if name != "pdf" {
            continue;
        }
        filename = field.file_name().map(|value| value.to_string());
        content_type = field.content_type().map(|value| value.to_string());

        let mut bytes = Vec::new();
        while let Some(chunk) = field.chunk().await.map_err(internal_error)? {
            if bytes.len() + chunk.len() > MAX_PDF_BYTES {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "PDF ist größer als 10MB".to_string(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        data = Some(bytes);
        break;
    }

    let Some(bytes) = data else {
        return Err((StatusCode::BAD_REQUEST, "PDF fehlt".to_string()));
    };

    let filename_hint = filename.unwrap_or_else(|| "bestellung.pdf".to_string());
    let filename_lower = filename_hint.to_lowercase();
    let content_type_ok = content_type
        .as_deref()
        .map(|value| value == "application/pdf")
        .unwrap_or(false);
    if !content_type_ok && !filename_lower.ends_with(".pdf") {
        return Err((StatusCode::BAD_REQUEST, "Nur PDF erlaubt".to_string()));
    }

    let storage_root = storage_dir();
    tokio::fs::create_dir_all(&storage_root)
        .await
        .map_err(internal_error)?;
    let file_name = format!("todo-{}.pdf", todo_id);
    let final_path = storage_root.join(&file_name);
    let tmp_path = storage_root.join(format!("todo-{}.tmp", todo_id));
    tokio::fs::write(&tmp_path, &bytes)
        .await
        .map_err(internal_error)?;
    tokio::fs::rename(&tmp_path, &final_path)
        .await
        .map_err(internal_error)?;

    let relative = format!("storage/{}", file_name);
    sqlx::query("UPDATE todos SET order_pdf = ? WHERE id = ?")
        .bind(relative)
        .bind(todo_id)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    let location = todo_anchor(todo_id);
    Ok(Redirect::to(&location))
}

async fn get_todo_pdf(
    State(state): State<AppState>,
    Path(todo_id): Path<i64>,
) -> AppResult<(HeaderMap, Bytes)> {
    let row = sqlx::query("SELECT order_pdf FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal_error)?;
    let Some(row) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            "Bestellung nicht gefunden".to_string(),
        ));
    };
    let order_pdf: Option<String> = row.get("order_pdf");
    let Some(path_str) = order_pdf.filter(|value| !value.trim().is_empty()) else {
        return Err((StatusCode::NOT_FOUND, "Kein PDF vorhanden".to_string()));
    };

    let path = PathBuf::from(&path_str);
    if !path.starts_with("storage") {
        return Err((StatusCode::BAD_REQUEST, "Ungültiger PDF-Pfad".to_string()));
    }
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err((StatusCode::NOT_FOUND, "PDF nicht gefunden".to_string()));
        }
        Err(err) => return Err(internal_error(err)),
    };
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bestellung.pdf");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    let disposition = format!("inline; filename=\"{}\"", filename);
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).map_err(internal_error)?,
    );
    Ok((headers, Bytes::from(bytes)))
}

async fn delete_todo(
    State(state): State<AppState>,
    Path(todo_id): Path<i64>,
) -> AppResult<Redirect> {
    sqlx::query("DELETE FROM todos WHERE id = ?")
        .bind(todo_id)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to("/"))
}

async fn archive_todo(
    State(state): State<AppState>,
    Path(todo_id): Path<i64>,
) -> AppResult<Redirect> {
    let active = match load_todo_active(&state.pool, todo_id).await? {
        Some(active) => active,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "Bestellung nicht gefunden".to_string(),
            ));
        }
    };
    if !active {
        return Ok(Redirect::to(archive_anchor()));
    }
    if !todo_is_complete(&state.pool, todo_id).await? {
        return Err((
            StatusCode::BAD_REQUEST,
            "Bestellung ist noch nicht abgeschlossen".to_string(),
        ));
    }

    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    sqlx::query("UPDATE todos SET archived_at = ? WHERE id = ? AND archived_at IS NULL")
        .bind(timestamp)
        .bind(todo_id)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to(archive_anchor()))
}

async fn unarchive_todo(
    State(state): State<AppState>,
    Path(todo_id): Path<i64>,
) -> AppResult<Redirect> {
    sqlx::query("UPDATE todos SET archived_at = NULL WHERE id = ?")
        .bind(todo_id)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to(archive_anchor()))
}

#[derive(Deserialize)]
struct NewTaskForm {
    title: String,
    amount: Option<String>,
}

async fn add_task(
    State(state): State<AppState>,
    Path(todo_id): Path<i64>,
    Form(form): Form<NewTaskForm>,
) -> AppResult<Redirect> {
    let active = match load_todo_active(&state.pool, todo_id).await? {
        Some(active) => active,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "Bestellung nicht gefunden".to_string(),
            ));
        }
    };
    if !active {
        return Ok(Redirect::to(archive_anchor()));
    }

    if form.title.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Titel fehlt".to_string()));
    }

    let amount = parse_required_money(form.amount.as_deref())
        .map_err(|message| (StatusCode::BAD_REQUEST, message.to_string()))?;

    sqlx::query("INSERT INTO tasks (todo_id, title, amount, done) VALUES (?, ?, ?, 0)")
        .bind(todo_id)
        .bind(form.title.trim())
        .bind(amount)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    recalculate_todo_spent(&state.pool, todo_id)
        .await
        .map_err(internal_error)?;

    let location = todo_anchor(todo_id);
    Ok(Redirect::to(&location))
}

async fn toggle_task(
    State(state): State<AppState>,
    Path(task_id): Path<i64>,
) -> AppResult<Redirect> {
    let (todo_id, active) = match load_task_active(&state.pool, task_id).await? {
        Some(value) => value,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "Einzelauftrag nicht gefunden".to_string(),
            ));
        }
    };
    if !active {
        return Ok(Redirect::to(archive_anchor()));
    }

    sqlx::query(
        r#"
        UPDATE tasks
        SET done = CASE done WHEN 1 THEN 0 ELSE 1 END
        WHERE id = ?
        "#,
    )
    .bind(task_id)
    .execute(&state.pool)
    .await
    .map_err(internal_error)?;

    let location = todo_anchor(todo_id);
    Ok(Redirect::to(&location))
}

#[derive(Deserialize)]
struct UpdateTaskForm {
    title: String,
    amount: Option<String>,
}

async fn update_task(
    State(state): State<AppState>,
    Path(task_id): Path<i64>,
    Form(form): Form<UpdateTaskForm>,
) -> AppResult<Redirect> {
    let (todo_id, active) = match load_task_active(&state.pool, task_id).await? {
        Some(value) => value,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "Einzelauftrag nicht gefunden".to_string(),
            ));
        }
    };
    if !active {
        return Ok(Redirect::to(archive_anchor()));
    }

    if form.title.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Titel fehlt".to_string()));
    }

    let amount = parse_required_money(form.amount.as_deref())
        .map_err(|message| (StatusCode::BAD_REQUEST, message.to_string()))?;

    sqlx::query("UPDATE tasks SET title = ?, amount = ? WHERE id = ?")
        .bind(form.title.trim())
        .bind(amount)
        .bind(task_id)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    recalculate_todo_spent(&state.pool, todo_id)
        .await
        .map_err(internal_error)?;

    let location = todo_anchor(todo_id);
    Ok(Redirect::to(&location))
}

async fn recalculate_todo_spent(pool: &SqlitePool, todo_id: i64) -> Result<(), sqlx::Error> {
    let budget_mode = sqlx::query("SELECT budget_manual FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(pool)
        .await?;
    if let Some(row) = budget_mode {
        let budget_manual: i64 = row.get("budget_manual");
        if budget_manual == 1 {
            return Ok(());
        }
    }

    let row = sqlx::query("SELECT COALESCE(SUM(amount), 0) AS total FROM tasks WHERE todo_id = ?")
        .bind(todo_id)
        .fetch_one(pool)
        .await?;
    let total: f64 = row.get("total");
    sqlx::query("UPDATE todos SET budget_spent = ? WHERE id = ?")
        .bind(total)
        .bind(todo_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn load_todo_active(pool: &SqlitePool, todo_id: i64) -> AppResult<Option<bool>> {
    let row = sqlx::query("SELECT archived_at FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(pool)
        .await
        .map_err(internal_error)?;
    Ok(row.map(|row| row.get::<Option<String>, _>("archived_at").is_none()))
}

async fn load_task_active(pool: &SqlitePool, task_id: i64) -> AppResult<Option<(i64, bool)>> {
    let row = sqlx::query(
        r#"
        SELECT todos.id AS todo_id, todos.archived_at AS archived_at
        FROM tasks
        JOIN todos ON tasks.todo_id = todos.id
        WHERE tasks.id = ?
        "#,
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .map_err(internal_error)?;

    Ok(row.map(|row| {
        let todo_id: i64 = row.get("todo_id");
        let archived_at: Option<String> = row.get("archived_at");
        (todo_id, archived_at.is_none())
    }))
}

async fn todo_is_complete(pool: &SqlitePool, todo_id: i64) -> AppResult<bool> {
    let stats = sqlx::query(
        "SELECT COUNT(*) AS total, COALESCE(SUM(done), 0) AS done FROM tasks WHERE todo_id = ?",
    )
    .bind(todo_id)
    .fetch_one(pool)
    .await
    .map_err(internal_error)?;

    let total: i64 = stats.get("total");
    let done: i64 = stats.get("done");
    Ok(total > 0 && total == done)
}

#[derive(Deserialize)]
struct AuthForm {
    enabled: Option<String>,
}

async fn update_auth(
    State(state): State<AppState>,
    Form(form): Form<AuthForm>,
) -> AppResult<Redirect> {
    let enabled = form.enabled.as_deref() == Some("1");
    let value = if enabled { "1" } else { "0" };

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'auth_enabled'")
        .bind(value)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to("/config"))
}

#[derive(Deserialize)]
struct UpdateUiTextForm {
    title: String,
    description: Option<String>,
}

async fn update_ui_text(
    State(state): State<AppState>,
    Form(form): Form<UpdateUiTextForm>,
) -> AppResult<Redirect> {
    let title = form.title.trim();
    let description = normalize_optional_string(form.description.as_deref()).unwrap_or_default();

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'dashboard_title'")
        .bind(title)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'dashboard_description'")
        .bind(description)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to("/config"))
}

#[derive(Deserialize)]
struct UpdateCurrencyForm {
    currency_code: String,
    currency_custom: Option<String>,
}

async fn update_currency(
    State(state): State<AppState>,
    Form(form): Form<UpdateCurrencyForm>,
) -> AppResult<Redirect> {
    let code = normalize_currency_code(&form.currency_code).to_string();
    let custom = normalize_optional_string(form.currency_custom.as_deref()).unwrap_or_default();

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'currency_code'")
        .bind(code)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'currency_custom'")
        .bind(custom)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to("/config"))
}

#[derive(Deserialize)]
struct UpdateProtoForm {
    enabled: Option<String>,
    port: Option<String>,
    token: Option<String>,
    clear_token: Option<String>,
}

async fn update_proto(
    State(state): State<AppState>,
    Form(form): Form<UpdateProtoForm>,
) -> AppResult<Redirect> {
    let enabled = form.enabled.as_deref() == Some("1");
    let port = form
        .port
        .as_deref()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(PROTO_DEFAULT_PORT);
    let token = resolve_secret_form_value(
        &state.pool,
        "proto_token",
        form.token.as_deref(),
        form.clear_token.as_deref() == Some("1"),
    )
    .await?;

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'proto_enabled'")
        .bind(if enabled { "1" } else { "0" })
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'proto_port'")
        .bind(port.to_string())
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    store_setting_value(&state.pool, "proto_token", &token)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to("/config"))
}

#[derive(Deserialize)]
struct UpdateMetricsForm {
    enabled: Option<String>,
    version: Option<String>,
    url: Option<String>,
    token: Option<String>,
    clear_token: Option<String>,
    v1_url: Option<String>,
    v1_db: Option<String>,
    v1_user: Option<String>,
    v1_password: Option<String>,
    clear_v1_password: Option<String>,
    v1_autocreate: Option<String>,
    interval: Option<String>,
    instance: Option<String>,
}

async fn update_metrics(
    State(state): State<AppState>,
    Form(form): Form<UpdateMetricsForm>,
) -> AppResult<Redirect> {
    let enabled = form.enabled.as_deref() == Some("1");
    let version = form
        .version
        .as_deref()
        .map(|value| value.trim().to_lowercase())
        .filter(|value| value == "v1" || value == "v2")
        .unwrap_or_else(|| "v2".to_string());
    let url = normalize_optional_string(form.url.as_deref()).unwrap_or_default();
    let token = resolve_secret_form_value(
        &state.pool,
        "metrics_token",
        form.token.as_deref(),
        form.clear_token.as_deref() == Some("1"),
    )
    .await?;
    let v1_url = normalize_optional_string(form.v1_url.as_deref()).unwrap_or_default();
    let v1_db = normalize_optional_string(form.v1_db.as_deref()).unwrap_or_default();
    let v1_user = normalize_optional_string(form.v1_user.as_deref()).unwrap_or_default();
    let v1_password = resolve_secret_form_value(
        &state.pool,
        "metrics_v1_password",
        form.v1_password.as_deref(),
        form.clear_v1_password.as_deref() == Some("1"),
    )
    .await?;
    let v1_autocreate = form.v1_autocreate.as_deref() == Some("1");
    let instance = normalize_optional_string(form.instance.as_deref()).unwrap_or_default();
    let interval = form
        .interval
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.max(5))
        .unwrap_or(30);

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_enabled'")
        .bind(if enabled { "1" } else { "0" })
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_url'")
        .bind(url)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    store_setting_value(&state.pool, "metrics_token", &token)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_version'")
        .bind(version)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_v1_url'")
        .bind(v1_url)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_v1_db'")
        .bind(v1_db)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_v1_user'")
        .bind(v1_user)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    store_setting_value(&state.pool, "metrics_v1_password", &v1_password)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_v1_autocreate'")
        .bind(if v1_autocreate { "1" } else { "0" })
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_interval'")
        .bind(interval.to_string())
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'metrics_instance'")
        .bind(instance)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to("/config#metrics"))
}

#[derive(Deserialize)]
struct UpdateUpdateForm {
    enabled: Option<String>,
    url: Option<String>,
    user: Option<String>,
    password: Option<String>,
    clear_password: Option<String>,
    channel: Option<String>,
}

async fn update_update_config(
    State(state): State<AppState>,
    Form(form): Form<UpdateUpdateForm>,
) -> AppResult<Redirect> {
    let enabled = form.enabled.as_deref() == Some("1");
    let url = normalize_optional_string(form.url.as_deref()).unwrap_or_default();
    let user = normalize_optional_string(form.user.as_deref()).unwrap_or_default();
    let password = resolve_secret_form_value(
        &state.pool,
        "update_password",
        form.password.as_deref(),
        form.clear_password.as_deref() == Some("1"),
    )
    .await?;
    let channel =
        normalize_optional_string(form.channel.as_deref()).unwrap_or_else(|| "stable".to_string());

    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_enabled'")
        .bind(if enabled { "1" } else { "0" })
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_url'")
        .bind(url)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_user'")
        .bind(user)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;
    store_setting_value(&state.pool, "update_password", &password)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_channel'")
        .bind(channel)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Redirect::to("/config#update"))
}

async fn update_check(State(state): State<AppState>) -> AppResult<Redirect> {
    let config = load_update_config(&state.pool).await?;
    let result = perform_update_check(&state.pool, &config).await;
    if let Err(message) = result {
        set_update_status(
            &state.pool,
            UpdateStatus {
                last_checked: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                last_status: format!("Fehler: {}", message),
                available: false,
                latest_version: String::new(),
                latest_notes: String::new(),
                latest_url: String::new(),
                latest_sha256: String::new(),
                latest_size: String::new(),
            },
        )
        .await
        .map_err(internal_error)?;
    }
    Ok(Redirect::to("/config#update"))
}

async fn update_apply(State(state): State<AppState>) -> AppResult<Redirect> {
    let config = load_update_config(&state.pool).await?;
    let result = apply_update(&state.pool, &config).await;
    if let Err(message) = result {
        let status = UpdateStatus {
            last_checked: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            last_status: format!("Fehler: {}", message),
            available: false,
            latest_version: String::new(),
            latest_notes: String::new(),
            latest_url: String::new(),
            latest_sha256: String::new(),
            latest_size: String::new(),
        };
        set_update_status(&state.pool, status)
            .await
            .map_err(internal_error)?;
        return Ok(Redirect::to("/config#update"));
    }
    Ok(Redirect::to("/"))
}

#[derive(Deserialize)]
struct UpdateDbPathForm {
    db_path: String,
}

async fn update_db_path(Form(form): Form<UpdateDbPathForm>) -> AppResult<Redirect> {
    let config_path = load_app_config().config_path;
    let trimmed = form.db_path.trim();
    if trimmed.is_empty() {
        if config_path.exists() {
            fs::remove_file(&config_path).map_err(internal_error)?;
        }
    } else {
        let resolved = resolve_db_path(trimmed);
        write_db_path_config(&config_path, &resolved.to_string_lossy()).map_err(internal_error)?;
    }
    Ok(Redirect::to("/config#db-path"))
}

async fn load_active_todos(pool: &SqlitePool, query: Option<&str>) -> AppResult<Vec<TodoData>> {
    load_todos_by_archive(pool, false, query).await
}

async fn load_archived_todos(pool: &SqlitePool, query: Option<&str>) -> AppResult<Vec<TodoData>> {
    load_todos_by_archive(pool, true, query).await
}

fn sql_placeholders(count: usize) -> String {
    std::iter::repeat("?")
        .take(count)
        .collect::<Vec<_>>()
        .join(", ")
}

async fn load_tasks_for_todo_ids(
    pool: &SqlitePool,
    todo_ids: &[i64],
) -> Result<HashMap<i64, Vec<TaskData>>, sqlx::Error> {
    let mut tasks_by_todo = HashMap::new();
    if todo_ids.is_empty() {
        return Ok(tasks_by_todo);
    }

    let sql = format!(
        "SELECT id, todo_id, title, amount, done FROM tasks WHERE todo_id IN ({}) ORDER BY todo_id, id",
        sql_placeholders(todo_ids.len())
    );
    let mut query = sqlx::query(&sql);
    for todo_id in todo_ids {
        query = query.bind(todo_id);
    }

    let rows = query.fetch_all(pool).await?;
    for row in rows {
        let todo_id: i64 = row.get("todo_id");
        tasks_by_todo
            .entry(todo_id)
            .or_insert_with(Vec::new)
            .push(TaskData {
                id: row.get("id"),
                title: row.get("title"),
                amount: row.get("amount"),
                done: row.get::<i64, _>("done") == 1,
            });
    }

    Ok(tasks_by_todo)
}

async fn load_task_stats_for_todo_ids(
    pool: &SqlitePool,
    todo_ids: &[i64],
) -> Result<HashMap<i64, (i64, i64)>, sqlx::Error> {
    let mut stats_by_todo = HashMap::new();
    if todo_ids.is_empty() {
        return Ok(stats_by_todo);
    }

    let sql = format!(
        "SELECT todo_id, COUNT(*) AS total, COALESCE(SUM(done), 0) AS done FROM tasks WHERE todo_id IN ({}) GROUP BY todo_id",
        sql_placeholders(todo_ids.len())
    );
    let mut query = sqlx::query(&sql);
    for todo_id in todo_ids {
        query = query.bind(todo_id);
    }

    let rows = query.fetch_all(pool).await?;
    for row in rows {
        let todo_id: i64 = row.get("todo_id");
        let total: i64 = row.get("total");
        let done: i64 = row.get("done");
        stats_by_todo.insert(todo_id, (total, done));
    }

    Ok(stats_by_todo)
}

async fn load_todos_by_archive(
    pool: &SqlitePool,
    archived: bool,
    query: Option<&str>,
) -> AppResult<Vec<TodoData>> {
    let trimmed = query.map(str::trim).filter(|value| !value.is_empty());
    let rows = if let Some(term) = trimmed {
        let pattern = format!("%{}%", term.to_lowercase());
        if archived {
            sqlx::query(
                r#"
                SELECT DISTINCT t.id, t.title, t.order_number, t.purchaser, t.order_date, t.order_pdf,
                       t.budget_spent, t.budget_planned, t.deadline, t.archived_at
                FROM todos t
                LEFT JOIN tasks ON tasks.todo_id = t.id
                WHERE t.archived_at IS NOT NULL
                  AND (
                    LOWER(t.title) LIKE ?
                    OR LOWER(COALESCE(t.order_number, '')) LIKE ?
                    OR LOWER(COALESCE(t.purchaser, '')) LIKE ?
                    OR LOWER(COALESCE(tasks.title, '')) LIKE ?
                  )
                ORDER BY t.archived_at DESC, t.id DESC
                "#,
            )
            .bind(&pattern)
            .bind(&pattern)
            .bind(&pattern)
            .bind(&pattern)
            .fetch_all(pool)
            .await
            .map_err(internal_error)?
        } else {
            sqlx::query(
                r#"
                SELECT DISTINCT t.id, t.title, t.order_number, t.purchaser, t.order_date, t.order_pdf,
                       t.budget_spent, t.budget_planned, t.deadline, t.archived_at
                FROM todos t
                LEFT JOIN tasks ON tasks.todo_id = t.id
                WHERE t.archived_at IS NULL
                  AND (
                    LOWER(t.title) LIKE ?
                    OR LOWER(COALESCE(t.order_number, '')) LIKE ?
                    OR LOWER(COALESCE(t.purchaser, '')) LIKE ?
                    OR LOWER(COALESCE(tasks.title, '')) LIKE ?
                  )
                ORDER BY t.id DESC
                "#,
            )
            .bind(&pattern)
            .bind(&pattern)
            .bind(&pattern)
            .bind(&pattern)
            .fetch_all(pool)
            .await
            .map_err(internal_error)?
        }
    } else if archived {
        sqlx::query(
            "SELECT id, title, order_number, purchaser, order_date, order_pdf, budget_spent, budget_planned, deadline, archived_at FROM todos WHERE archived_at IS NOT NULL ORDER BY archived_at DESC, id DESC",
        )
        .fetch_all(pool)
        .await
        .map_err(internal_error)?
    } else {
        sqlx::query(
            "SELECT id, title, order_number, purchaser, order_date, order_pdf, budget_spent, budget_planned, deadline, archived_at FROM todos WHERE archived_at IS NULL ORDER BY id DESC",
        )
        .fetch_all(pool)
        .await
        .map_err(internal_error)?
    };

    let mut todos = rows
        .into_iter()
        .map(|row| TodoData {
            id: row.get("id"),
            title: row.get("title"),
            order_number: row.get("order_number"),
            purchaser: row.get("purchaser"),
            order_date: row.get("order_date"),
            order_pdf: row.get("order_pdf"),
            budget_spent: row.get("budget_spent"),
            budget_planned: row.get("budget_planned"),
            deadline: row.get("deadline"),
            archived_at: row.get("archived_at"),
            tasks: Vec::new(),
        })
        .collect::<Vec<_>>();

    let todo_ids = todos.iter().map(|todo| todo.id).collect::<Vec<_>>();
    let mut tasks_by_todo = load_tasks_for_todo_ids(pool, &todo_ids)
        .await
        .map_err(internal_error)?;
    for todo in &mut todos {
        todo.tasks = tasks_by_todo.remove(&todo.id).unwrap_or_default();
    }

    Ok(todos)
}

async fn load_auth_enabled(pool: &SqlitePool) -> AppResult<bool> {
    let row = sqlx::query("SELECT value FROM settings WHERE key = 'auth_enabled'")
        .fetch_optional(pool)
        .await
        .map_err(internal_error)?;

    Ok(row
        .and_then(|row| row.try_get::<String, _>("value").ok())
        .map(|value| value == "1")
        .unwrap_or(false))
}

#[derive(Clone)]
struct CurrencyConfig {
    code: String,
    custom: String,
}

#[derive(Clone)]
struct UiTextConfig {
    title: String,
    description: String,
}

#[derive(Clone)]
struct ProtoConfig {
    enabled: bool,
    port: u16,
    token: String,
}

async fn load_currency_config(pool: &SqlitePool) -> AppResult<CurrencyConfig> {
    let raw_code = load_setting_value(pool, "currency_code")
        .await?
        .unwrap_or_else(|| "EUR".to_string());
    let code = normalize_currency_code(&raw_code).to_string();
    let custom = load_setting_value(pool, "currency_custom")
        .await?
        .unwrap_or_default();

    Ok(CurrencyConfig { code, custom })
}

async fn load_ui_text(pool: &SqlitePool) -> AppResult<UiTextConfig> {
    let title = load_setting_value(pool, "dashboard_title")
        .await?
        .unwrap_or_else(|| "BlueTodo Dashboard".to_string());
    let description = load_setting_value(pool, "dashboard_description")
        .await?
        .unwrap_or_default();

    Ok(UiTextConfig {
        title: normalize_title(title),
        description: description.trim().to_string(),
    })
}

async fn load_proto_config(pool: &SqlitePool) -> AppResult<ProtoConfig> {
    let enabled = load_setting_value(pool, "proto_enabled")
        .await?
        .map(|value| value == "1")
        .unwrap_or(false);
    let port = load_setting_value(pool, "proto_port")
        .await?
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(PROTO_DEFAULT_PORT);
    let token = load_setting_value(pool, "proto_token")
        .await?
        .unwrap_or_default();

    Ok(ProtoConfig {
        enabled,
        port,
        token,
    })
}

async fn load_secret_storage_info(pool: &SqlitePool) -> AppResult<SecretStorageInfo> {
    let storage_version = load_app_meta_value(pool, SECRET_STORAGE_META_KEY)
        .await?
        .unwrap_or_else(|| "—".to_string());
    let migrated_at = load_app_meta_value(pool, SECRET_STORAGE_MIGRATED_AT_KEY)
        .await?
        .unwrap_or_else(|| "—".to_string());

    let mut configured_secrets = 0usize;
    let mut encrypted_secrets = 0usize;
    for key in SECRET_SETTING_KEYS {
        if let Some(value) = load_setting_value_raw(pool, key)
            .await
            .map_err(internal_error)?
        {
            if !value.trim().is_empty() {
                configured_secrets += 1;
                if is_encrypted_secret_value(&value) {
                    encrypted_secrets += 1;
                }
            }
        }
    }

    let (key_source, key_location, key_status) = inspect_secret_key_runtime();
    let preferred_setup = format!(
        "{} nach {}",
        SECRET_MASTER_KEY_FILE_ENV,
        default_secret_key_path().to_string_lossy()
    );

    Ok(SecretStorageInfo {
        storage_version,
        migrated_at,
        configured_secrets,
        encrypted_secrets,
        key_source,
        key_location,
        key_status,
        preferred_setup,
    })
}

async fn load_setting_value_raw(
    pool: &SqlitePool,
    key: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|row| row.try_get::<String, _>("value").ok()))
}

async fn load_setting_value(pool: &SqlitePool, key: &str) -> AppResult<Option<String>> {
    let raw = load_setting_value_raw(pool, key)
        .await
        .map_err(internal_error)?;
    let Some(value) = raw else {
        return Ok(None);
    };
    if !is_secret_setting_key(key) {
        return Ok(Some(value));
    }
    let decrypted = decrypt_secret_value(key, &value)
        .map_err(|message| (StatusCode::INTERNAL_SERVER_ERROR, message))?;
    Ok(Some(decrypted))
}

async fn store_setting_value_raw(
    pool: &SqlitePool,
    key: &str,
    value: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE settings SET value = ? WHERE key = ?")
        .bind(value)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

async fn store_setting_value(pool: &SqlitePool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    let stored = if is_secret_setting_key(key) {
        encrypt_secret_value(key, value).map_err(secret_storage_error)?
    } else {
        value.to_string()
    };
    store_setting_value_raw(pool, key, &stored).await?;
    if is_secret_setting_key(key) {
        set_app_meta_value(pool, SECRET_STORAGE_META_KEY, SECRET_STORAGE_VERSION).await?;
    }
    Ok(())
}

async fn migrate_secret_settings(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut migrated_keys = Vec::new();
    let mut any_encrypted = false;

    for key in SECRET_SETTING_KEYS {
        let Some(raw) = load_setting_value_raw(pool, key).await? else {
            continue;
        };
        if raw.trim().is_empty() {
            continue;
        }
        if is_encrypted_secret_value(&raw) {
            decrypt_secret_value(key, &raw).map_err(secret_storage_error)?;
            any_encrypted = true;
            continue;
        }

        let encrypted = encrypt_secret_value(key, &raw).map_err(secret_storage_error)?;
        store_setting_value_raw(pool, key, &encrypted).await?;
        any_encrypted = true;
        migrated_keys.push(key.to_string());
        eprintln!(
            "BlueTodo Secret-Migration: '{}' wurde von Klartext auf verschlüsselte Speicherung umgestellt",
            key
        );
    }

    let cleanup_needed = if !migrated_keys.is_empty() {
        true
    } else if any_encrypted {
        load_app_meta_value_raw(pool, SECRET_STORAGE_MIGRATED_AT_KEY)
            .await?
            .is_none()
    } else {
        false
    };

    if cleanup_needed {
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(pool)
            .await?;
        sqlx::query("VACUUM").execute(pool).await?;
        set_app_meta_value(
            pool,
            SECRET_STORAGE_MIGRATED_AT_KEY,
            &Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        )
        .await?;
    }

    if any_encrypted {
        set_app_meta_value(pool, SECRET_STORAGE_META_KEY, SECRET_STORAGE_VERSION).await?;
    }

    if !migrated_keys.is_empty() {
        eprintln!(
            "BlueTodo Secret-Migration abgeschlossen: {}",
            migrated_keys.join(", ")
        );
    }

    Ok(())
}

async fn resolve_secret_form_value(
    pool: &SqlitePool,
    key: &str,
    submitted: Option<&str>,
    clear: bool,
) -> AppResult<String> {
    if clear {
        return Ok(String::new());
    }
    if let Some(value) = normalize_optional_string(submitted) {
        return Ok(value);
    }
    Ok(load_setting_value(pool, key).await?.unwrap_or_default())
}

async fn load_app_meta_value(pool: &SqlitePool, key: &str) -> AppResult<Option<String>> {
    let row = sqlx::query("SELECT value FROM app_meta WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(internal_error)?;
    Ok(row.and_then(|row| row.try_get::<String, _>("value").ok()))
}

async fn load_app_version(pool: &SqlitePool) -> AppResult<Option<String>> {
    load_app_meta_value(pool, "app_version").await
}

async fn load_proto_version(pool: &SqlitePool) -> AppResult<Option<String>> {
    load_app_meta_value(pool, "proto_version").await
}

async fn load_app_id(pool: &SqlitePool) -> AppResult<Option<String>> {
    load_app_meta_value(pool, "app_id").await
}

async fn load_sqlite_version(pool: &SqlitePool) -> AppResult<String> {
    let row = sqlx::query("SELECT sqlite_version() AS version")
        .fetch_one(pool)
        .await
        .map_err(internal_error)?;
    Ok(row.get::<String, _>("version"))
}

async fn load_sqlite_size_bytes(pool: &SqlitePool) -> AppResult<i64> {
    let page_count_row = sqlx::query("PRAGMA page_count")
        .fetch_one(pool)
        .await
        .map_err(internal_error)?;
    let page_size_row = sqlx::query("PRAGMA page_size")
        .fetch_one(pool)
        .await
        .map_err(internal_error)?;
    let page_count: i64 = page_count_row.get(0);
    let page_size: i64 = page_size_row.get(0);
    Ok(page_count.saturating_mul(page_size))
}

async fn load_db_file_path(pool: &SqlitePool) -> AppResult<String> {
    let rows = sqlx::query("PRAGMA database_list")
        .fetch_all(pool)
        .await
        .map_err(internal_error)?;
    for row in rows {
        let name: String = row.try_get("name").unwrap_or_else(|_| "main".to_string());
        if name == "main" {
            let file: Option<String> = row.try_get("file").ok();
            let file = file.unwrap_or_default();
            if file.trim().is_empty() {
                return Ok("In-Memory".to_string());
            }
            return Ok(file);
        }
    }
    Ok("Unbekannt".to_string())
}

#[derive(Clone)]
struct MetricsConfig {
    enabled: bool,
    version: String,
    url: String,
    token: String,
    v1_url: String,
    v1_db: String,
    v1_user: String,
    v1_password: String,
    v1_autocreate: bool,
    interval_seconds: u64,
    instance: String,
}

#[derive(Clone)]
struct UpdateConfig {
    enabled: bool,
    url: String,
    user: String,
    password: String,
    channel: String,
}

#[derive(Clone)]
struct UpdateStatus {
    last_checked: String,
    last_status: String,
    available: bool,
    latest_version: String,
    latest_notes: String,
    latest_url: String,
    latest_sha256: String,
    latest_size: String,
}

async fn load_metrics_config(pool: &SqlitePool) -> AppResult<MetricsConfig> {
    let enabled = load_setting_value(pool, "metrics_enabled")
        .await?
        .map(|value| value == "1")
        .unwrap_or(false);
    let version = load_setting_value(pool, "metrics_version")
        .await?
        .unwrap_or_else(|| "v2".to_string());
    let url = load_setting_value(pool, "metrics_url")
        .await?
        .unwrap_or_default();
    let token = load_setting_value(pool, "metrics_token")
        .await?
        .unwrap_or_default();
    let v1_url = load_setting_value(pool, "metrics_v1_url")
        .await?
        .unwrap_or_default();
    let v1_db = load_setting_value(pool, "metrics_v1_db")
        .await?
        .unwrap_or_default();
    let v1_user = load_setting_value(pool, "metrics_v1_user")
        .await?
        .unwrap_or_default();
    let v1_password = load_setting_value(pool, "metrics_v1_password")
        .await?
        .unwrap_or_default();
    let v1_autocreate = load_setting_value(pool, "metrics_v1_autocreate")
        .await?
        .map(|value| value == "1")
        .unwrap_or(true);
    let interval_seconds = load_setting_value(pool, "metrics_interval")
        .await?
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.max(5))
        .unwrap_or(30);
    let instance = load_setting_value(pool, "metrics_instance")
        .await?
        .unwrap_or_default();

    Ok(MetricsConfig {
        enabled,
        version,
        url,
        token,
        v1_url,
        v1_db,
        v1_user,
        v1_password,
        v1_autocreate,
        interval_seconds,
        instance,
    })
}

async fn load_update_config(pool: &SqlitePool) -> AppResult<UpdateConfig> {
    let enabled = load_setting_value(pool, "update_enabled")
        .await?
        .map(|value| value == "1")
        .unwrap_or(false);
    let url = load_setting_value(pool, "update_url")
        .await?
        .unwrap_or_default();
    let user = load_setting_value(pool, "update_user")
        .await?
        .unwrap_or_default();
    let password = load_setting_value(pool, "update_password")
        .await?
        .unwrap_or_default();
    let channel = load_setting_value(pool, "update_channel")
        .await?
        .unwrap_or_else(|| "stable".to_string());

    Ok(UpdateConfig {
        enabled,
        url,
        user,
        password,
        channel,
    })
}

async fn load_update_status(pool: &SqlitePool) -> AppResult<UpdateStatus> {
    let last_checked = load_setting_value(pool, "update_last_checked")
        .await?
        .unwrap_or_default();
    let last_status = load_setting_value(pool, "update_last_status")
        .await?
        .unwrap_or_default();
    let available = load_setting_value(pool, "update_available")
        .await?
        .map(|value| value == "1")
        .unwrap_or(false);
    let latest_version = load_setting_value(pool, "update_latest_version")
        .await?
        .unwrap_or_default();
    let latest_notes = load_setting_value(pool, "update_latest_notes")
        .await?
        .unwrap_or_default();
    let latest_url = load_setting_value(pool, "update_latest_url")
        .await?
        .unwrap_or_default();
    let latest_sha256 = load_setting_value(pool, "update_latest_sha256")
        .await?
        .unwrap_or_default();
    let latest_size = load_setting_value(pool, "update_latest_size")
        .await?
        .unwrap_or_default();

    Ok(UpdateStatus {
        last_checked,
        last_status,
        available,
        latest_version,
        latest_notes,
        latest_url,
        latest_sha256,
        latest_size,
    })
}

#[derive(Clone)]
struct TodoData {
    id: i64,
    title: String,
    order_number: Option<String>,
    purchaser: Option<String>,
    order_date: Option<String>,
    order_pdf: Option<String>,
    budget_spent: f64,
    budget_planned: f64,
    deadline: Option<String>,
    archived_at: Option<String>,
    tasks: Vec<TaskData>,
}

#[derive(Clone)]
struct TaskData {
    id: i64,
    title: String,
    amount: f64,
    done: bool,
}

fn append_search_value(target: &mut String, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    if !target.is_empty() {
        target.push(' ');
    }
    target.push_str(trimmed);
}

fn todo_search_blob(todo: &TodoData) -> String {
    let mut blob = String::new();
    append_search_value(&mut blob, &todo.title);
    if let Some(value) = todo.order_number.as_deref() {
        append_search_value(&mut blob, value);
    }
    if let Some(value) = todo.purchaser.as_deref() {
        append_search_value(&mut blob, value);
    }
    for task in &todo.tasks {
        append_search_value(&mut blob, &task.title);
    }
    blob.to_lowercase()
}

fn render_todo_card(todo: &TodoData, currency_label: &str) -> String {
    let total_tasks = todo.tasks.len();
    let done_tasks = todo.tasks.iter().filter(|task| task.done).count();
    let progress = if total_tasks == 0 {
        0.0
    } else {
        (done_tasks as f64 / total_tasks as f64) * 100.0
    };

    let title_raw = &todo.title;
    let title = escape_html(title_raw);
    let order_number = todo
        .order_number
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let purchaser = todo.purchaser.as_deref().unwrap_or("").trim().to_string();
    let order_number_display = if order_number.is_empty() {
        "—".to_string()
    } else {
        order_number.clone()
    };
    let purchaser_display = if purchaser.is_empty() {
        "—".to_string()
    } else {
        purchaser.clone()
    };
    let pdf_path = todo.order_pdf.as_deref().unwrap_or("").trim();
    let has_pdf = !pdf_path.is_empty();
    let order_date = todo
        .order_date
        .as_deref()
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        .map(|date| date.format("%d.%m.%Y").to_string())
        .unwrap_or_else(|| "—".to_string());
    let order_date_value = todo.order_date.as_deref().unwrap_or("");

    let deadline = todo
        .deadline
        .as_deref()
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        .map(|date| date.format("%d.%m.%Y").to_string())
        .unwrap_or_else(|| "—".to_string());
    let deadline_value = todo.deadline.as_deref().unwrap_or("");

    let budget_spent = format!("{:.2}", todo.budget_spent);
    let budget_planned = format!("{:.2}", todo.budget_planned);
    let budget_remaining = format!("{:.2}", todo.budget_planned - todo.budget_spent);
    let spent_percent = if todo.budget_planned > 0.0 {
        Some((todo.budget_spent / todo.budget_planned) * 100.0)
    } else {
        None
    };
    let spent_percent_label = spent_percent
        .map(|value| format!("{:.0}%", value))
        .unwrap_or_else(|| "—".to_string());
    let spent_over = spent_percent.map(|value| value > 100.0).unwrap_or(false);
    let budget_spent_display = format_currency_value(&budget_spent, currency_label);
    let budget_planned_display = format_currency_value(&budget_planned, currency_label);
    let budget_remaining_display = format_currency_value(&budget_remaining, currency_label);
    let currency_hint = currency_label_hint(currency_label);

    let mut card = String::new();
    let can_archive = total_tasks > 0 && total_tasks == done_tasks;

    let search_blob = escape_html(&todo_search_blob(todo));
    card.push_str(&format!(
        "<article class=\"todo-card\" id=\"todo-{}\" data-search=\"{}\">",
        todo.id, search_blob
    ));
    card.push_str("<header class=\"todo-header\">");
    card.push_str(&format!(
        "<div><h3 data-search-text>{}</h3>\
        <div class=\"meta-line\">Bestellnr.: <strong data-search-text>{}</strong></div>\
        <div class=\"meta-line\">Besteller: <strong data-search-text>{}</strong></div>\
        <div class=\"meta-line\">Bestelldatum: <strong>{}</strong></div>\
        <div class=\"deadline\">Deadline: <strong>{}</strong></div></div>",
        title,
        escape_html(&order_number_display),
        escape_html(&purchaser_display),
        escape_html(&order_date),
        escape_html(&deadline)
    ));
    card.push_str("<div class=\"todo-actions\">");
    if has_pdf {
        card.push_str(&format!(
            "<a class=\"icon-btn pdf-btn\" href=\"/todos/{}/pdf\" target=\"_blank\" aria-label=\"PDF öffnen\" title=\"PDF öffnen\">PDF</a>",
            todo.id
        ));
    }
    card.push_str(&format!(
        "<button type=\"button\" class=\"icon-btn todo-edit-trigger\" data-dialog=\"todo-edit-{}\" aria-label=\"Bestellung bearbeiten\">&#9881;</button>",
        todo.id
    ));
    if can_archive {
        card.push_str(&format!(
            "<form class=\"todo-archive\" method=\"post\" action=\"/todos/{}/archive\" data-confirm=\"Bestellung wirklich archivieren?\">",
            todo.id
        ));
        card.push_str("<button class=\"icon-btn archive-btn\" type=\"submit\" aria-label=\"Bestellung archivieren\" title=\"Archivieren\">&#128230;</button>");
        card.push_str("</form>");
    }
    card.push_str("</div>");
    card.push_str("</header>");
    card.push_str(&format!(
        "<dialog id=\"todo-edit-{}\" class=\"edit-dialog\">",
        todo.id
    ));
    card.push_str("<div class=\"dialog-header\">");
    card.push_str("<h4>Bestellung bearbeiten</h4>");
    card.push_str("<button type=\"button\" class=\"icon-btn dialog-close\" data-close aria-label=\"Schließen\">&#215;</button>");
    card.push_str("</div>");
    card.push_str(&format!(
        "<form class=\"todo-edit\" method=\"post\" action=\"/todos/{}/update\">",
        todo.id
    ));
    card.push_str("<div class=\"field\">");
    card.push_str("<label>Titel</label>");
    card.push_str(&format!(
        "<input name=\"title\" required value=\"{}\" />",
        escape_html(title_raw)
    ));
    card.push_str("</div>");
    card.push_str("<div class=\"grid\">");
    card.push_str("<div class=\"field\">");
    card.push_str("<label>Bestellnummer</label>");
    card.push_str(&format!(
        "<input name=\"order_number\" required value=\"{}\" />",
        escape_html(&order_number)
    ));
    card.push_str("</div>");
    card.push_str("<div class=\"field\">");
    card.push_str("<label>Besteller</label>");
    card.push_str(&format!(
        "<input name=\"purchaser\" required value=\"{}\" />",
        escape_html(&purchaser)
    ));
    card.push_str("</div>");
    card.push_str("<div class=\"field\">");
    card.push_str("<label>Bestelldatum</label>");
    card.push_str(&format!(
        "<input name=\"order_date\" type=\"date\" required value=\"{}\" />",
        escape_html(order_date_value)
    ));
    card.push_str("</div>");
    card.push_str("<div class=\"field\">");
    card.push_str(&format!("<label>Budget geplant{}</label>", currency_hint));
    card.push_str(&format!(
        "<input name=\"budget_planned\" type=\"number\" step=\"0.01\" value=\"{}\" />",
        budget_planned
    ));
    card.push_str("</div>");
    card.push_str("<div class=\"field\">");
    card.push_str("<label>Deadline</label>");
    card.push_str(&format!(
        "<input name=\"deadline\" type=\"date\" value=\"{}\" />",
        escape_html(deadline_value)
    ));
    card.push_str("</div>");
    card.push_str("</div>");
    card.push_str("<div class=\"dialog-actions\">");
    card.push_str("<button class=\"btn primary\" type=\"submit\">Änderungen speichern</button>");
    card.push_str("</div>");
    card.push_str("</form>");
    card.push_str(&format!(
        "<form class=\"pdf-upload\" method=\"post\" action=\"/todos/{}/upload\" enctype=\"multipart/form-data\">",
        todo.id
    ));
    card.push_str("<div class=\"field\">");
    card.push_str("<label>Bestellung (PDF, max 10&nbsp;MB)</label>");
    card.push_str("<input type=\"file\" name=\"pdf\" accept=\"application/pdf\" required />");
    card.push_str("</div>");
    card.push_str("<button class=\"btn\" type=\"submit\">PDF hochladen</button>");
    card.push_str("</form>");
    card.push_str(&format!(
        "<form class=\"todo-delete\" method=\"post\" action=\"/todos/{}/delete\" data-confirm=\"Bestellung wirklich löschen?\">",
        todo.id
    ));
    card.push_str("<button class=\"btn danger\" type=\"submit\">Bestellung löschen</button>");
    card.push_str("</form>");
    card.push_str("</dialog>");

    card.push_str("<div class=\"progress\">");
    card.push_str(&format!(
        "<div class=\"progress-bar\"><span style=\"width: {}%\"></span></div>",
        progress
    ));
    card.push_str(&format!(
        "<div class=\"progress-meta\">{}/{} erledigt ({:.0}%)</div>",
        done_tasks, total_tasks, progress
    ));
    card.push_str("</div>");

    card.push_str("<div class=\"budget\">");
    card.push_str(&format!(
        "<div class=\"budget-item\"><span class=\"budget-label\">Ausgegeben</span><div class=\"budget-line\"><strong>{}</strong><span class=\"budget-percent {}\">({})</span></div></div>",
        budget_spent_display,
        if spent_over { "budget-over" } else { "" },
        escape_html(&spent_percent_label)
    ));
    card.push_str(&format!(
        "<div class=\"budget-item\"><span class=\"budget-label\">Geplant</span><div class=\"budget-line\"><strong>{}</strong></div></div>",
        budget_planned_display
    ));
    card.push_str(&format!(
        "<div class=\"budget-item\"><span class=\"budget-label\">Rest</span><div class=\"budget-line\"><strong>{}</strong></div></div>",
        budget_remaining_display
    ));
    card.push_str("</div>");

    card.push_str("<div class=\"tasks\">");
    if todo.tasks.is_empty() {
        card.push_str("<p class=\"muted\">Noch keine Einzelaufträge.</p>");
    } else {
        for task in &todo.tasks {
            let task_title_raw = &task.title;
            let task_title = escape_html(task_title_raw);
            let status_class = if task.done { "task done" } else { "task" };
            let toggle_label = if task.done {
                "Zurücksetzen"
            } else {
                "Erledigt"
            };
            let toggle_symbol = if task.done { "↺" } else { "✓" };
            let toggle_class = if task.done { "undo" } else { "complete" };
            let task_amount_value = format!("{:.2}", task.amount);
            let task_amount_display = format_currency_value(&task_amount_value, currency_label);
            card.push_str("<div class=\"task-row\">");
            card.push_str("<div class=\"task-content\">");
            card.push_str(&format!(
                "<span class=\"{}\" data-search-text>{}</span>",
                status_class, task_title
            ));
            card.push_str(&format!(
                "<div class=\"task-desc\">Summe: <strong>{}</strong></div>",
                task_amount_display
            ));
            card.push_str("</div>");
            card.push_str("<div class=\"task-actions\">");
            card.push_str(&format!(
                "<button type=\"button\" class=\"icon-btn task-edit-trigger\" data-dialog=\"task-edit-{}\" aria-label=\"Einzelauftrag bearbeiten\">&#9881;</button>",
                task.id
            ));
            card.push_str(&format!(
                "<form class=\"task-toggle-form\" method=\"post\" action=\"/tasks/{}/toggle\">",
                task.id
            ));
            card.push_str(&format!(
                "<button class=\"icon-btn action-btn {}\" type=\"submit\" aria-label=\"{}\" title=\"{}\">{}</button>",
                toggle_class,
                toggle_label,
                toggle_label,
                toggle_symbol
            ));
            card.push_str("</form>");
            card.push_str("</div>");
            card.push_str("</div>");
            card.push_str(&format!(
                "<dialog id=\"task-edit-{}\" class=\"edit-dialog\">",
                task.id
            ));
            card.push_str("<div class=\"dialog-header\">");
            card.push_str("<h4>Einzelauftrag bearbeiten</h4>");
            card.push_str("<button type=\"button\" class=\"icon-btn dialog-close\" data-close aria-label=\"Schließen\">&#215;</button>");
            card.push_str("</div>");
            card.push_str(&format!(
                "<form class=\"task-edit-form\" method=\"post\" action=\"/tasks/{}/update\">",
                task.id
            ));
            card.push_str("<div class=\"field\">");
            card.push_str("<label>Titel</label>");
            card.push_str(&format!(
                "<input name=\"title\" required value=\"{}\" />",
                escape_html(task_title_raw)
            ));
            card.push_str("</div>");
            card.push_str("<div class=\"field\">");
            card.push_str(&format!("<label>Summe{}</label>", currency_hint));
            card.push_str(&format!(
                "<input name=\"amount\" type=\"number\" step=\"0.01\" required value=\"{}\" />",
                task_amount_value
            ));
            card.push_str("</div>");
            card.push_str("<button class=\"btn\" type=\"submit\">Speichern</button>");
            card.push_str("</form>");
            card.push_str("</dialog>");
        }
    }
    card.push_str("</div>");

    card.push_str(&format!(
        "<form class=\"task-add\" method=\"post\" action=\"/todos/{}/tasks\">",
        todo.id
    ));
    card.push_str("<input name=\"title\" placeholder=\"Neuer Einzelauftrag\" required />");
    card.push_str(&format!(
        "<input name=\"amount\" type=\"number\" step=\"0.01\" required placeholder=\"Summe{}\" />",
        currency_hint
    ));
    card.push_str("<button class=\"btn\" type=\"submit\">Hinzufügen</button>");
    card.push_str("</form>");

    card.push_str("</article>");
    card
}

fn render_archive_item(todo: &TodoData, currency_label: &str) -> String {
    let total_tasks = todo.tasks.len();
    let done_tasks = todo.tasks.iter().filter(|task| task.done).count();
    let progress = if total_tasks == 0 {
        0.0
    } else {
        (done_tasks as f64 / total_tasks as f64) * 100.0
    };

    let title_raw = &todo.title;
    let title = escape_html(title_raw);
    let order_number = todo
        .order_number
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let purchaser = todo.purchaser.as_deref().unwrap_or("").trim().to_string();
    let order_number_display = if order_number.is_empty() {
        "—".to_string()
    } else {
        order_number.clone()
    };
    let purchaser_display = if purchaser.is_empty() {
        "—".to_string()
    } else {
        purchaser.clone()
    };
    let pdf_path = todo.order_pdf.as_deref().unwrap_or("").trim();
    let has_pdf = !pdf_path.is_empty();
    let order_date = todo
        .order_date
        .as_deref()
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        .map(|date| date.format("%d.%m.%Y").to_string())
        .unwrap_or_else(|| "—".to_string());

    let deadline = todo
        .deadline
        .as_deref()
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        .map(|date| date.format("%d.%m.%Y").to_string())
        .unwrap_or_else(|| "—".to_string());

    let budget_spent = format!("{:.2}", todo.budget_spent);
    let budget_planned = format!("{:.2}", todo.budget_planned);
    let budget_remaining = format!("{:.2}", todo.budget_planned - todo.budget_spent);
    let spent_percent = if todo.budget_planned > 0.0 {
        Some((todo.budget_spent / todo.budget_planned) * 100.0)
    } else {
        None
    };
    let spent_percent_label = spent_percent
        .map(|value| format!("{:.0}%", value))
        .unwrap_or_else(|| "—".to_string());
    let spent_over = spent_percent.map(|value| value > 100.0).unwrap_or(false);
    let budget_spent_display = format_currency_value(&budget_spent, currency_label);
    let budget_planned_display = format_currency_value(&budget_planned, currency_label);
    let budget_remaining_display = format_currency_value(&budget_remaining, currency_label);
    let archived_at = format_archived_at(&todo.archived_at);

    let mut item = String::new();
    let search_blob = escape_html(&todo_search_blob(todo));
    item.push_str(&format!(
        "<details class=\"archive-item\" id=\"archive-{}\" data-search=\"{}\">",
        todo.id, search_blob
    ));
    item.push_str("<summary>");
    item.push_str("<div class=\"archive-summary\">");
    item.push_str(&format!("<strong data-search-text>{}</strong>", title));
    item.push_str(&format!(
        "<span class=\"archive-meta\">{} / {} erledigt ({:.0}%)</span>",
        done_tasks, total_tasks, progress
    ));
    item.push_str("</div>");
    item.push_str(&format!(
        "<span class=\"archive-meta\">Archiviert: {}</span>",
        escape_html(&archived_at)
    ));
    item.push_str("</summary>");

    item.push_str("<div class=\"archive-body\">");
    item.push_str(&format!(
        "<div class=\"meta-line\">Bestellnr.: <strong data-search-text>{}</strong></div>",
        escape_html(&order_number_display)
    ));
    item.push_str(&format!(
        "<div class=\"meta-line\">Besteller: <strong data-search-text>{}</strong></div>",
        escape_html(&purchaser_display)
    ));
    if has_pdf {
        item.push_str(&format!(
            "<div class=\"meta-line\"><a class=\"pdf-link\" href=\"/todos/{}/pdf\" target=\"_blank\">PDF öffnen</a></div>",
            todo.id
        ));
    }
    item.push_str(&format!(
        "<div class=\"meta-line\">Bestelldatum: <strong>{}</strong></div>",
        escape_html(&order_date)
    ));
    item.push_str(&format!(
        "<div class=\"deadline\">Deadline: <strong>{}</strong></div>",
        escape_html(&deadline)
    ));

    item.push_str("<div class=\"budget\">");
    item.push_str(&format!(
        "<div class=\"budget-item\"><span class=\"budget-label\">Ausgegeben</span><div class=\"budget-line\"><strong>{}</strong><span class=\"budget-percent {}\">({})</span></div></div>",
        budget_spent_display,
        if spent_over { "budget-over" } else { "" },
        escape_html(&spent_percent_label)
    ));
    item.push_str(&format!(
        "<div class=\"budget-item\"><span class=\"budget-label\">Geplant</span><div class=\"budget-line\"><strong>{}</strong></div></div>",
        budget_planned_display
    ));
    item.push_str(&format!(
        "<div class=\"budget-item\"><span class=\"budget-label\">Rest</span><div class=\"budget-line\"><strong>{}</strong></div></div>",
        budget_remaining_display
    ));
    item.push_str("</div>");

    item.push_str("<div class=\"archive-tasks\">");
    if todo.tasks.is_empty() {
        item.push_str("<p class=\"muted\">Keine Einzelaufträge.</p>");
    } else {
        for task in &todo.tasks {
            let task_title = escape_html(&task.title);
            let task_amount_value = format!("{:.2}", task.amount);
            let task_amount_display = format_currency_value(&task_amount_value, currency_label);
            let marker = if task.done { "✓" } else { "•" };
            item.push_str("<div class=\"archive-task\">");
            item.push_str(&format!(
                "<span class=\"task-marker\">{}</span><div><div class=\"task-title\" data-search-text>{}</div>",
                marker, task_title
            ));
            item.push_str(&format!(
                "<div class=\"task-desc\">Summe: <strong>{}</strong></div>",
                task_amount_display
            ));
            item.push_str("</div>");
            item.push_str("</div>");
        }
    }
    item.push_str("</div>");

    item.push_str(&format!(
        "<form class=\"archive-restore\" method=\"post\" action=\"/todos/{}/unarchive\">",
        todo.id
    ));
    item.push_str("<button class=\"btn\" type=\"submit\">Wiederherstellen</button>");
    item.push_str("</form>");
    item.push_str("</div>");
    item.push_str("</details>");

    item
}

fn render_search_panel(query: &str, scope: &str) -> String {
    let query_value = escape_html(query);
    let active_selected = if scope == "active" { "selected" } else { "" };
    let archive_selected = if scope == "archive" { "selected" } else { "" };
    format!(
        r#"<section class="panel search-panel">
  <form class="search-form" method="get" action="{}" data-scope="{}">
    <div class="field">
      <label>Suche</label>
      <input id="search-input" name="q" placeholder="Titel, Bestellnr., Besteller, Einzelauftrag" value="{}" />
    </div>
    <div class="field">
      <label>Bereich</label>
      <select id="search-scope" name="scope">
        <option value="active" {}>Aktive Bestellungen</option>
        <option value="archive" {}>Archiv</option>
      </select>
    </div>
    <div class="field">
      <label>&nbsp;</label>
      <button class="btn" type="button" id="search-reset">Zurücksetzen</button>
    </div>
  </form>
  <p class="search-help">Live-Filter ist aktiv – Enter nicht nötig.</p>
</section>"#,
        if scope == "archive" { "/archive" } else { "/" },
        scope,
        query_value,
        active_selected,
        archive_selected
    )
}

fn page_layout(title: &str, body: String, footer_text: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <style>
    :root {{
      --ink: #1d2322;
      --muted: #5f6f6c;
      --accent: #2f6f6d;
      --accent-strong: #235c5a;
      --accent-soft: #cde5df;
      --warm: #e07a5f;
      --bg-1: #f5f1e8;
      --bg-2: #e4f0f5;
      --card: #ffffff;
      --line: #d7e3df;
      --shadow: 0 14px 30px rgba(33, 46, 43, 0.08);
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      font-family: "Fira Sans", "Segoe UI", system-ui, sans-serif;
      color: var(--ink);
      background: radial-gradient(circle at 15% 20%, rgba(255, 255, 255, 0.9), transparent 45%),
                  linear-gradient(130deg, var(--bg-1), var(--bg-2));
      min-height: 100vh;
    }}

    h1, h2, h3 {{ margin: 0 0 0.4rem; font-weight: 700; letter-spacing: -0.02em; }}
    p {{ margin: 0 0 1rem; line-height: 1.5; color: var(--muted); }}

    .container {{ max-width: 1080px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }}

    .top-bar {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
      padding: 1.5rem 0 1rem;
      border-bottom: 1px solid var(--line);
    }}

    .status {{ display: flex; gap: 1rem; align-items: center; }}
    .status-line {{ font-size: 0.95rem; color: var(--muted); }}

    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.55rem 1.2rem;
      border-radius: 999px;
      border: 1px solid var(--accent);
      color: var(--accent);
      background: transparent;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
    }}

    .btn.primary {{
      background: var(--accent);
      color: white;
      border-color: var(--accent);
    }}

    .btn.primary:hover {{ background: var(--accent-strong); }}
    .btn.danger {{
      border-color: #b3432c;
      color: #b3432c;
      background: transparent;
    }}
    .btn.danger:hover {{
      background: #b3432c;
      color: #ffffff;
    }}

    .panel {{
      margin-top: 2rem;
      background: var(--card);
      border-radius: 18px;
      padding: 1.5rem;
      box-shadow: var(--shadow);
      border: 1px solid rgba(215, 227, 223, 0.7);
    }}

    .todo-form {{ display: grid; gap: 1rem; }}
    .todo-form .grid {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .currency-form {{ display: grid; gap: 1rem; max-width: 520px; }}
    .text-form {{ display: grid; gap: 1rem; max-width: 520px; }}
    .proto-form {{ display: grid; gap: 1rem; max-width: 520px; }}
    .field {{ display: flex; flex-direction: column; gap: 0.35rem; }}
    label {{ font-weight: 600; font-size: 0.9rem; }}
    input, textarea, select {{
      border-radius: 10px;
      border: 1px solid var(--line);
      padding: 0.65rem 0.75rem;
      font: inherit;
      background: #fbfcfb;
    }}
    select {{
      appearance: none;
    }}

    .todos {{
      margin-top: 2.5rem;
      display: grid;
      gap: 1.8rem;
    }}

    .todo-card {{
      background: var(--card);
      border-radius: 20px;
      padding: 1.7rem;
      box-shadow: var(--shadow);
      border: 1px solid rgba(215, 227, 223, 0.7);
      display: grid;
      gap: 1.2rem;
      position: relative;
      scroll-margin-top: 1.5rem;
    }}

    .todo-header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 1rem;
      align-items: flex-start;
    }}
    .todo-actions {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .todo-archive {{ margin: 0; }}
    .archive-btn {{
      background: #f0f6f4;
      border-color: #c9dfd8;
      color: var(--accent-strong);
    }}
    .deadline {{ font-size: 0.95rem; color: var(--muted); }}
    .meta-line {{ font-size: 0.95rem; color: var(--muted); }}

    .progress {{ display: grid; gap: 0.5rem; }}
    .progress-bar {{
      height: 12px;
      background: var(--accent-soft);
      border-radius: 999px;
      overflow: hidden;
    }}
    .progress-bar span {{
      display: block;
      height: 100%;
      background: linear-gradient(90deg, var(--accent), var(--warm));
    }}

    .progress-meta {{ font-size: 0.9rem; color: var(--muted); }}

    .budget {{
      display: inline-flex;
      flex-wrap: wrap;
      align-items: flex-start;
      gap: 0.75rem 1.5rem;
      background: #f4f8f7;
      padding: 0.9rem 1rem;
      border-radius: 14px;
      border: 1px solid var(--line);
      width: fit-content;
      max-width: 100%;
      justify-self: start;
    }}

    .budget-item {{
      display: grid;
      gap: 0.25rem;
    }}
    .budget-label {{
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .budget-line {{
      display: inline-flex;
      align-items: baseline;
      gap: 0.35rem;
      white-space: nowrap;
    }}
    .budget-percent {{
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .budget-percent.budget-over {{
      color: #b3432c;
      font-weight: 600;
    }}

    .info-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      background: #f8f6f1;
      padding: 0.9rem 1rem;
      border-radius: 14px;
      border: 1px solid var(--line);
    }}
    .info-grid div {{ display: grid; gap: 0.25rem; }}
    .info-grid span {{ font-size: 0.85rem; color: var(--muted); }}
    .info-grid.path-grid {{ grid-template-columns: 1fr; }}
    .info-grid.path-grid .path-value {{
      overflow-wrap: anywhere;
      word-break: break-word;
    }}

    .tasks {{ display: grid; gap: 0.9rem; }}
    .task-row {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 0.75rem 1rem;
      align-items: start;
    }}
    .task-actions {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .task-toggle-form {{ margin: 0; }}
    .task-content {{ display: grid; gap: 0.2rem; }}
    .task-desc {{ font-size: 0.85rem; color: var(--muted); }}

    .task {{ color: var(--ink); font-weight: 600; }}
    .task.done {{ color: var(--muted); text-decoration: line-through; }}

    .icon-btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 34px;
      height: 34px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #ffffff;
      color: var(--muted);
      cursor: pointer;
      font-size: 1rem;
    }}
    .icon-btn:hover {{
      color: var(--accent-strong);
      border-color: var(--accent);
    }}
    .pdf-btn {{
      width: auto;
      padding: 0 0.65rem;
      font-size: 0.75rem;
      font-weight: 600;
      text-decoration: none;
      color: var(--accent-strong);
    }}
    .pdf-link {{
      color: var(--accent-strong);
      text-decoration: none;
      font-weight: 600;
    }}

    .todo-edit-trigger {{
      position: static;
    }}
    .task-edit-trigger {{
      justify-self: end;
    }}
    .action-btn {{
      width: 40px;
      height: 40px;
      font-size: 1.05rem;
    }}
    .action-btn.complete {{
      background: #d7f1e5;
      border-color: #b6e2d2;
      color: #1c6b4f;
    }}
    .action-btn.undo {{
      background: #fff0da;
      border-color: #f1d1ad;
      color: #8a4b1d;
    }}

    .todo-edit,
    .task-edit-form {{
      display: grid;
      gap: 0.8rem;
      margin-top: 0.8rem;
    }}

    .task-add {{
      display: grid;
      gap: 0.75rem;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      align-items: end;
    }}
    .task-add input,
    .task-add textarea {{
      min-width: 180px;
      height: 44px;
    }}
    .task-add textarea {{
      resize: vertical;
    }}
    .pdf-upload {{
      display: grid;
      gap: 0.6rem;
      margin-top: 0.8rem;
    }}
    .search-panel {{ padding: 0.9rem 1.1rem; }}
    .search-form {{
      display: grid;
      gap: 0.7rem;
      align-items: end;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    }}
    .search-form input,
    .search-form select {{
      height: 44px;
    }}
    .search-help {{
      font-size: 0.85rem;
      color: var(--muted);
      margin: 0;
    }}
    .notes {{
      margin-top: 0.8rem;
    }}
    .action-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.6rem;
      margin-top: 0.8rem;
    }}

    .edit-dialog {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 1rem;
      width: min(520px, 92vw);
      box-shadow: var(--shadow);
    }}
    .edit-dialog::backdrop {{
      background: rgba(29, 35, 34, 0.25);
      backdrop-filter: blur(2px);
    }}
    .dialog-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
      margin-bottom: 0.6rem;
    }}
    .dialog-header h4 {{
      margin: 0;
    }}
    .dialog-actions {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
    }}
    .todo-delete {{
      margin-top: 0.8rem;
    }}

    .archive {{
      background: rgba(255, 255, 255, 0.85);
    }}
    .archive-count {{
      font-size: 0.85rem;
      color: var(--muted);
      margin-left: 0.4rem;
    }}
    .archive-list {{
      display: grid;
      gap: 0.75rem;
      margin-top: 1rem;
    }}
    .archive-item {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--card);
      box-shadow: var(--shadow);
    }}
    .archive-item summary {{
      list-style: none;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.8rem 1rem;
    }}
    .archive-item summary::-webkit-details-marker {{
      display: none;
    }}
    .archive-summary {{
      display: grid;
      gap: 0.2rem;
    }}
    .archive-meta {{
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .archive-body {{
      padding: 0 1rem 1rem;
      display: grid;
      gap: 0.9rem;
    }}
    .archive-tasks {{
      display: grid;
      gap: 0.5rem;
    }}
    .archive-task {{
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.5rem;
      align-items: start;
    }}
    .archive-task .task-marker {{
      font-weight: 700;
      color: var(--accent);
    }}
    .archive-task .task-title {{
      font-weight: 600;
    }}
    .archive-restore {{
      margin: 0;
    }}

    .site-footer {{
      margin-top: 3rem;
      text-align: center;
      font-size: 0.9rem;
      color: var(--muted);
    }}

    .muted {{ color: var(--muted); margin: 0; }}

    .empty {{
      text-align: center;
      padding: 2.5rem 1.5rem;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.7);
      border: 1px dashed var(--line);
    }}

    .config-form {{ display: flex; align-items: center; gap: 1rem; margin-top: 1rem; }}
    .toggle {{ display: inline-flex; align-items: center; gap: 0.6rem; font-weight: 600; }}
    .metrics-group {{
      margin-top: 1rem;
      padding: 1rem;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: #f8f6f1;
      display: grid;
      gap: 0.75rem;
    }}
    .metrics-group h3 {{
      margin: 0;
      font-size: 1rem;
    }}
    .warning {{
      margin: 0.8rem 0 0;
      padding: 0.6rem 0.8rem;
      border-radius: 12px;
      background: #fff1ec;
      border: 1px solid #f2c7b7;
      color: #8a3a26;
      font-size: 0.9rem;
    }}

    @media (max-width: 720px) {{
      .top-bar {{ flex-direction: column; align-items: flex-start; }}
      .status {{ width: 100%; justify-content: space-between; }}
      .config-form {{ flex-direction: column; align-items: flex-start; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    {}
    <footer class="site-footer">{}</footer>
  </div>
  <script>
    (() => {{
      document.querySelectorAll('[data-dialog]').forEach((button) => {{
        button.addEventListener('click', () => {{
          const dialog = document.getElementById(button.dataset.dialog);
          if (!dialog) {{
            return;
          }}
          if (typeof dialog.showModal === 'function') {{
            dialog.showModal();
          }} else {{
            dialog.setAttribute('open', 'open');
          }}
        }});
      }});

      document.querySelectorAll('[data-close]').forEach((button) => {{
        button.addEventListener('click', () => {{
          const dialog = button.closest('dialog');
          if (dialog) {{
            dialog.close();
          }}
        }});
      }});

      document.querySelectorAll('dialog.edit-dialog').forEach((dialog) => {{
        dialog.addEventListener('click', (event) => {{
          if (event.target === dialog) {{
            dialog.close();
          }}
        }});
      }});

      document.querySelectorAll('form[data-confirm]').forEach((form) => {{
        form.addEventListener('submit', (event) => {{
          const message = form.dataset.confirm || 'Bist du sicher?';
          if (!confirm(message)) {{
            event.preventDefault();
          }}
        }});
      }});

      const versionSelect = document.getElementById('metrics-version');
      const currentVersion = document.getElementById('metrics-version-current');
      const metricsEnabled = document.getElementById('metrics-enabled');
      const metricsGroups = Array.from(document.querySelectorAll('.metrics-group'));
      const metricsWarnings = Array.from(document.querySelectorAll('.metrics-warning'));
      const updateMetricsGroups = (value) => {{
        metricsGroups.forEach((group) => {{
          const isMatch = group.dataset.version === value;
          group.style.display = isMatch ? 'grid' : 'none';
          group.querySelectorAll('input, select, textarea').forEach((field) => {{
            field.disabled = !isMatch;
          }});
        }});
      }};
      const updateMetricsWarnings = (value) => {{
        const enabled = metricsEnabled ? metricsEnabled.checked : true;
        const v2Url = document.querySelector('input[name="url"]');
        const v1Url = document.querySelector('input[name="v1_url"]');
        const v1Db = document.querySelector('input[name="v1_db"]');
        metricsWarnings.forEach((warning) => {{
          const isMatch = warning.dataset.version === value;
          let show = enabled && isMatch;
          if (show && value === 'v2') {{
            show = v2Url && v2Url.value.trim() === '';
          }}
          if (show && value === 'v1') {{
            const missingUrl = !v1Url || v1Url.value.trim() === '';
            const missingDb = !v1Db || v1Db.value.trim() === '';
            show = missingUrl || missingDb;
          }}
          warning.style.display = show ? 'block' : 'none';
        }});
      }};
      if (versionSelect) {{
        const value = versionSelect.value || (currentVersion ? currentVersion.value : 'v2');
        updateMetricsGroups(value);
        updateMetricsWarnings(value);
        versionSelect.addEventListener('change', () => {{
          updateMetricsGroups(versionSelect.value);
          updateMetricsWarnings(versionSelect.value);
        }});
      }}
      if (metricsEnabled) {{
        metricsEnabled.addEventListener('change', () => {{
          if (versionSelect) {{
            updateMetricsWarnings(versionSelect.value);
          }}
        }});
      }}
      ['url', 'v1_url', 'v1_db'].forEach((name) => {{
        const field = document.querySelector('input[name="' + name + '"]');
        if (!field) {{
          return;
        }}
        field.addEventListener('input', () => {{
          if (versionSelect) {{
            updateMetricsWarnings(versionSelect.value);
          }}
        }});
      }});

      const searchForm = document.querySelector('.search-form');
      const searchInput = document.getElementById('search-input');
      const searchScope = document.getElementById('search-scope');
      const searchReset = document.getElementById('search-reset');
      const searchItems = Array.from(document.querySelectorAll('[data-search]'));
      const searchableNodes = Array.from(document.querySelectorAll('[data-search-text]'));
      const escapeHtml = (value) => value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\"/g, '&quot;')
        .replace(/'/g, '&#x27;');
      const highlightAll = (value) => {{
        const query = value.trim().toLowerCase();
        searchableNodes.forEach((node) => {{
          const original = node.dataset.searchOriginal || node.textContent || '';
          if (!node.dataset.searchOriginal) {{
            node.dataset.searchOriginal = original;
          }}
          if (!query) {{
            node.textContent = original;
            return;
          }}
          const lower = original.toLowerCase();
          if (!lower.includes(query)) {{
            node.textContent = original;
            return;
          }}
          let out = '';
          let idx = 0;
          while (true) {{
            const next = lower.indexOf(query, idx);
            if (next === -1) {{
              out += escapeHtml(original.slice(idx));
              break;
            }}
            out += escapeHtml(original.slice(idx, next));
            out += '<mark>' + escapeHtml(original.slice(next, next + query.length)) + '</mark>';
            idx = next + query.length;
          }}
          node.innerHTML = out;
        }});
      }};
      const applyFilter = (value) => {{
        const query = value.trim().toLowerCase();
        searchItems.forEach((item) => {{
          const haystack = (item.dataset.search || '').toLowerCase();
          item.style.display = !query || haystack.includes(query) ? '' : 'none';
        }});
        highlightAll(value);
      }};
      const updateUrl = (value) => {{
        const url = new URL(window.location.href);
        if (value.trim()) {{
          url.searchParams.set('q', value);
        }} else {{
          url.searchParams.delete('q');
        }}
        window.history.replaceState(null, '', url.toString());
      }};
      if (searchForm && searchInput) {{
        const scope = searchForm.dataset.scope || 'active';
        const run = () => {{
          const value = searchInput.value || '';
          const targetScope = searchScope ? searchScope.value : scope;
          if (targetScope !== scope) {{
            const base = targetScope === 'archive' ? '/archive' : '/';
            const url = new URL(base, window.location.origin);
            if (value.trim()) {{
              url.searchParams.set('q', value.trim());
            }}
            window.location.href = url.toString();
            return;
          }}
          applyFilter(value);
          updateUrl(value);
        }};
        searchInput.addEventListener('input', () => {{
          run();
        }});
        searchForm.addEventListener('submit', (event) => {{
          event.preventDefault();
          run();
        }});
        if (searchScope) {{
          searchScope.addEventListener('change', () => {{
            run();
          }});
        }}
        if (searchReset) {{
          searchReset.addEventListener('click', () => {{
            searchInput.value = '';
            run();
            searchInput.focus();
          }});
        }}
        applyFilter(searchInput.value || '');
      }}
    }})();
  </script>
</body>
</html>"#,
        escape_html(title),
        body,
        escape_html(footer_text)
    )
}

fn todo_anchor(todo_id: i64) -> String {
    format!("/#todo-{}", todo_id)
}

fn archive_anchor() -> &'static str {
    "/archive"
}

fn normalize_currency_code(value: &str) -> &str {
    match value {
        "EUR" | "USD" | "CHF" | "GBP" | "CUSTOM" => value,
        _ => "EUR",
    }
}

fn normalize_title(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "BlueTodo Dashboard".to_string()
    } else {
        trimmed.to_string()
    }
}

fn resolve_currency_label(code: &str, custom: &str) -> String {
    let label = match code {
        "EUR" => "€",
        "USD" => "$",
        "CHF" => "CHF",
        "GBP" => "£",
        "CUSTOM" => custom.trim(),
        _ => "€",
    };
    if label.is_empty() {
        "€".to_string()
    } else {
        label.to_string()
    }
}

fn currency_label_hint(currency_label: &str) -> String {
    let label = currency_label.trim();
    if label.is_empty() {
        String::new()
    } else {
        format!(" ({})", escape_html(label))
    }
}

fn format_currency_value(amount: &str, currency_label: &str) -> String {
    let label = currency_label.trim();
    if label.is_empty() {
        amount.to_string()
    } else {
        format!("{} {}", amount, escape_html(label))
    }
}

fn build_footer_text(title: &str, app_version: &str) -> String {
    let base = title.trim();
    let label = if base.is_empty() { "BlueTodo" } else { base };
    let year = Utc::now().year();
    format!("{} · v{} · {}", label, app_version, year)
}

fn format_bytes(bytes: i64) -> String {
    let size = bytes.max(0) as f64;
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = size;
    let mut index = 0;
    while value >= 1024.0 && index < units.len() - 1 {
        value /= 1024.0;
        index += 1;
    }
    if index == 0 {
        format!("{} {}", value as i64, units[index])
    } else {
        format!("{:.1} {}", value, units[index])
    }
}

fn format_archived_at(value: &Option<String>) -> String {
    match value.as_deref() {
        Some(raw) => NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
            .map(|dt| dt.format("%d.%m.%Y %H:%M").to_string())
            .unwrap_or_else(|_| raw.to_string()),
        None => "—".to_string(),
    }
}

async fn run_proto_server(state: AppState, config: ProtoConfig) -> Result<(), String> {
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| err.to_string())?;
    println!("Proto-Server aktiv auf tcp://{addr}");

    loop {
        let (stream, _) = listener.accept().await.map_err(|err| err.to_string())?;
        let state = state.clone();
        let token = config.token.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_proto_client(stream, state, token).await {
                eprintln!("Proto-Client Fehler: {err}");
            }
        });
    }
}

async fn handle_proto_client(
    stream: TcpStream,
    state: AppState,
    token: String,
) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut authed = token.is_empty();
    let mut client_label = "legacy".to_string();
    state.metrics.proto_connect(&client_label).await;

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .await
            .map_err(|err| err.to_string())?;
        if bytes == 0 {
            break;
        }

        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            continue;
        }

        let response_lines = match parse_proto_line(trimmed) {
            Ok(request) => {
                let mut request = request;
                if !authed && !token.is_empty() {
                    if let Some(candidate) = request.params.get("token") {
                        if candidate == &token {
                            authed = true;
                        }
                    }
                }

                if request.command == "AUTH" {
                    if let Some(label) = request.params.get("client") {
                        let trimmed = label.trim();
                        if !trimmed.is_empty() {
                            state
                                .metrics
                                .proto_update_label(&client_label, trimmed)
                                .await;
                            client_label = trimmed.to_string();
                        }
                    }
                    if token.is_empty() {
                        vec![build_ok_line(&request.seq, "")]
                    } else if request.params.get("token") == Some(&token) {
                        authed = true;
                        vec![build_ok_line(&request.seq, "")]
                    } else {
                        vec![build_err_line(&request.seq, "AUTH", "InvalidToken")]
                    }
                } else if !authed && request.command != "HELLO" {
                    vec![build_err_line(&request.seq, "AUTH", "AuthRequired")]
                } else {
                    if request.command != "HELLO" && request.command != "AUTH" {
                        state
                            .metrics
                            .proto_request(&client_label, &request.command)
                            .await;
                    }
                    match handle_proto_command(&mut request, &state).await {
                        Ok(lines) => lines,
                        Err(err) => vec![build_err_line(&request.seq, err.code, &err.message)],
                    }
                }
            }
            Err(err) => vec![build_err_line(&err.seq, err.code, &err.message)],
        };

        for response in response_lines {
            writer
                .write_all(response.as_bytes())
                .await
                .map_err(|err| err.to_string())?;
            writer
                .write_all(b"\r\n")
                .await
                .map_err(|err| err.to_string())?;
        }
    }

    state.metrics.proto_disconnect(&client_label).await;
    Ok(())
}

struct ProtoRequest {
    command: String,
    params: std::collections::HashMap<String, String>,
    seq: String,
}

struct ProtoParseError {
    code: &'static str,
    message: String,
    seq: String,
}

struct ProtoCommandError {
    code: &'static str,
    message: String,
}

struct ClientUpdateArtifact {
    target: &'static str,
    artifact: &'static str,
    file_name: &'static str,
    path: PathBuf,
}

fn proto_validation_error(message: String) -> ProtoCommandError {
    ProtoCommandError {
        code: "VALIDATION",
        message,
    }
}

fn proto_internal_error(err: impl std::fmt::Display) -> ProtoCommandError {
    ProtoCommandError {
        code: "INTERNAL",
        message: err.to_string(),
    }
}

fn parse_proto_line(line: &str) -> Result<ProtoRequest, ProtoParseError> {
    let (base, crc) = split_crc(line).ok_or_else(|| ProtoParseError {
        code: "VALIDATION",
        message: "MissingCRC".to_string(),
        seq: "0".to_string(),
    })?;

    let seq = extract_seq(&base).unwrap_or_else(|| "0".to_string());
    let expected = crc32_hex(base.as_bytes());
    if !expected.eq_ignore_ascii_case(&crc) {
        return Err(ProtoParseError {
            code: "CRC",
            message: "BadCRC".to_string(),
            seq,
        });
    }

    let mut parts = base.split_whitespace();
    let command = parts
        .next()
        .ok_or_else(|| ProtoParseError {
            code: "VALIDATION",
            message: "MissingCommand".to_string(),
            seq: "0".to_string(),
        })?
        .to_string();

    let mut params = std::collections::HashMap::new();
    for part in parts {
        let (key, value) = part.split_once('=').ok_or_else(|| ProtoParseError {
            code: "VALIDATION",
            message: "BadParam".to_string(),
            seq: seq.clone(),
        })?;
        let decoded = decode_value(value).map_err(|message| ProtoParseError {
            code: "VALIDATION",
            message,
            seq: seq.clone(),
        })?;
        params.insert(key.to_string(), decoded);
    }

    let seq = params.remove("seq").ok_or_else(|| ProtoParseError {
        code: "VALIDATION",
        message: "MissingSeq".to_string(),
        seq: "0".to_string(),
    })?;

    Ok(ProtoRequest {
        command,
        params,
        seq,
    })
}

fn split_crc(line: &str) -> Option<(String, String)> {
    let marker = " crc32=";
    let idx = line.rfind(marker)?;
    let base = line[..idx].to_string();
    let crc = line[idx + marker.len()..].trim().to_string();
    if crc.is_empty() {
        None
    } else {
        Some((base, crc))
    }
}

fn extract_seq(base: &str) -> Option<String> {
    for part in base.split_whitespace() {
        if let Some(value) = part.strip_prefix("seq=") {
            return Some(value.to_string());
        }
    }
    None
}

fn build_ok_line(seq: &str, extra: &str) -> String {
    let mut base = String::from("OK");
    if !extra.is_empty() {
        base.push(' ');
        base.push_str(extra);
    }
    base.push_str(" seq=");
    base.push_str(seq);
    build_proto_line(&base)
}

fn build_err_line(seq: &str, code: &str, message: &str) -> String {
    let base = format!(
        "ERR code={} msg={} seq={}",
        code,
        encode_value(message),
        seq
    );
    build_proto_line(&base)
}

fn build_proto_line(base: &str) -> String {
    let crc = crc32_hex(base.as_bytes());
    format!("{} crc32={}", base, crc)
}

async fn handle_proto_command(
    request: &mut ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    match request.command.as_str() {
        "HELLO" => Ok(vec![build_ok_line(
            &request.seq,
            &format!(
                "version={} schema={} proto={}",
                APP_VERSION, SCHEMA_VERSION, PROTO_VERSION
            ),
        )]),
        "LIST_TODOS" => proto_list_todos(request, state).await,
        "LIST_ARCHIVED" => proto_list_archived_todos(request, state).await,
        "GET_TODO" => proto_get_todo(request, state).await,
        "ADD_TODO" => proto_add_todo(request, state).await,
        "UPDATE_TODO" => proto_update_todo(request, state).await,
        "DELETE_TODO" => proto_delete_todo(request, state).await,
        "ARCHIVE_TODO" => proto_archive_todo(request, state).await,
        "UNARCHIVE_TODO" => proto_unarchive_todo(request, state).await,
        "LIST_TASKS" => proto_list_tasks(request, state).await,
        "ADD_TASK" => proto_add_task(request, state).await,
        "UPDATE_TASK" => proto_update_task(request, state).await,
        "TOGGLE_TASK" => proto_toggle_task(request, state).await,
        "GET_CLIENT_UPDATE_INFO" => proto_get_client_update_info(request).await,
        "DOWNLOAD_CLIENT_UPDATE" => proto_download_client_update(request).await,
        _ => Ok(vec![build_err_line(
            &request.seq,
            "VALIDATION",
            "UnknownCommand",
        )]),
    }
}

fn default_win16_client_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bluetodo-win16")
}

fn default_nt4ppc_client_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bluetodo-nt4ppc")
}

fn first_update_env_path(names: &[&str]) -> Option<PathBuf> {
    for name in names {
        if let Some(value) = env::var_os(name) {
            return Some(PathBuf::from(value));
        }
    }
    None
}

fn normalize_update_target(target: &str) -> Option<&'static str> {
    match target {
        WIN16_UPDATE_TARGET => Some(WIN16_UPDATE_TARGET),
        NTPPC_UPDATE_TARGET_LEGACY | NT4PPC_UPDATE_TARGET => Some(NT4PPC_UPDATE_TARGET),
        _ => None,
    }
}

fn resolve_client_update_artifact(
    request: &ProtoRequest,
) -> Result<ClientUpdateArtifact, ProtoCommandError> {
    let target = request
        .params
        .get("target")
        .map(String::as_str)
        .unwrap_or(WIN16_UPDATE_TARGET);
    let artifact = request
        .params
        .get("artifact")
        .map(String::as_str)
        .unwrap_or(CLIENT_UPDATE_ARTIFACT_CLIENT);

    let normalized_target = normalize_update_target(target)
        .ok_or_else(|| proto_validation_error("UnsupportedUpdateTarget".to_string()))?;

    let resolved = match (normalized_target, artifact) {
        (WIN16_UPDATE_TARGET, CLIENT_UPDATE_ARTIFACT_CLIENT) => {
            let win16_dir = default_win16_client_dir();
            ClientUpdateArtifact {
                target: WIN16_UPDATE_TARGET,
                artifact: CLIENT_UPDATE_ARTIFACT_CLIENT,
                file_name: "BLUETODO.EXE",
                path: first_update_env_path(&["BLUETODO_WIN16_UPDATE_EXE"])
                    .unwrap_or_else(|| win16_dir.join("bluetodo-win16.exe")),
            }
        }
        (WIN16_UPDATE_TARGET, CLIENT_UPDATE_ARTIFACT_UPDATER) => {
            let win16_dir = default_win16_client_dir();
            ClientUpdateArtifact {
                target: WIN16_UPDATE_TARGET,
                artifact: CLIENT_UPDATE_ARTIFACT_UPDATER,
                file_name: "BTUPDT16.EXE",
                path: first_update_env_path(&["BLUETODO_WIN16_UPDATER_EXE"])
                    .unwrap_or_else(|| win16_dir.join("btupdt16.exe")),
            }
        }
        (NT4PPC_UPDATE_TARGET, CLIENT_UPDATE_ARTIFACT_CLIENT) => {
            let nt4ppc_dir = default_nt4ppc_client_dir();
            ClientUpdateArtifact {
                target: NT4PPC_UPDATE_TARGET,
                artifact: CLIENT_UPDATE_ARTIFACT_CLIENT,
                file_name: "bluetodo-nt4ppc.exe",
                path: first_update_env_path(&[
                    "BLUETODO_NT4PPC_UPDATE_EXE",
                    "BLUETODO_NTPPC_UPDATE_EXE",
                ])
                .unwrap_or_else(|| nt4ppc_dir.join("bluetodo-nt4ppc.exe")),
            }
        }
        (NT4PPC_UPDATE_TARGET, CLIENT_UPDATE_ARTIFACT_UPDATER) => {
            let nt4ppc_dir = default_nt4ppc_client_dir();
            ClientUpdateArtifact {
                target: NT4PPC_UPDATE_TARGET,
                artifact: CLIENT_UPDATE_ARTIFACT_UPDATER,
                file_name: "btupdt32-nt4ppc.exe",
                path: first_update_env_path(&[
                    "BLUETODO_NT4PPC_UPDATER_EXE",
                    "BLUETODO_NTPPC_UPDATER_EXE",
                ])
                .unwrap_or_else(|| nt4ppc_dir.join("btupdt32-nt4ppc.exe")),
            }
        }
        _ => {
            return Err(proto_validation_error(
                "UnsupportedUpdateArtifact".to_string(),
            ));
        }
    };

    if !resolved.path.is_file() {
        return Err(proto_internal_error(format!(
            "Update artifact missing: {}",
            resolved.path.display()
        )));
    }

    Ok(resolved)
}

fn push_update_header_line(
    lines: &mut Vec<String>,
    seq: &str,
    artifact: &ClientUpdateArtifact,
    bytes: &[u8],
) {
    lines.push(build_ok_line(
        seq,
        &format!(
            "target={} artifact={} version={} name={} size={} file_crc32={}",
            artifact.target,
            artifact.artifact,
            APP_VERSION,
            artifact.file_name,
            bytes.len(),
            crc32_hex(bytes)
        ),
    ));
}

fn encode_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut text = String::with_capacity(data.len() * 2);
    for &byte in data {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0F) as usize] as char);
    }
    text
}

async fn proto_get_client_update_info(
    request: &ProtoRequest,
) -> Result<Vec<String>, ProtoCommandError> {
    let artifact = resolve_client_update_artifact(request)?;
    let bytes = fs::read(&artifact.path).map_err(proto_internal_error)?;
    let mut lines = Vec::new();
    push_update_header_line(&mut lines, &request.seq, &artifact, &bytes);
    Ok(lines)
}

async fn proto_download_client_update(
    request: &ProtoRequest,
) -> Result<Vec<String>, ProtoCommandError> {
    let artifact = resolve_client_update_artifact(request)?;
    let bytes = fs::read(&artifact.path).map_err(proto_internal_error)?;
    let mut lines = Vec::new();

    push_update_header_line(&mut lines, &request.seq, &artifact, &bytes);

    for (offset, chunk) in bytes.chunks(CLIENT_UPDATE_CHUNK_SIZE).enumerate() {
        lines.push(build_proto_line(&format!(
            "DATA offset={} size={} hex={} seq={}",
            offset * CLIENT_UPDATE_CHUNK_SIZE,
            chunk.len(),
            encode_hex(chunk),
            request.seq
        )));
    }

    lines.push(build_proto_line(&format!(
        "END size={} file_crc32={} seq={}",
        bytes.len(),
        crc32_hex(&bytes),
        request.seq
    )));

    Ok(lines)
}

async fn proto_list_todos(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let rows = sqlx::query(
        "SELECT id, title, description, order_number, purchaser, order_date, budget_spent, budget_planned, deadline FROM todos WHERE archived_at IS NULL ORDER BY id DESC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    let todo_ids = rows.iter().map(|row| row.get("id")).collect::<Vec<i64>>();
    let stats_by_todo = load_task_stats_for_todo_ids(&state.pool, &todo_ids)
        .await
        .map_err(proto_internal_error)?;

    let mut lines = Vec::new();
    lines.push(build_ok_line(
        &request.seq,
        &format!("count={}", rows.len()),
    ));

    for row in rows {
        let id: i64 = row.get("id");
        let title: String = row.get("title");
        let description: Option<String> = row.get("description");
        let order_number: Option<String> = row.get("order_number");
        let purchaser: Option<String> = row.get("purchaser");
        let order_date: Option<String> = row.get("order_date");
        let budget_spent: f64 = row.get("budget_spent");
        let budget_planned: f64 = row.get("budget_planned");
        let deadline: Option<String> = row.get("deadline");
        let (total, done) = stats_by_todo.get(&id).copied().unwrap_or((0, 0));
        let progress = if total == 0 {
            0.0
        } else {
            (done as f64 / total as f64) * 100.0
        };

        let deadline_value = deadline.unwrap_or_default();
        let description_value = description.unwrap_or_default();
        let order_number_value = order_number.unwrap_or_default();
        let purchaser_value = purchaser.unwrap_or_default();
        let order_date_value = order_date.unwrap_or_default();
        let line = format!(
            "TODO id={} title={} desc={} order_number={} purchaser={} order_date={} progress={:.0} budget_spent={:.2} budget_planned={:.2} deadline={} seq={}",
            id,
            encode_value(&title),
            encode_value(&description_value),
            encode_value(&order_number_value),
            encode_value(&purchaser_value),
            encode_value(&order_date_value),
            progress,
            budget_spent,
            budget_planned,
            encode_value(&deadline_value),
            request.seq
        );
        lines.push(build_proto_line(&line));
    }

    lines.push(build_proto_line(&format!("END seq={}", request.seq)));
    Ok(lines)
}

async fn proto_list_archived_todos(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let rows = sqlx::query(
        "SELECT id, title, description, order_number, purchaser, order_date, budget_spent, budget_planned, deadline, archived_at FROM todos WHERE archived_at IS NOT NULL ORDER BY archived_at DESC, id DESC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    let todo_ids = rows.iter().map(|row| row.get("id")).collect::<Vec<i64>>();
    let stats_by_todo = load_task_stats_for_todo_ids(&state.pool, &todo_ids)
        .await
        .map_err(proto_internal_error)?;

    let mut lines = Vec::new();
    lines.push(build_ok_line(
        &request.seq,
        &format!("count={}", rows.len()),
    ));

    for row in rows {
        let id: i64 = row.get("id");
        let title: String = row.get("title");
        let description: Option<String> = row.get("description");
        let order_number: Option<String> = row.get("order_number");
        let purchaser: Option<String> = row.get("purchaser");
        let order_date: Option<String> = row.get("order_date");
        let budget_spent: f64 = row.get("budget_spent");
        let budget_planned: f64 = row.get("budget_planned");
        let deadline: Option<String> = row.get("deadline");
        let archived_at: Option<String> = row.get("archived_at");
        let (total, done) = stats_by_todo.get(&id).copied().unwrap_or((0, 0));
        let progress = if total == 0 {
            0.0
        } else {
            (done as f64 / total as f64) * 100.0
        };

        let deadline_value = deadline.unwrap_or_default();
        let description_value = description.unwrap_or_default();
        let archived_value = archived_at.unwrap_or_default();
        let order_number_value = order_number.unwrap_or_default();
        let purchaser_value = purchaser.unwrap_or_default();
        let order_date_value = order_date.unwrap_or_default();
        let line = format!(
            "TODO id={} title={} desc={} order_number={} purchaser={} order_date={} progress={:.0} budget_spent={:.2} budget_planned={:.2} deadline={} archived_at={} seq={}",
            id,
            encode_value(&title),
            encode_value(&description_value),
            encode_value(&order_number_value),
            encode_value(&purchaser_value),
            encode_value(&order_date_value),
            progress,
            budget_spent,
            budget_planned,
            encode_value(&deadline_value),
            encode_value(&archived_value),
            request.seq
        );
        lines.push(build_proto_line(&line));
    }

    lines.push(build_proto_line(&format!("END seq={}", request.seq)));
    Ok(lines)
}

async fn proto_get_todo(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let id = get_i64_param(request, "id").map_err(proto_validation_error)?;
    let row = sqlx::query(
        "SELECT id, title, description, order_number, purchaser, order_date, budget_spent, budget_planned, deadline, archived_at FROM todos WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    let row = match row {
        Some(row) => row,
        None => {
            return Ok(vec![build_err_line(
                &request.seq,
                "NOTFOUND",
                "TodoMissing",
            )]);
        }
    };

    let title: String = row.get("title");
    let description: Option<String> = row.get("description");
    let order_number: Option<String> = row.get("order_number");
    let purchaser: Option<String> = row.get("purchaser");
    let order_date: Option<String> = row.get("order_date");
    let budget_spent: f64 = row.get("budget_spent");
    let budget_planned: f64 = row.get("budget_planned");
    let deadline: Option<String> = row.get("deadline");
    let archived_at: Option<String> = row.get("archived_at");
    let line = format!(
        "OK id={} title={} desc={} order_number={} purchaser={} order_date={} budget_spent={:.2} budget_planned={:.2} deadline={} archived_at={} seq={}",
        id,
        encode_value(&title),
        encode_value(description.as_deref().unwrap_or("")),
        encode_value(order_number.as_deref().unwrap_or("")),
        encode_value(purchaser.as_deref().unwrap_or("")),
        encode_value(order_date.as_deref().unwrap_or("")),
        budget_spent,
        budget_planned,
        encode_value(deadline.as_deref().unwrap_or("")),
        encode_value(archived_at.as_deref().unwrap_or("")),
        request.seq
    );
    Ok(vec![build_proto_line(&line)])
}

async fn proto_add_todo(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let title = get_param(request, "title").map_err(proto_validation_error)?;
    let description = normalize_optional_string(request.params.get("desc").map(String::as_str));
    let order_number =
        normalize_optional_string(request.params.get("order_number").map(String::as_str));
    let purchaser = normalize_optional_string(request.params.get("purchaser").map(String::as_str));
    let order_date = normalize_optional_date(request.params.get("order_date").map(String::as_str));
    let has_order_metadata = order_number.is_some() || purchaser.is_some() || order_date.is_some();
    let budget_spent =
        get_f64_param_optional(request, "budget_spent").map_err(proto_validation_error)?;
    let budget_planned =
        get_f64_param_optional(request, "budget_planned").map_err(proto_validation_error)?;
    let deadline = request.params.get("deadline").cloned().unwrap_or_default();
    let deadline = normalize_optional_date(Some(&deadline));
    let budget_manual = if has_order_metadata { 0 } else { 1 };

    if has_order_metadata {
        if order_number.is_none() {
            return Err(ProtoCommandError {
                code: "VALIDATION",
                message: "Missing order_number".to_string(),
            });
        }
        if purchaser.is_none() {
            return Err(ProtoCommandError {
                code: "VALIDATION",
                message: "Missing purchaser".to_string(),
            });
        }
        if order_date.is_none() {
            return Err(ProtoCommandError {
                code: "VALIDATION",
                message: "Bad order_date".to_string(),
            });
        }
    }

    let result = sqlx::query(
        r#"
        INSERT INTO todos (title, description, order_number, purchaser, order_date, budget_spent, budget_planned, budget_manual, deadline)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(title)
    .bind(description)
    .bind(order_number)
    .bind(purchaser)
    .bind(order_date)
    .bind(budget_spent)
    .bind(budget_planned)
    .bind(budget_manual)
    .bind(deadline)
    .execute(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    Ok(vec![build_ok_line(
        &request.seq,
        &format!("id={}", result.last_insert_rowid()),
    )])
}

async fn proto_update_todo(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let id = get_i64_param(request, "id").map_err(proto_validation_error)?;
    let active = match proto_load_todo_active(&state.pool, id).await? {
        Some(active) => active,
        None => {
            return Err(ProtoCommandError {
                code: "NOTFOUND",
                message: "TodoMissing".to_string(),
            });
        }
    };
    if !active {
        return Err(ProtoCommandError {
            code: "ARCHIVED",
            message: "TodoArchived".to_string(),
        });
    }
    let title = get_param(request, "title").map_err(proto_validation_error)?;
    let description = normalize_optional_string(request.params.get("desc").map(String::as_str));
    let order_number =
        normalize_optional_string(request.params.get("order_number").map(String::as_str));
    let purchaser = normalize_optional_string(request.params.get("purchaser").map(String::as_str));
    let order_date = normalize_optional_date(request.params.get("order_date").map(String::as_str));
    let has_order_metadata = order_number.is_some() || purchaser.is_some() || order_date.is_some();
    let budget_spent =
        get_f64_param_optional(request, "budget_spent").map_err(proto_validation_error)?;
    let budget_planned =
        get_f64_param_optional(request, "budget_planned").map_err(proto_validation_error)?;
    let deadline = request.params.get("deadline").cloned().unwrap_or_default();
    let deadline = normalize_optional_date(Some(&deadline));
    let budget_manual = if has_order_metadata { 0 } else { 1 };

    if has_order_metadata {
        if order_number.is_none() {
            return Err(ProtoCommandError {
                code: "VALIDATION",
                message: "Missing order_number".to_string(),
            });
        }
        if purchaser.is_none() {
            return Err(ProtoCommandError {
                code: "VALIDATION",
                message: "Missing purchaser".to_string(),
            });
        }
        if order_date.is_none() {
            return Err(ProtoCommandError {
                code: "VALIDATION",
                message: "Bad order_date".to_string(),
            });
        }
    }

    sqlx::query(
        r#"
        UPDATE todos
        SET title = ?, description = ?, order_number = ?, purchaser = ?, order_date = ?, budget_spent = ?, budget_planned = ?, budget_manual = ?, deadline = ?
        WHERE id = ?
        "#,
    )
    .bind(title)
    .bind(description)
    .bind(order_number)
    .bind(purchaser)
    .bind(order_date)
    .bind(budget_spent)
    .bind(budget_planned)
    .bind(budget_manual)
    .bind(deadline)
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    Ok(vec![build_ok_line(&request.seq, "")])
}

async fn proto_delete_todo(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let id = get_i64_param(request, "id").map_err(proto_validation_error)?;
    if request.params.get("confirm") != Some(&"1".to_string()) {
        return Ok(vec![build_err_line(
            &request.seq,
            "VALIDATION",
            "ConfirmRequired",
        )]);
    }

    sqlx::query("DELETE FROM todos WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(proto_internal_error)?;

    Ok(vec![build_ok_line(&request.seq, "")])
}

async fn proto_archive_todo(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let id = get_i64_param(request, "id").map_err(proto_validation_error)?;
    let active = match proto_load_todo_active(&state.pool, id).await? {
        Some(active) => active,
        None => {
            return Err(ProtoCommandError {
                code: "NOTFOUND",
                message: "TodoMissing".to_string(),
            });
        }
    };
    if !active {
        return Ok(vec![build_ok_line(&request.seq, "")]);
    }
    let complete = proto_todo_is_complete(&state.pool, id).await?;
    if !complete {
        return Err(ProtoCommandError {
            code: "VALIDATION",
            message: "TodoNotDone".to_string(),
        });
    }

    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    sqlx::query("UPDATE todos SET archived_at = ? WHERE id = ? AND archived_at IS NULL")
        .bind(timestamp)
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(proto_internal_error)?;

    Ok(vec![build_ok_line(&request.seq, "")])
}

async fn proto_unarchive_todo(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let id = get_i64_param(request, "id").map_err(proto_validation_error)?;
    let result = sqlx::query("UPDATE todos SET archived_at = NULL WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(proto_internal_error)?;

    if result.rows_affected() == 0 {
        return Err(ProtoCommandError {
            code: "NOTFOUND",
            message: "TodoMissing".to_string(),
        });
    }

    Ok(vec![build_ok_line(&request.seq, "")])
}

async fn proto_list_tasks(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let todo_id = get_i64_param(request, "todo_id").map_err(proto_validation_error)?;
    let rows = sqlx::query(
        "SELECT id, todo_id, title, description, amount, done FROM tasks WHERE todo_id = ? ORDER BY id",
    )
    .bind(todo_id)
    .fetch_all(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    let mut lines = Vec::new();
    lines.push(build_ok_line(
        &request.seq,
        &format!("count={}", rows.len()),
    ));

    for row in rows {
        let id: i64 = row.get("id");
        let title: String = row.get("title");
        let description: Option<String> = row.get("description");
        let amount: f64 = row.get("amount");
        let done: i64 = row.get("done");
        let line = format!(
            "TASK id={} todo_id={} title={} desc={} amount={:.2} done={} seq={}",
            id,
            todo_id,
            encode_value(&title),
            encode_value(description.as_deref().unwrap_or("")),
            amount,
            done,
            request.seq
        );
        lines.push(build_proto_line(&line));
    }

    lines.push(build_proto_line(&format!("END seq={}", request.seq)));
    Ok(lines)
}

async fn proto_add_task(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let todo_id = get_i64_param(request, "todo_id").map_err(proto_validation_error)?;
    let active = match proto_load_todo_active(&state.pool, todo_id).await? {
        Some(active) => active,
        None => {
            return Err(ProtoCommandError {
                code: "NOTFOUND",
                message: "TodoMissing".to_string(),
            });
        }
    };
    if !active {
        return Err(ProtoCommandError {
            code: "ARCHIVED",
            message: "TodoArchived".to_string(),
        });
    }
    let title = get_param(request, "title").map_err(proto_validation_error)?;
    let description = normalize_optional_string(request.params.get("desc").map(String::as_str));
    let amount = get_f64_param_optional(request, "amount").map_err(proto_validation_error)?;

    let result = sqlx::query(
        "INSERT INTO tasks (todo_id, title, description, amount, done) VALUES (?, ?, ?, ?, 0)",
    )
    .bind(todo_id)
    .bind(title)
    .bind(description)
    .bind(amount)
    .execute(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    recalculate_todo_spent(&state.pool, todo_id)
        .await
        .map_err(proto_internal_error)?;

    Ok(vec![build_ok_line(
        &request.seq,
        &format!("id={}", result.last_insert_rowid()),
    )])
}

async fn proto_update_task(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let id = get_i64_param(request, "id").map_err(proto_validation_error)?;
    let (todo_id, active) = match proto_load_task_active(&state.pool, id).await? {
        Some(value) => value,
        None => {
            return Err(ProtoCommandError {
                code: "NOTFOUND",
                message: "TaskMissing".to_string(),
            });
        }
    };
    if !active {
        return Err(ProtoCommandError {
            code: "ARCHIVED",
            message: "TodoArchived".to_string(),
        });
    }
    let title = get_param(request, "title").map_err(proto_validation_error)?;
    let description = normalize_optional_string(request.params.get("desc").map(String::as_str));
    let amount = get_f64_param_optional(request, "amount").map_err(proto_validation_error)?;

    sqlx::query("UPDATE tasks SET title = ?, description = ?, amount = ? WHERE id = ?")
        .bind(title)
        .bind(description)
        .bind(amount)
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(proto_internal_error)?;

    recalculate_todo_spent(&state.pool, todo_id)
        .await
        .map_err(proto_internal_error)?;

    Ok(vec![build_ok_line(&request.seq, "")])
}

async fn proto_toggle_task(
    request: &ProtoRequest,
    state: &AppState,
) -> Result<Vec<String>, ProtoCommandError> {
    let id = get_i64_param(request, "id").map_err(proto_validation_error)?;
    let (_todo_id, active) = match proto_load_task_active(&state.pool, id).await? {
        Some(value) => value,
        None => {
            return Err(ProtoCommandError {
                code: "NOTFOUND",
                message: "TaskMissing".to_string(),
            });
        }
    };
    if !active {
        return Err(ProtoCommandError {
            code: "ARCHIVED",
            message: "TodoArchived".to_string(),
        });
    }

    sqlx::query(
        r#"
        UPDATE tasks
        SET done = CASE done WHEN 1 THEN 0 ELSE 1 END
        WHERE id = ?
        "#,
    )
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(proto_internal_error)?;

    let row = sqlx::query("SELECT done FROM tasks WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(proto_internal_error)?;
    let done = row.map(|row| row.get::<i64, _>("done")).unwrap_or(0);

    Ok(vec![build_ok_line(&request.seq, &format!("done={}", done))])
}

async fn run_metrics_loop(state: AppState) {
    loop {
        let config = match load_metrics_config(&state.pool).await {
            Ok(config) => config,
            Err((_status, message)) => {
                eprintln!("Metrics config Fehler: {message}");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let interval = config.interval_seconds.max(5);
        if !config.enabled {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            continue;
        }
        let ready = match config.version.as_str() {
            "v1" => !config.v1_url.trim().is_empty() && !config.v1_db.trim().is_empty(),
            _ => !config.url.trim().is_empty(),
        };
        if !ready {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            continue;
        }

        if let Err(err) = emit_metrics(&state, &config).await {
            eprintln!("Metrics Fehler: {err}");
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

async fn emit_metrics(state: &AppState, config: &MetricsConfig) -> Result<(), String> {
    if config.version == "v1" && config.v1_autocreate {
        ensure_influx_v1_db_exists(&state.metrics, config).await?;
    }
    let snapshot = collect_db_metrics(&state.pool)
        .await
        .map_err(|(_, msg)| msg)?;

    let instance = if !config.instance.trim().is_empty() {
        config.instance.clone()
    } else {
        env::var("HOSTNAME").unwrap_or_else(|_| "bluetodo".to_string())
    };
    let instance_tag = influx_escape_tag(&instance);

    let http_inflight = state.metrics.http_inflight.load(Ordering::Relaxed) as i64;
    let http_requests_total = state.metrics.http_requests_total.load(Ordering::Relaxed) as i64;
    let proto_connections = state.metrics.proto_connections.load(Ordering::Relaxed) as i64;
    let proto_requests_total = state.metrics.proto_requests_total.load(Ordering::Relaxed) as i64;
    let clients_connected = http_inflight + proto_connections;

    let mut payload = String::new();
    payload.push_str(&format!(
        "bluetodo,instance={} clients_connected={}i,http_inflight={}i,http_requests_total={}i,proto_connections={}i,proto_requests_total={}i\n",
        instance_tag,
        clients_connected,
        http_inflight,
        http_requests_total,
        proto_connections,
        proto_requests_total
    ));
    payload.push_str(&format!(
        "bluetodo_state,instance={} todos_active={}i,todos_archived={}i,todos_completed={}i,tasks_total={}i,tasks_done={}i,overdue_todos={}i,budget_planned_sum={},budget_spent_sum={},over_budget_count={}i\n",
        instance_tag,
        snapshot.todos_active,
        snapshot.todos_archived,
        snapshot.todos_completed,
        snapshot.tasks_total,
        snapshot.tasks_done,
        snapshot.overdue_todos,
        snapshot.budget_planned_sum,
        snapshot.budget_spent_sum,
        snapshot.over_budget_count
    ));

    let client_counts = state.metrics.client_request_counts.lock().await.clone();
    for (client, count) in client_counts {
        let client_tag = influx_escape_tag(&client);
        payload.push_str(&format!(
            "bluetodo_client_requests,instance={},client={} requests_total={}i\n",
            instance_tag, client_tag, count
        ));
    }

    let proto_connections = state.metrics.proto_client_connections.lock().await.clone();
    for (client, count) in proto_connections {
        let client_tag = influx_escape_tag(&client);
        payload.push_str(&format!(
            "bluetodo_proto_clients,instance={},client={} connections={}i\n",
            instance_tag, client_tag, count
        ));
    }

    let proto_commands = state.metrics.proto_command_counts.lock().await.clone();
    for (command, count) in proto_commands {
        let command_tag = influx_escape_tag(&command);
        payload.push_str(&format!(
            "bluetodo_proto_commands,instance={},command={} requests_total={}i\n",
            instance_tag, command_tag, count
        ));
    }

    send_metrics_payload(config, payload).await
}

struct DbMetricsSnapshot {
    todos_active: i64,
    todos_archived: i64,
    todos_completed: i64,
    tasks_total: i64,
    tasks_done: i64,
    overdue_todos: i64,
    budget_planned_sum: f64,
    budget_spent_sum: f64,
    over_budget_count: i64,
}

async fn collect_db_metrics(pool: &SqlitePool) -> AppResult<DbMetricsSnapshot> {
    let active_row = sqlx::query("SELECT COUNT(*) AS count FROM todos WHERE archived_at IS NULL")
        .fetch_one(pool)
        .await
        .map_err(internal_error)?;
    let todos_active: i64 = active_row.get(0);

    let archived_row =
        sqlx::query("SELECT COUNT(*) AS count FROM todos WHERE archived_at IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(internal_error)?;
    let todos_archived: i64 = archived_row.get(0);

    let completed_row = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM (
            SELECT t.id, COUNT(tasks.id) AS total, COALESCE(SUM(tasks.done), 0) AS done
            FROM todos t
            LEFT JOIN tasks ON tasks.todo_id = t.id
            WHERE t.archived_at IS NULL
            GROUP BY t.id
        )
        WHERE total > 0 AND total = done
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(internal_error)?;
    let todos_completed: i64 = completed_row.get(0);

    let tasks_row = sqlx::query(
        r#"
        SELECT COUNT(*) AS total, COALESCE(SUM(tasks.done), 0) AS done
        FROM tasks
        JOIN todos ON tasks.todo_id = todos.id
        WHERE todos.archived_at IS NULL
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(internal_error)?;
    let tasks_total: i64 = tasks_row.get("total");
    let tasks_done: i64 = tasks_row.get("done");

    let overdue_row = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM (
            SELECT t.id, t.deadline, COUNT(tasks.id) AS total, COALESCE(SUM(tasks.done), 0) AS done
            FROM todos t
            LEFT JOIN tasks ON tasks.todo_id = t.id
            WHERE t.archived_at IS NULL AND t.deadline IS NOT NULL
            GROUP BY t.id
        )
        WHERE deadline < ? AND (total = 0 OR done < total)
        "#,
    )
    .bind(Utc::now().format("%Y-%m-%d").to_string())
    .fetch_one(pool)
    .await
    .map_err(internal_error)?;
    let overdue_todos: i64 = overdue_row.get(0);

    let budget_row = sqlx::query(
        r#"
        SELECT COALESCE(SUM(budget_planned), 0) AS planned, COALESCE(SUM(budget_spent), 0) AS spent
        FROM todos
        WHERE archived_at IS NULL
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(internal_error)?;
    let budget_planned_sum: f64 = budget_row.get("planned");
    let budget_spent_sum: f64 = budget_row.get("spent");

    let over_budget_row = sqlx::query(
        r#"
        SELECT COUNT(*) AS count
        FROM todos
        WHERE archived_at IS NULL AND budget_planned > 0 AND budget_spent > budget_planned
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(internal_error)?;
    let over_budget_count: i64 = over_budget_row.get(0);

    Ok(DbMetricsSnapshot {
        todos_active,
        todos_archived,
        todos_completed,
        tasks_total,
        tasks_done,
        overdue_todos,
        budget_planned_sum,
        budget_spent_sum,
        over_budget_count,
    })
}

fn build_http_client() -> HttpClient {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

async fn send_metrics_payload(config: &MetricsConfig, payload: String) -> Result<(), String> {
    let url = if config.version == "v1" {
        build_influx_v1_url(
            &config.v1_url,
            &config.v1_db,
            &config.v1_user,
            &config.v1_password,
        )?
    } else {
        config.url.clone()
    };
    let uri = url
        .parse::<hyper::Uri>()
        .map_err(|err| format!("Bad metrics URL: {err}"))?;
    let client = build_http_client();
    let mut request = Request::post(uri)
        .header("Content-Type", "text/plain")
        .header("User-Agent", "bluetodo-metrics");
    if config.version != "v1" && !config.token.trim().is_empty() {
        request = request.header("Authorization", format!("Token {}", config.token));
    }
    let body = Full::new(Bytes::from(payload));
    let response = client
        .request(request.body(body).map_err(|err| err.to_string())?)
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("Influx status {}", response.status()));
    }
    Ok(())
}

fn influx_escape_tag(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(' ', "\\ ")
        .replace('=', "\\=")
}

async fn ensure_influx_v1_db_exists(
    metrics: &MetricsState,
    config: &MetricsConfig,
) -> Result<(), String> {
    let base = config.v1_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("Missing v1 base URL".to_string());
    }
    if config.v1_db.trim().is_empty() {
        return Err("Missing v1 database".to_string());
    }
    let key = format!("{}|{}|{}", base, config.v1_db, config.v1_user);
    {
        let guard = metrics.v1_db_checked.lock().await;
        if guard.contains(&key) {
            return Ok(());
        }
    }

    let uri = format!("{}/query", base)
        .parse::<hyper::Uri>()
        .map_err(|err| format!("Bad v1 URL: {err}"))?;
    let mut query = format!(
        "q={}",
        encode_query(&format!("CREATE DATABASE {}", config.v1_db))
    );
    if !config.v1_user.trim().is_empty() {
        query.push_str("&u=");
        query.push_str(&encode_query(&config.v1_user));
    }
    if !config.v1_password.trim().is_empty() {
        query.push_str("&p=");
        query.push_str(&encode_query(&config.v1_password));
    }
    let client = build_http_client();
    let request = Request::post(uri)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "bluetodo-metrics")
        .body(Full::new(Bytes::from(query)))
        .map_err(|err| err.to_string())?;
    let response = client
        .request(request)
        .await
        .map_err(|err| err.to_string())?;
    if response.status().is_success() {
        let mut guard = metrics.v1_db_checked.lock().await;
        guard.insert(key);
        return Ok(());
    }
    Err(format!("Influx v1 create DB status {}", response.status()))
}

fn build_influx_v1_url(base: &str, db: &str, user: &str, password: &str) -> Result<String, String> {
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("Missing v1 base URL".to_string());
    }
    if db.trim().is_empty() {
        return Err("Missing v1 database".to_string());
    }
    let mut url = format!("{}/write?db={}&precision=s", base, encode_query(db));
    if !user.trim().is_empty() {
        url.push_str("&u=");
        url.push_str(&encode_query(user));
    }
    if !password.trim().is_empty() {
        url.push_str("&p=");
        url.push_str(&encode_query(password));
    }
    Ok(url)
}

fn encode_query(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{:02X}", byte),
        })
        .collect::<Vec<String>>()
        .join("")
}

async fn metrics_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    state.metrics.http_start();
    let response = next.run(req).await;
    state.metrics.http_end();
    state.metrics.http_request().await;
    response
}

async fn proto_load_todo_active(
    pool: &SqlitePool,
    todo_id: i64,
) -> Result<Option<bool>, ProtoCommandError> {
    let row = sqlx::query("SELECT archived_at FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(pool)
        .await
        .map_err(proto_internal_error)?;
    Ok(row.map(|row| row.get::<Option<String>, _>("archived_at").is_none()))
}

async fn proto_load_task_active(
    pool: &SqlitePool,
    task_id: i64,
) -> Result<Option<(i64, bool)>, ProtoCommandError> {
    let row = sqlx::query(
        r#"
        SELECT todos.id AS todo_id, todos.archived_at AS archived_at
        FROM tasks
        JOIN todos ON tasks.todo_id = todos.id
        WHERE tasks.id = ?
        "#,
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .map_err(proto_internal_error)?;

    Ok(row.map(|row| {
        let todo_id: i64 = row.get("todo_id");
        let archived_at: Option<String> = row.get("archived_at");
        (todo_id, archived_at.is_none())
    }))
}

async fn proto_todo_is_complete(
    pool: &SqlitePool,
    todo_id: i64,
) -> Result<bool, ProtoCommandError> {
    let stats = sqlx::query(
        "SELECT COUNT(*) AS total, COALESCE(SUM(done), 0) AS done FROM tasks WHERE todo_id = ?",
    )
    .bind(todo_id)
    .fetch_one(pool)
    .await
    .map_err(proto_internal_error)?;

    let total: i64 = stats.get("total");
    let done: i64 = stats.get("done");
    Ok(total > 0 && total == done)
}

fn get_param(request: &ProtoRequest, key: &str) -> Result<String, String> {
    request
        .params
        .get(key)
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("Missing {}", key))
}

fn get_i64_param(request: &ProtoRequest, key: &str) -> Result<i64, String> {
    let value = get_param(request, key)?;
    value.parse::<i64>().map_err(|_| format!("Bad {}", key))
}

fn get_f64_param_optional(request: &ProtoRequest, key: &str) -> Result<f64, String> {
    match request.params.get(key) {
        Some(value) if !value.trim().is_empty() => {
            value.parse::<f64>().map_err(|_| format!("Bad {}", key))
        }
        _ => Ok(0.0),
    }
}

fn encode_value(value: &str) -> String {
    let mut encoded = String::new();
    for &byte in value.as_bytes() {
        if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}

fn decode_value(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err("BadEscape".to_string());
                }
                let hi = from_hex(bytes[i + 1]).ok_or_else(|| "BadEscape".to_string())?;
                let lo = from_hex(bytes[i + 2]).ok_or_else(|| "BadEscape".to_string())?;
                output.push((hi << 4) | lo);
                i += 3;
            }
            byte => {
                output.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|_| "BadUtf8".to_string())
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn crc32_hex(data: &[u8]) -> String {
    format!("{:08X}", crc32(data))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let mut value = (crc ^ byte as u32) & 0xFF;
        for _ in 0..8 {
            if value & 1 != 0 {
                value = 0xEDB88320 ^ (value >> 1);
            } else {
                value >>= 1;
            }
        }
        crc = (crc >> 8) ^ value;
    }
    !crc
}

fn parse_optional_money(value: Option<&str>) -> f64 {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .and_then(|text| text.replace(',', ".").parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn parse_required_money(value: Option<&str>) -> Result<f64, &'static str> {
    let text = value.map(str::trim).filter(|text| !text.is_empty());
    let text = match text {
        Some(value) => value,
        None => return Err("Summe fehlt"),
    };
    text.replace(',', ".")
        .parse::<f64>()
        .map_err(|_| "Summe ungültig")
}

fn normalize_optional_date(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .and_then(|text| NaiveDate::parse_from_str(text, "%Y-%m-%d").ok())
        .map(|date| date.format("%Y-%m-%d").to_string())
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| text.to_string())
}

#[derive(Deserialize)]
struct UpdateAsset {
    os: String,
    arch: String,
    url: String,
    sha256: String,
    size_bytes: Option<u64>,
}

#[derive(Deserialize)]
struct UpdateManifest {
    app_id: String,
    channel: String,
    latest_version: String,
    notes: Option<String>,
    assets: Vec<UpdateAsset>,
}

async fn set_update_status(pool: &SqlitePool, status: UpdateStatus) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_last_checked'")
        .bind(status.last_checked)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_last_status'")
        .bind(status.last_status)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_available'")
        .bind(if status.available { "1" } else { "0" })
        .execute(pool)
        .await?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_latest_version'")
        .bind(status.latest_version)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_latest_notes'")
        .bind(status.latest_notes)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_latest_url'")
        .bind(status.latest_url)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_latest_sha256'")
        .bind(status.latest_sha256)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE settings SET value = ? WHERE key = 'update_latest_size'")
        .bind(status.latest_size)
        .execute(pool)
        .await?;
    Ok(())
}

fn compare_versions(current: &str, latest: &str) -> std::cmp::Ordering {
    let parse = |value: &str| -> Vec<u64> {
        value
            .split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let a = parse(current);
    let b = parse(latest);
    let max = a.len().max(b.len());
    for idx in 0..max {
        let av = *a.get(idx).unwrap_or(&0);
        let bv = *b.get(idx).unwrap_or(&0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn basic_auth_header(user: &str, password: &str) -> Option<HeaderValue> {
    if user.trim().is_empty() && password.trim().is_empty() {
        return None;
    }
    let token = format!("{}:{}", user, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(token);
    HeaderValue::from_str(&format!("Basic {}", encoded)).ok()
}

async fn fetch_url_bytes(url: &str, user: &str, password: &str) -> Result<Vec<u8>, String> {
    let client = build_http_client();
    let mut request = Request::builder()
        .method("GET")
        .uri(url)
        .body(Full::new(Bytes::new()))
        .map_err(|err| err.to_string())?;
    if let Some(header_value) = basic_auth_header(user, password) {
        request
            .headers_mut()
            .insert(header::AUTHORIZATION, header_value);
    }
    let response = client
        .request(request)
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status));
    }
    let body = response.into_body();
    let bytes = body
        .collect()
        .await
        .map_err(|err| err.to_string())?
        .to_bytes();
    Ok(bytes.to_vec())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

async fn perform_update_check(pool: &SqlitePool, config: &UpdateConfig) -> Result<(), String> {
    if !config.enabled {
        set_update_status(
            pool,
            UpdateStatus {
                last_checked: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                last_status: "Deaktiviert".to_string(),
                available: false,
                latest_version: String::new(),
                latest_notes: String::new(),
                latest_url: String::new(),
                latest_sha256: String::new(),
                latest_size: String::new(),
            },
        )
        .await
        .map_err(|err| err.to_string())?;
        return Ok(());
    }
    let manifest_bytes = fetch_url_bytes(&config.url, &config.user, &config.password).await?;
    let manifest: UpdateManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|err| err.to_string())?;
    if manifest.app_id != APP_ID {
        return Err("Manifest passt nicht zur App-ID".to_string());
    }
    if manifest.channel != config.channel {
        return Err("Manifest-Kanal passt nicht".to_string());
    }
    let asset = manifest
        .assets
        .iter()
        .find(|asset| asset.os == std::env::consts::OS && asset.arch == std::env::consts::ARCH)
        .ok_or_else(|| "Kein Asset für Plattform".to_string())?;
    let ordering = compare_versions(APP_VERSION, &manifest.latest_version);
    let available = ordering == std::cmp::Ordering::Less;
    let notes = manifest.notes.unwrap_or_default();
    let size = asset
        .size_bytes
        .map(|value| value.to_string())
        .unwrap_or_default();
    set_update_status(
        pool,
        UpdateStatus {
            last_checked: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            last_status: if available {
                format!("Update verfügbar ({})", manifest.latest_version)
            } else {
                "Aktuell".to_string()
            },
            available,
            latest_version: manifest.latest_version,
            latest_notes: notes,
            latest_url: asset.url.clone(),
            latest_sha256: asset.sha256.clone(),
            latest_size: size,
        },
    )
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

async fn apply_update(pool: &SqlitePool, config: &UpdateConfig) -> Result<(), String> {
    perform_update_check(pool, config).await?;
    let status = load_update_status(pool).await.map_err(|err| err.1)?;
    if !status.available {
        return Ok(());
    }
    let url = status.latest_url;
    if url.trim().is_empty() {
        return Err("Kein Download-URL".to_string());
    }
    let zip_bytes = fetch_url_bytes(&url, &config.user, &config.password).await?;
    let expected = status.latest_sha256.to_lowercase();
    if !expected.is_empty() {
        let actual = sha256_hex(&zip_bytes);
        if actual != expected {
            return Err("SHA256 stimmt nicht".to_string());
        }
    }
    let mut archive =
        ZipArchive::new(std::io::Cursor::new(zip_bytes)).map_err(|err| err.to_string())?;
    let binary_name = if std::env::consts::OS == "windows" {
        "bluetodo.exe"
    } else {
        "bluetodo"
    };
    let mut extracted: Option<Vec<u8>> = None;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|err| err.to_string())?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        if name == binary_name || name.ends_with(&format!("/{}", binary_name)) {
            let mut buf = Vec::new();
            std::io::copy(&mut file, &mut buf).map_err(|err| err.to_string())?;
            extracted = Some(buf);
            break;
        }
    }
    let Some(binary) = extracted else {
        return Err("Binary nicht im ZIP gefunden".to_string());
    };
    let exe_path = std::env::current_exe().map_err(|err| err.to_string())?;
    let dir = exe_path
        .parent()
        .ok_or_else(|| "Pfad ungültig".to_string())?;
    let new_path = dir.join("bluetodo.new");
    let backup_path = dir.join("bluetodo.old");
    fs::write(&new_path, &binary).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::metadata(&exe_path)
            .map(|meta| meta.permissions().mode())
            .unwrap_or(0o755);
        fs::set_permissions(&new_path, fs::Permissions::from_mode(perm))
            .map_err(|err| err.to_string())?;
    }
    if backup_path.exists() {
        let _ = fs::remove_file(&backup_path);
    }
    fs::rename(&exe_path, &backup_path).map_err(|err| err.to_string())?;
    fs::rename(&new_path, &exe_path).map_err(|err| err.to_string())?;
    let restart_scheduled = schedule_restart(exe_path.clone());
    let status_msg = if restart_scheduled {
        "Update installiert – Neustart läuft"
    } else {
        "Update installiert – bitte neu starten"
    };
    set_update_status(
        pool,
        UpdateStatus {
            last_checked: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            last_status: status_msg.to_string(),
            available: false,
            latest_version: String::new(),
            latest_notes: String::new(),
            latest_url: String::new(),
            latest_sha256: String::new(),
            latest_size: String::new(),
        },
    )
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

fn schedule_restart(exe_path: PathBuf) -> bool {
    #[cfg(unix)]
    {
        let args: Vec<String> = std::env::args().collect();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            let mut cmd = std::process::Command::new(exe_path);
            if args.len() > 1 {
                cmd.args(&args[1..]);
            }
            use std::os::unix::process::CommandExt;
            let _ = cmd.exec();
        });
        true
    }
    #[cfg(not(unix))]
    {
        let _ = exe_path;
        false
    }
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn internal_error(err: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
