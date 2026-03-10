use super::*;

#[derive(Clone, Debug)]
struct DbStartupSnapshot {
    app_id: Option<String>,
    app_version: Option<String>,
    schema_version: Option<i64>,
    proto_version: Option<i64>,
    has_user_tables: bool,
}

#[derive(Clone, Debug)]
pub(super) struct DbStartupBackup {
    pub(super) created_at: String,
    pub(super) backup_path: PathBuf,
    pub(super) reason: String,
    pub(super) from_app_id: Option<String>,
    pub(super) from_app_version: Option<String>,
    pub(super) from_schema_version: Option<i64>,
    pub(super) from_proto_version: Option<i64>,
}

pub(super) async fn prepare_db_startup_backup(
    db_path: &StdPath,
) -> Result<Option<DbStartupBackup>, Box<dyn std::error::Error>> {
    let Some(snapshot) = inspect_existing_db_snapshot(db_path).await? else {
        return Ok(None);
    };
    let Some(reason) = startup_backup_reason(&snapshot) else {
        return Ok(None);
    };

    let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let backup_path = build_startup_backup_path(db_path, &snapshot, &created_at);
    copy_sqlite_backup(db_path, &backup_path)?;

    Ok(Some(DbStartupBackup {
        created_at,
        backup_path,
        reason,
        from_app_id: snapshot.app_id,
        from_app_version: snapshot.app_version,
        from_schema_version: snapshot.schema_version,
        from_proto_version: snapshot.proto_version,
    }))
}

async fn inspect_existing_db_snapshot(
    db_path: &StdPath,
) -> Result<Option<DbStartupSnapshot>, Box<dyn std::error::Error>> {
    let metadata = match fs::metadata(db_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(Box::new(err)),
    };
    if metadata.len() == 0 {
        return Ok(None);
    }

    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(false)
        .foreign_keys(false);
    let pool = SqlitePool::connect_with(options).await?;
    let has_app_meta = table_exists(&pool, "app_meta").await?;
    let has_user_tables = has_non_sqlite_tables(&pool).await?;
    let snapshot = if has_app_meta {
        DbStartupSnapshot {
            app_id: load_app_meta_value_raw(&pool, "app_id").await?,
            app_version: load_app_meta_value_raw(&pool, "app_version").await?,
            schema_version: load_app_meta_i64_raw(&pool, "schema_version").await?,
            proto_version: load_app_meta_i64_raw(&pool, "proto_version").await?,
            has_user_tables,
        }
    } else if has_user_tables {
        DbStartupSnapshot {
            app_id: None,
            app_version: None,
            schema_version: None,
            proto_version: None,
            has_user_tables,
        }
    } else {
        pool.close().await;
        return Ok(None);
    };
    pool.close().await;
    Ok(Some(snapshot))
}

async fn table_exists(pool: &SqlitePool, table: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
    )
    .bind(table)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

async fn has_non_sqlite_tables(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

fn startup_backup_reason(snapshot: &DbStartupSnapshot) -> Option<String> {
    if let Some(app_id) = snapshot.app_id.as_deref() {
        if app_id != APP_ID && app_id != LEGACY_APP_ID_WINTODO {
            return None;
        }
    }

    let mut reasons = Vec::new();
    if snapshot.app_id.as_deref() == Some(LEGACY_APP_ID_WINTODO) {
        reasons.push(format!(
            "legacy app_id {} -> {}",
            LEGACY_APP_ID_WINTODO, APP_ID
        ));
    } else if snapshot.has_user_tables && snapshot.app_id.is_none() {
        reasons.push("fehlende app_id-Metadaten".to_string());
    }

    if snapshot.schema_version.unwrap_or(0) < SCHEMA_VERSION {
        reasons.push(format!(
            "schema {} -> {}",
            snapshot
                .schema_version
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unbekannt".to_string()),
            SCHEMA_VERSION
        ));
    }

    if snapshot.proto_version.unwrap_or(0) < PROTO_VERSION {
        reasons.push(format!(
            "proto {} -> {}",
            snapshot
                .proto_version
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unbekannt".to_string()),
            PROTO_VERSION
        ));
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    }
}

fn build_startup_backup_path(
    db_path: &StdPath,
    snapshot: &DbStartupSnapshot,
    created_at: &str,
) -> PathBuf {
    let backup_dir = db_path
        .parent()
        .unwrap_or_else(|| StdPath::new("."))
        .join("backups");
    let file_name = db_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bluetodo.db");
    let timestamp = created_at
        .chars()
        .map(|c| match c {
            '0'..='9' => c,
            _ => '-',
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let from_version = sanitize_backup_label(snapshot.app_version.as_deref().unwrap_or("unknown"));
    let file_name = format!(
        "{}.pre-{}-from-{}-s{}-p{}-{}.bak",
        file_name,
        sanitize_backup_label(APP_VERSION),
        from_version,
        snapshot.schema_version.unwrap_or(0),
        snapshot.proto_version.unwrap_or(0),
        timestamp
    );
    backup_dir.join(file_name)
}

fn sanitize_backup_label(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn copy_sqlite_backup(db_path: &StdPath, backup_path: &StdPath) -> std::io::Result<()> {
    if let Some(parent) = backup_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::copy(db_path, backup_path)?;
    copy_sqlite_sidecar(db_path, backup_path, "-wal")?;
    copy_sqlite_sidecar(db_path, backup_path, "-shm")?;
    Ok(())
}

fn copy_sqlite_sidecar(
    db_path: &StdPath,
    backup_path: &StdPath,
    suffix: &str,
) -> std::io::Result<()> {
    let sidecar_path = PathBuf::from(format!("{}{}", db_path.to_string_lossy(), suffix));
    if !sidecar_path.exists() {
        return Ok(());
    }
    let backup_sidecar = PathBuf::from(format!("{}{}", backup_path.to_string_lossy(), suffix));
    fs::copy(sidecar_path, backup_sidecar)?;
    Ok(())
}
