use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum DbPathSource {
    Env,
    Config,
    Default,
}

#[derive(Clone, Debug)]
pub(super) struct AppConfig {
    pub(super) db_path: PathBuf,
    pub(super) config_path: PathBuf,
    pub(super) source: DbPathSource,
    pub(super) configured_db_path: Option<String>,
    pub(super) env_override: Option<String>,
}

pub(super) fn load_app_config() -> AppConfig {
    let config_path = default_config_path();
    let env_override = env::var("BLUETODO_DB_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let configured_db_path = read_db_path_config(&config_path);

    let (raw_path, source) = if let Some(value) = env_override.clone() {
        (value, DbPathSource::Env)
    } else if let Some(value) = configured_db_path.clone() {
        (value, DbPathSource::Config)
    } else {
        (
            default_db_path().to_string_lossy().to_string(),
            DbPathSource::Default,
        )
    };

    let resolved = resolve_db_path(&raw_path);

    AppConfig {
        db_path: resolved,
        config_path,
        source,
        configured_db_path,
        env_override,
    }
}

fn default_db_path() -> PathBuf {
    if let Ok(dir) = env::var("XDG_DATA_HOME") {
        return PathBuf::from(dir).join("bluetodo").join("bluetodo.db");
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("bluetodo")
            .join("bluetodo.db");
    }
    PathBuf::from("bluetodo.db")
}

fn default_config_path() -> PathBuf {
    if let Ok(path) = env::var("BLUETODO_CONFIG") {
        return PathBuf::from(path);
    }
    if let Ok(dir) = env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(dir).join("bluetodo").join("config.env");
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("bluetodo")
            .join("config.env");
    }
    PathBuf::from("bluetodo.conf")
}

pub(super) fn default_secret_key_path() -> PathBuf {
    if let Ok(path) = env::var(SECRET_MASTER_KEY_FILE_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Some(parent) = default_config_path().parent() {
        if !parent.as_os_str().is_empty() {
            return parent.join("master.key");
        }
    }
    PathBuf::from("bluetodo.master.key")
}

fn read_db_path_config(path: &StdPath) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            if key.trim() == "db_path" {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

pub(super) fn write_db_path_config(path: &StdPath, value: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = fs::File::create(path)?;
    writeln!(file, "# BlueTodo config")?;
    writeln!(file, "db_path={}", value)?;
    Ok(())
}

pub(super) fn resolve_db_path(raw: &str) -> PathBuf {
    let expanded = expand_tilde(raw.trim());
    PathBuf::from(expanded)
}

pub(super) fn storage_dir() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("storage")
}

fn expand_tilde(value: &str) -> String {
    if let Some(stripped) = value.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home)
                .join(stripped)
                .to_string_lossy()
                .to_string();
        }
    }
    value.to_string()
}
