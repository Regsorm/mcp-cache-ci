//! Универсальный кэширующий MCP-прокси перед произвольным HTTP MCP-сервером.
//!
//! При старте подключается к бэкенду через rmcp `streamable-http-client`,
//! делает handshake (`initialize` → `notifications/initialized`),
//! запрашивает `tools/list` и сохраняет снимок. Дальше принимает запросы от
//! MCP-клиентов на `/mcp` через `StreamableHttpService` rmcp и форвардит
//! `tools/call` через [`cache_core::CacheProxy`].
//!
//! Кроме `/mcp` бинарник обслуживает служебные эндпоинты `/health`,
//! `/metrics`, `/invalidate` (см. модуль `handlers`).
//!
//! Имя прокси (`alias`) и имена аргументов области (`scope_args`) задаются конфигом.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Extension, Request},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Router,
};
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tracing::{info, warn};

use cache_core::{
    Cache, CacheProxy, DirtySet, FreezeController, Metrics, Policy, ProxyConfig, ProxyServer,
    RevalConfig, RmcpBackend, SingleFlight,
};

mod handlers;
mod pidlock;

#[derive(Parser, Debug)]
#[command(version, about = "Универсальный кэш-прокси перед HTTP MCP-сервером")]
struct Cli {
    /// Путь к TOML-конфигу. Может также быть задан через MCP_CACHE_CONFIG.
    #[arg(long, env = "MCP_CACHE_CONFIG")]
    config: PathBuf,

    /// Перебить bind_port из конфига.
    #[arg(long, env = "MCP_CACHE_BIND_PORT")]
    bind_port: Option<u16>,

    /// Путь к PID-файлу для singleton-защиты. Если не задан — lock не берётся
    /// (Docker: singleton гарантирует контейнер). Задавать на Windows под supervisor.
    #[arg(long, env = "MCP_CACHE_PID_FILE")]
    pid_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    info!(config = %cli.config.display(), "запуск mcp-cache-ci");

    // Опциональный singleton PID-lock: активен только при заданном --pid-file
    // (Windows под supervisor). В Docker не задаётся — singleton даёт контейнер.
    let _pidlock = pidlock::PidLock::acquire_optional(cli.pid_file.clone(), "mcp-cache-ci")
        .context("захват PID-lock")?;

    let mut cfg = ProxyConfig::from_file(&cli.config)
        .with_context(|| "не удалось загрузить конфиг")?;
    if let Some(port) = cli.bind_port {
        cfg.server.bind_port = port;
    }
    info!(alias = %cfg.server.alias, scope_args = ?cfg.server.scope_args, "конфиг загружен");

    let policy = load_policy(&cli.config, &cfg).await?;

    // 1) Подключаемся к бэкенду как MCP-клиент.
    let backend = Arc::new(
        RmcpBackend::connect(cfg.backend.url.clone())
            .await
            .with_context(|| format!("не удалось подключиться к бэкенду {}", cfg.backend.url))?,
    );

    // 2) Снимаем tools/list с бэкенда — отдаём клиентам как свой набор.
    let tools = backend
        .list_all_tools()
        .await
        .with_context(|| "не удалось получить tools/list у бэкенда")?;
    info!(count = tools.len(), "получен снимок tools/list у бэкенда");

    // 3) Собираем ядро.
    let cache = Arc::new(Cache::new());
    let metrics = Arc::new(Metrics::new());
    let singleflight = Arc::new(SingleFlight::<String>::new());
    let policy_swap = Arc::new(arc_swap::ArcSwap::from_pointee(policy));
    let freeze = FreezeController::new();
    let dirty = Arc::new(DirtySet::new());
    let reval = RevalConfig {
        enabled: cfg.cache.lazy_revalidation_enabled,
        max_wait: Duration::from_millis(cfg.cache.revalidation_max_wait_ms),
        retry_interval: Duration::from_millis(cfg.cache.revalidation_retry_interval_ms.max(1)),
    };
    info!(
        enabled = reval.enabled,
        max_wait_ms = cfg.cache.revalidation_max_wait_ms,
        retry_ms = cfg.cache.revalidation_retry_interval_ms,
        dirty_ttl_s = cfg.cache.dirty_ttl_seconds,
        "ленивая ревалидация (#1471)"
    );

    let proxy = Arc::new(CacheProxy::new(
        cfg.server.alias.clone(),
        cfg.server.scope_args.clone(),
        policy_swap.clone(),
        cache.clone(),
        singleflight.clone(),
        metrics.clone(),
        backend.clone(),
        freeze.clone(),
        dirty.clone(),
        reval,
    ));

    spawn_eviction_task(
        cache.clone(),
        metrics.clone(),
        dirty.clone(),
        Duration::from_secs(cfg.cache.dirty_ttl_seconds),
        cfg.cache.evict_interval_seconds,
    );

    // 4) Создаём rmcp ServerHandler и оборачиваем его в StreamableHttpService.
    let proxy_server = ProxyServer::new(
        cfg.server.alias.clone(),
        env!("CARGO_PKG_VERSION"),
        proxy.clone(),
        tools,
    );
    // Stateless mode — кеш-прокси хеширует по (tool_name, args), session_id
    // в ключах не участвует. with_stateful_mode(false) + NeverSessionManager
    // полностью отключают session enforcement: сервер игнорирует Mcp-Session-Id,
    // никаких 404 «Session not found» при рестарте процесса / TTL не возникает.
    // json_response=true — отдаём application/json вместо text/event-stream:
    // меньше overhead'а, у нас нет server-initiated notifications (только
    // ответы на tool-call).
    let session_manager = Arc::new(NeverSessionManager::default());
    let svc_factory = {
        let proxy_server = proxy_server.clone();
        move || Ok(proxy_server.clone())
    };
    let mut http_config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true);
    if let Some(hosts) = &cfg.server.allowed_hosts {
        tracing::info!(allowed_hosts = ?hosts, "переопределяю allowed_hosts из конфига");
        http_config = http_config.with_allowed_hosts(hosts.clone());
    }
    let mcp_service = StreamableHttpService::new(svc_factory, session_manager, http_config);

    // 5) Поднимаем axum: /mcp + служебные эндпоинты.
    let state = handlers::AppState {
        cache,
        metrics,
        backend_url: cfg.backend.url.clone(),
        server_alias: cfg.server.alias.clone(),
        freeze: freeze.clone(),
        dirty: dirty.clone(),
    };

    // Fallback-прокси: всё, что не /health, /metrics, /invalidate, /mcp/* —
    // прозрачно проксируется на бэкенд тем же методом и body. Нужно для
    // federation-роутов code-index (POST /federate/<tool>), которые rmcp
    // StreamableHttpService не обслуживает.
    let backend_base = derive_base_url(&cfg.backend.url);
    let fallback_state = FallbackState {
        client: reqwest::Client::builder()
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .context("не удалось создать reqwest::Client для fallback")?,
        backend_base: backend_base.clone(),
    };
    info!(backend_base = %backend_base, "fallback-прокси для не-MCP роутов готов");

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/metrics", get(handlers::metrics))
        .route("/metrics/json", get(handlers::metrics_json))
        .route("/status", get(handlers::status))
        .route("/invalidate", post(handlers::invalidate))
        .route("/mark-dirty", post(handlers::mark_dirty))
        .route("/freeze", post(handlers::freeze))
        .route("/thaw", post(handlers::thaw))
        .with_state(state)
        .nest_service("/mcp", mcp_service)
        .fallback(fallback_proxy)
        .layer(Extension(fallback_state));

    let bind = format!("{}:{}", cfg.server.bind_host, cfg.server.bind_port);
    info!(bind = %bind, backend = %cfg.backend.url, "слушаем");
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("не удалось забиндиться на {bind}"))?;
    axum::serve(listener, app).await.context("axum::serve упал")?;
    Ok(())
}

fn init_tracing() {
    use std::io::{self, IsTerminal};
    use tracing_subscriber::{fmt::writer::BoxMakeWriter, EnvFilter};

    let terminal = io::stderr().is_terminal();
    let writer = if terminal {
        BoxMakeWriter::new(io::stderr)
    } else {
        BoxMakeWriter::new(io::stdout)
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(terminal)
        .with_writer(writer)
        .init();
}

fn spawn_eviction_task(
    cache: Arc<Cache>,
    metrics: Arc<Metrics>,
    dirty: Arc<DirtySet>,
    dirty_ttl: Duration,
    interval_s: u64,
) {
    if interval_s == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(interval_s));
        loop {
            tick.tick().await;
            let removed = cache.evict_expired();
            metrics.update_cache_size(cache.len());
            // Страховочная чистка протухших dirty-флагов (#1471): в норме флаг
            // снимается сверкой mtime на первом чтении, но если по пути чтения
            // так и не пришло — TTL не даёт множеству расти бесконечно.
            let dirty_pruned = dirty.prune_older_than(dirty_ttl);
            if removed > 0 || dirty_pruned > 0 {
                tracing::debug!(removed, dirty_pruned, "background eviction");
            }
        }
    });
}

/// State для fallback-прокси: один общий reqwest::Client + базовый URL бэкенда
/// без `/mcp` в конце.
#[derive(Clone)]
struct FallbackState {
    client: reqwest::Client,
    backend_base: String,
}

/// Из `http://host:port/mcp` делает `http://host:port`. Если суффикса нет —
/// просто отрезает trailing slash.
fn derive_base_url(mcp_url: &str) -> String {
    let trimmed = mcp_url.trim_end_matches('/');
    if let Some(stripped) = trimmed.strip_suffix("/mcp") {
        stripped.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Прозрачный HTTP reverse-proxy на бэкенд для всех путей, не обработанных
/// конкретными routes. Главный потребитель — federation-роуты code-index
/// (`POST /federate/<tool>`).
async fn fallback_proxy(
    Extension(state): Extension<FallbackState>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 16 * 1024 * 1024)
        .await
        .map_err(|e| {
            warn!(error = %e, "fallback: не смог прочитать тело запроса");
            StatusCode::PAYLOAD_TOO_LARGE
        })?;

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let url = format!(
        "{}{}",
        state.backend_base.trim_end_matches('/'),
        path_and_query
    );

    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return Err(StatusCode::METHOD_NOT_ALLOWED),
    };
    let mut rb = state.client.request(method, &url).body(body_bytes.to_vec());
    for (name, value) in parts.headers.iter() {
        // hop-by-hop и `host` пропускаем — reqwest проставит свои корректно.
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
        ) {
            continue;
        }
        rb = rb.header(name.as_str(), value.as_bytes());
    }

    let upstream = rb.send().await.map_err(|e| {
        warn!(error = %e, url = %url, "fallback: ошибка обращения к бэкенду");
        StatusCode::BAD_GATEWAY
    })?;

    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let body_bytes = upstream.bytes().await.map_err(|e| {
        warn!(error = %e, "fallback: ошибка чтения тела ответа бэкенда");
        StatusCode::BAD_GATEWAY
    })?;

    let mut builder = Response::builder().status(status.as_u16());
    for (name, value) in upstream_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "content-length" | "connection" | "transfer-encoding"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    builder
        .body(Body::from(body_bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Загрузка политики: либо из явного `policy_path` в конфиге, либо дефолт.
async fn load_policy(config_path: &Path, cfg: &ProxyConfig) -> Result<Policy> {
    let Some(rel) = cfg.policy_path.as_ref() else {
        tracing::info!("policy: не указан policy_path — использую Policy::default()");
        return Ok(Policy::default());
    };
    let policy_path: PathBuf = if PathBuf::from(rel).is_absolute() {
        PathBuf::from(rel)
    } else {
        // Разрешаем относительно каталога конфиг-файла.
        config_path
            .parent()
            .map(|p| p.join(rel))
            .unwrap_or_else(|| PathBuf::from(rel))
    };
    let policy = Policy::from_file(&policy_path)
        .with_context(|| format!("не удалось прочитать политику: {}", policy_path.display()))?;
    tracing::info!(
        path = %policy_path.display(),
        default_ttl = policy.default_ttl_seconds,
        tools = policy.tools.len(),
        "policy загружена"
    );
    Ok(policy)
}
