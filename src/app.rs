use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use tokio::{sync::RwLock, time::sleep};

use axum::{
    error_handling::HandleErrorLayer,
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    BoxError, Json, Router,
};
use lazy_static::lazy_static;
use namada_sdk::{
    address::Address, args::TxBuilder, chain::ChainId, io::NullIo, key::RefTo,
    masp::fs::FsShieldedUtils, wallet::fs::FsWalletUtils, NamadaImpl,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde_json::json;
use tendermint_rpc::{HttpClient, Url};
use tower::{buffer::BufferLayer, limit::RateLimitLayer, ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{app_state::AppState, config::AppConfig, state::faucet::FaucetState};
use crate::{handler::faucet as faucet_handler, sdk::utils::sk_from_str};

lazy_static! {
    static ref HTTP_TIMEOUT: u64 = 30;
    static ref REQ_PER_SEC: u64 = u64::MAX;
}

pub struct ApplicationServer;

impl ApplicationServer {
    pub async fn serve(config: Arc<AppConfig>, db: Arc<RwLock<AppState>>) -> anyhow::Result<()> {
        let auth_key = config.auth_key.clone();
        let auth_key = auth_key.unwrap_or_else(|| {
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect()
        });

        assert!(auth_key.len() == 32);

        let difficulty = config.difficulty;
        let rps = config.rps;
        let chain_id = config.chain_id.clone();
        let rpc = config.rpc.clone();
        let chain_start = config.chain_start;
        let withdraw_limit = config.withdraw_limit.unwrap_or(1000_u64);

        let sk = config.private_key.clone();
        let sk = sk_from_str(&sk);
        let pk = sk.ref_to();
        let address = Address::from(&pk);

        loop {
            let current_timestamp = chrono::offset::Utc::now().timestamp();
            if current_timestamp > chain_start {
                break;
            } else {
                tracing::info!("Sleeping until: {}", chain_start);
                sleep(Duration::from_secs(60)).await;
            }
        }

        let url = Url::from_str(&rpc).expect("invalid RPC address");
        let http_client = HttpClient::new(url).unwrap();

        // Setup wallet storage
        let wallet = FsWalletUtils::new("wallet".into());

        // Setup shielded context storage
        let shielded_ctx = FsShieldedUtils::new("masp".into());

        let null_io = NullIo;

        let sdk = NamadaImpl::new(http_client, wallet, shielded_ctx, null_io)
            .await
            .expect("unable to initialize Namada context")
            .chain_id(ChainId::from_str(&chain_id).unwrap());

        let mut wallet = sdk.wallet.write().await;
        wallet
            .insert_keypair(
                "faucet".to_string(),
                true,
                sk.clone(),
                None,
                Some(address.clone()),
                None,
            )
            .unwrap();

        drop(wallet);

        let routes = {
            let faucet_state = FaucetState::new(
                &db,
                address,
                sdk,
                auth_key,
                difficulty,
                chain_id,
                chain_start,
                withdraw_limit,
                config.turnstile_secret.clone(),
            );

            Router::new()
                .route("/faucet/setting", get(faucet_handler::faucet_settings))
                .route("/faucet", get(faucet_handler::request_challenge))
                .route("/faucet", post(faucet_handler::request_transfer))
                .with_state(faucet_state)
        };

        let cors = CorsLayer::new()
            .allow_origin("*".parse::<HeaderValue>().unwrap())
            .allow_methods(Any)
            .allow_headers(Any);

        let router = Router::new()
            .nest("/api/v1", routes)
            .merge(Router::new().route(
                "/health",
                get(|| async { json!({"commit": env!("VERGEN_GIT_SHA").to_string(), "version": env!("CARGO_PKG_VERSION") }).to_string() }),
            ))
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(HandleErrorLayer::new(Self::handle_timeout_error))
                    .timeout(Duration::from_secs(*HTTP_TIMEOUT))
                    .layer(cors)
                    .layer(BufferLayer::new(4096))
                    .layer(RateLimitLayer::new(
                        rps.unwrap_or(*REQ_PER_SEC),
                        Duration::from_secs(1),
                    )),
            );

        let router = router.fallback(Self::handle_404);

        let port = config.port;
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));

        tracing::info!("🚀 Server has launched on https://{addr}");

        axum::Server::bind(&addr)
            .serve(router.into_make_service())
            .with_graceful_shutdown(Self::shutdown_signal())
            .await
            .unwrap_or_else(|e| panic!("Server error: {}", e));

        Ok(())
    }

    /// Adds a custom handler for tower's `TimeoutLayer`, see https://docs.rs/axum/latest/axum/middleware/index.html#commonly-used-middleware.
    async fn handle_timeout_error(err: BoxError) -> (StatusCode, Json<serde_json::Value>) {
        if err.is::<tower::timeout::error::Elapsed>() {
            (
                StatusCode::REQUEST_TIMEOUT,
                Json(json!({
                    "error":
                        format!(
                            "request took longer than the configured {} second timeout",
                            *HTTP_TIMEOUT
                        )
                })),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("unhandled internal error: {}", err)
                })),
            )
        }
    }

    /// Tokio signal handler that will wait for a user to press CTRL+C.
    /// We use this in our hyper `Server` method `with_graceful_shutdown`.
    async fn shutdown_signal() {
        tokio::signal::ctrl_c()
            .await
            .expect("expect tokio signal ctrl-c");
        println!("signal shutdown");
    }

    async fn handle_404() -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            axum::response::Json(serde_json::json!({
                    "errors":{
                    "message": vec!(String::from("The requested resource does not exist on this server!")),}
                }
            )),
        )
    }
}
