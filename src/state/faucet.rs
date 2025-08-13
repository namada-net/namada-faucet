use crate::{
    app_state::AppState, repository::faucet::FaucetRepository,
    repository::faucet::FaucetRepositoryTrait, services::faucet::FaucetService,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use namada_sdk::{
    address::Address, io::NullIo, masp::fs::FsShieldedUtils, wallet::fs::FsWalletUtils, NamadaImpl,
};
use tendermint_rpc::HttpClient;

#[derive(Clone)]
pub struct FaucetState {
    pub faucet_service: FaucetService,
    pub faucet_repo: FaucetRepository,
    pub faucet_address: Address,
    pub sdk: Arc<NamadaImpl<HttpClient, FsWalletUtils, FsShieldedUtils, NullIo>>,
    pub auth_key: String,
    pub difficulty: u64,
    pub chain_id: String,
    pub chain_start: i64,
    pub withdraw_limit: u64,
    pub turnstile_secret: Option<String>,
}

impl FaucetState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data: &Arc<RwLock<AppState>>,
        faucet_address: Address,
        sdk: NamadaImpl<HttpClient, FsWalletUtils, FsShieldedUtils, NullIo>,
        auth_key: String,
        difficulty: u64,
        chain_id: String,
        chain_start: i64,
        withdraw_limit: u64,
        turnstile_secret: Option<String>,
    ) -> Self {
        Self {
            faucet_service: FaucetService::new(data),
            faucet_repo: FaucetRepository::new(data),
            faucet_address,
            sdk: Arc::new(sdk),
            auth_key,
            difficulty,
            chain_id,
            chain_start,
            withdraw_limit: withdraw_limit * 10_u64.pow(6),
            turnstile_secret,
        }
    }
}
