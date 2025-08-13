#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum CargoEnv {
    Development,
    Production,
}

#[derive(clap::Parser)]
pub struct AppConfig {
    #[clap(long, env, default_value = "5000")]
    pub port: u16,

    #[clap(long, env)]
    pub difficulty: u64,

    #[clap(long, env)]
    pub private_key: String,

    #[clap(long, env)]
    pub chain_start: i64,

    #[clap(long, env)]
    pub chain_id: String,

    #[clap(long, env)]
    pub rpc: String,

    #[clap(long, env)]
    pub withdraw_limit: Option<u64>,

    #[clap(long, env)]
    pub auth_key: Option<String>,

    #[clap(long, env)]
    pub rps: Option<u64>,

    #[clap(long, env)]
    pub turnstile_secret: Option<String>,
}
