use crate::response::api::ApiErrorResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FaucetError {
    #[error("Invalid Proof of Work")]
    InvalidPoW,
    #[error("Invalid tag")]
    InvalidProof,
    #[error("Proof of work challenge already seen")]
    DuplicateChallenge,
    #[error("Invalid Address")]
    InvalidAddress,
    #[error("Chain didn't start yet")]
    ChainNotStarted,
    #[error("Faucet out of balance")]
    FaucetOutOfBalance,
    #[error("Error while sending transfer: {0}")]
    SdkError(String),
    #[error("Withdraw limit must be less then {0}")]
    InvalidWithdrawLimit(u64),
    #[error("Invalid Captcha")]
    InvalidCaptcha,
}

impl IntoResponse for FaucetError {
    fn into_response(self) -> Response {
        let status_code = match self {
            FaucetError::InvalidPoW => StatusCode::BAD_REQUEST,
            FaucetError::InvalidProof => StatusCode::FORBIDDEN,
            FaucetError::DuplicateChallenge => StatusCode::CONFLICT,
            FaucetError::InvalidAddress => StatusCode::BAD_REQUEST,
            FaucetError::ChainNotStarted => StatusCode::BAD_REQUEST,
            FaucetError::InvalidWithdrawLimit(_) => StatusCode::BAD_REQUEST,
            FaucetError::FaucetOutOfBalance => StatusCode::CONFLICT,
            FaucetError::SdkError(_) => StatusCode::BAD_REQUEST,
            FaucetError::InvalidCaptcha => StatusCode::BAD_REQUEST,
        };

        ApiErrorResponse::send(status_code.as_u16(), Some(self.to_string()))
    }
}
