#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("INVALID_LICENSE: {0}")]
    Invalid(String),
    #[error("HARDWARE_MISMATCH")]
    HardwareMismatch,
    #[error("DEVICE_KEY_MISMATCH")]
    DeviceKeyMismatch,
    #[error("DEVELOPMENT_MODE_FORBIDDEN")]
    DevelopmentForbidden,
    #[error("LICENSE_EXPIRED_OR_NOT_YET_VALID")]
    LicenseTime,
    #[error("SIGNATURE_INVALID")]
    Signature,
    #[error("LIMIT_REACHED")]
    Limit,
    #[error("SESSION_LIMIT_REACHED")]
    SessionLimit,
    #[error("REQUEST_RATE_LIMIT_REACHED")]
    RateLimit,
    #[error("MODULE_DENIED")]
    ModuleDenied,
    #[error("LEASE_INVALID_OR_EXPIRED")]
    LeaseInvalid,
    #[error("UNAUTHORIZED")]
    Unauthorized,
    #[error("REVISION_ROLLBACK_OR_CONFLICT")]
    Revision,
    #[error("CLOCK_SUSPECT")]
    Clock,
    #[error("REQUEST_ID_CONFLICT")]
    RequestConflict,
    #[error("STATE_NOT_INITIALIZED")]
    StateMissing,
    #[error("DEVICE_UNAVAILABLE: {0}")]
    Device(String),
    #[error(transparent)]
    Storage(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
