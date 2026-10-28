use crate::{
    device::Device,
    error::{Error, Result},
    lease::{self, LeaseClaims, LeaseToken},
    license::{self, Claims},
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

pub const LEASE_TTL: i64 = 180;
pub const HEARTBEAT_SECONDS: u32 = 60;
pub const MAX_SESSIONS: i64 = 4;
const CLOCK_TOLERANCE: i64 = 300;
const REQUEST_WINDOW: i64 = 3600;
const MAX_REQUESTS_PER_SUBJECT: i64 = 512;

#[derive(Debug, Clone)]
pub struct Principal {
    pub organization: String,
    pub subject: String,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub license_id: String,
    pub revision: u64,
    pub expiration_date: i64,
    pub max_users: u32,
    pub active_users: u32,
    pub modules: Vec<String>,
    pub binding_mode: String,
}

pub struct Engine {
    connection: Mutex<Connection>,
    pub claims: Claims,
    device: Arc<dyn Device>,
    allow_dev: bool,
}

impl Engine {
    pub fn open(
        path: &Path,
        claims: Claims,
        device: Arc<dyn Device>,
        allow_dev: bool,
        initialize: bool,
        now: i64,
    ) -> Result<Self> {
        license::check_binding(
            &claims,
            device.as_ref(),
            allow_dev,
            &claims.organization_id,
            &claims.product_id,
            now,
        )?;
        if !path.exists() && !initialize {
            return Err(Error::StateMissing);
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY CHECK(id=1), license_id TEXT NOT NULL,
                revision INTEGER NOT NULL, digest TEXT NOT NULL, high_time INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leases (
                lease_id TEXT PRIMARY KEY, subject TEXT NOT NULL, session TEXT NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, token TEXT NOT NULL,
                revision INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS lease_expiry ON leases(expires_at, subject);
            CREATE INDEX IF NOT EXISTS lease_session ON leases(subject, session);
            CREATE TABLE IF NOT EXISTS requests (
                request_id TEXT PRIMARY KEY, subject TEXT NOT NULL,
                fingerprint TEXT NOT NULL, token TEXT NOT NULL, expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS request_expiry ON requests(expires_at);
            CREATE INDEX IF NOT EXISTS request_subject ON requests(subject);
        ",
        )?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = metadata(&tx)?;
        let digest = license::claims_digest(&claims)?;
        match old {
            None if !initialize => return Err(Error::StateMissing),
            None => {
                tx.execute(
                    "INSERT INTO metadata VALUES(1,?1,?2,?3,?4)",
                    params![claims.license_id, claims.revision as i64, digest, now],
                )?;
            }
            Some((id, revision, old_digest, high_time)) => {
                if id != claims.license_id
                    || revision > claims.revision as i64
                    || (revision == claims.revision as i64 && old_digest != digest)
                {
                    return Err(Error::Revision);
                }
                if now < high_time - CLOCK_TOLERANCE {
                    return Err(Error::Clock);
                }
                tx.execute(
                    "UPDATE metadata SET revision=?1,digest=?2,high_time=?3 WHERE id=1",
                    params![claims.revision as i64, digest, now.max(high_time)],
                )?;
            }
        }
        tx.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
            claims,
            device,
            allow_dev,
        })
    }

    fn with_state<T>(
        &self,
        principal: &Principal,
        now: i64,
        f: impl FnOnce(&Transaction<'_>, i64) -> Result<T>,
    ) -> Result<T> {
        if principal.organization != self.claims.organization_id
            || !license::valid_id(&principal.subject)
        {
            return Err(Error::Unauthorized);
        }
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| Error::Device("state lock poisoned".into()))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (id, revision, digest, high_time) = metadata(&tx)?.ok_or(Error::StateMissing)?;
        if id != self.claims.license_id
            || revision != self.claims.revision as i64
            || digest != license::claims_digest(&self.claims)?
        {
            return Err(Error::Revision);
        }
        if now < high_time - CLOCK_TOLERANCE {
            return Err(Error::Clock);
        }
        let effective = now.max(high_time);
        license::check_binding(
            &self.claims,
            self.device.as_ref(),
            self.allow_dev,
            &principal.organization,
            &self.claims.product_id,
            effective,
        )?;
        tx.execute("UPDATE metadata SET high_time=?1 WHERE id=1", [effective])?;
        tx.execute("DELETE FROM requests WHERE expires_at<=?1", [effective])?;
        tx.execute("DELETE FROM leases WHERE expires_at<=?1", [effective])?;
        let result = f(&tx, effective)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn acquire(
        &self,
        p: &Principal,
        request: &str,
        session: &str,
        modules: &[String],
        now: i64,
    ) -> Result<LeaseToken> {
        if !license::valid_id(request) || !license::valid_id(session) {
            return Err(Error::Invalid("invalid request/session id".into()));
        }
        let modules = normalized_modules(modules, &self.claims)?;
        let fingerprint =
            request_fingerprint(&("acquire", &p.organization, &p.subject, session, &modules))?;
        self.with_state(p, now, |tx, now| {
            request_timestamp(request, now)?;
            if let Some(token) = retry(tx, request, p, &fingerprint)? {
                self.check_persisted(tx, p, &token, now)?; return Ok(token);
            }
            check_request_budget(tx, p)?;
            self.ensure_capacity(&active_users(tx, now)?, &p.subject)?;
            let previous: Option<(String, i64, i64)> = tx.query_row(
                "SELECT lease_id,revision,issued_at FROM leases WHERE subject=?1 AND session=?2 AND expires_at>?3",
                params![p.subject, session, now], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let seat_since = if let Some((id, revision, since)) = previous {
                if revision >= self.claims.revision as i64 { return Err(Error::RequestConflict); }
                tx.execute("DELETE FROM leases WHERE lease_id=?1", [id])?;
                since
            } else { now };
            let sessions: i64 = tx.query_row("SELECT COUNT(*) FROM leases WHERE subject=?1 AND expires_at>?2", params![p.subject, now], |r| r.get(0))?;
            if sessions >= MAX_SESSIONS { return Err(Error::SessionLimit); }
            let claims = LeaseClaims {
                lease_id: uuid::Uuid::new_v4().to_string(), license_id: self.claims.license_id.clone(), revision: self.claims.revision,
                organization_id: p.organization.clone(), subject: p.subject.clone(), session_id: session.into(), allowed_modules: modules,
                issued_at: now, expires_at: (now + LEASE_TTL).min(self.claims.expiration_date),
            };
            let token = lease::sign_token(&claims, self.device.as_ref())?;
            tx.execute("INSERT INTO leases VALUES(?1,?2,?3,?4,?5,?6,?7)", params![claims.lease_id, p.subject, session, seat_since, claims.expires_at, serde_json::to_string(&token)?, self.claims.revision as i64])?;
            remember(tx, request, p, &fingerprint, &token, now)?; Ok(token)
        })
    }

    pub fn renew(
        &self,
        p: &Principal,
        request: &str,
        lease_id: &str,
        session: &str,
        now: i64,
    ) -> Result<LeaseToken> {
        if !license::valid_id(request)
            || !license::valid_id(session)
            || !license::valid_id(lease_id)
        {
            return Err(Error::Invalid("invalid renewal id".into()));
        }
        let fingerprint =
            request_fingerprint(&("renew", &p.organization, &p.subject, lease_id, session))?;
        self.with_state(p, now, |tx, now| {
            request_timestamp(request, now)?;
            if let Some(token) = retry(tx, request, p, &fingerprint)? {
                self.check_persisted(tx, p, &token, now)?;
                return Ok(token);
            }
            check_request_budget(tx, p)?;
            let raw: String = tx
                .query_row(
                    "SELECT token FROM leases WHERE lease_id=?1",
                    [lease_id],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Error::LeaseInvalid)?;
            let token: LeaseToken = serde_json::from_str(&raw)?;
            let mut claims = self.check_persisted(tx, p, &token, now)?;
            if claims.session_id != session {
                return Err(Error::Unauthorized);
            }
            claims.issued_at = now;
            claims.expires_at = (now + LEASE_TTL).min(self.claims.expiration_date);
            let token = lease::sign_token(&claims, self.device.as_ref())?;
            tx.execute(
                "UPDATE leases SET expires_at=?1,token=?2 WHERE lease_id=?3",
                params![claims.expires_at, serde_json::to_string(&token)?, lease_id],
            )?;
            remember(tx, request, p, &fingerprint, &token, now)?;
            Ok(token)
        })
    }

    fn check_persisted(
        &self,
        tx: &Transaction<'_>,
        p: &Principal,
        token: &LeaseToken,
        now: i64,
    ) -> Result<LeaseClaims> {
        let claims = lease::verify_token(token, &self.claims, now)?;
        if claims.subject != p.subject || claims.organization_id != p.organization {
            return Err(Error::Unauthorized);
        }
        let saved: Option<String> = tx
            .query_row(
                "SELECT token FROM leases WHERE lease_id=?1 AND expires_at>?2",
                params![claims.lease_id, now],
                |r| r.get(0),
            )
            .optional()?;
        if saved != Some(serde_json::to_string(token)?) {
            return Err(Error::LeaseInvalid);
        }
        if !active_users(tx, now)?
            .iter()
            .take(self.claims.max_users as usize)
            .any(|s| s == &p.subject)
        {
            return Err(Error::Limit);
        }
        Ok(claims)
    }

    fn ensure_capacity(&self, users: &[String], subject: &str) -> Result<()> {
        match users.iter().position(|s| s == subject) {
            Some(index) if index < self.claims.max_users as usize => Ok(()),
            None if users.len() < self.claims.max_users as usize => Ok(()),
            _ => Err(Error::Limit),
        }
    }

    pub fn validate(
        &self,
        p: &Principal,
        token: &LeaseToken,
        module: &str,
        now: i64,
    ) -> Result<LeaseClaims> {
        self.with_state(p, now, |tx, now| {
            let claims = self.check_persisted(tx, p, token, now)?;
            if !claims.allowed_modules.iter().any(|m| m == module) {
                return Err(Error::ModuleDenied);
            }
            Ok(claims)
        })
    }

    pub fn status(&self, p: &Principal, now: i64) -> Result<Status> {
        self.with_state(p, now, |tx, now| {
            Ok(Status {
                license_id: self.claims.license_id.clone(),
                revision: self.claims.revision,
                expiration_date: self.claims.expiration_date,
                max_users: self.claims.max_users,
                active_users: active_users(tx, now)?.len() as u32,
                modules: self.claims.allowed_modules.clone(),
                binding_mode: self.claims.binding_mode.clone(),
            })
        })
    }
}

type Metadata = (String, i64, String, i64);
fn metadata(tx: &Transaction<'_>) -> Result<Option<Metadata>> {
    Ok(tx
        .query_row(
            "SELECT license_id,revision,digest,high_time FROM metadata WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?)
}
fn normalized_modules(modules: &[String], license: &Claims) -> Result<Vec<String>> {
    if modules.is_empty()
        || modules.len() > 128
        || modules.iter().any(|m| !license.allowed_modules.contains(m))
    {
        return Err(Error::ModuleDenied);
    }
    let mut result = modules.to_vec();
    result.sort();
    result.dedup();
    Ok(result)
}
fn request_fingerprint(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
fn retry(
    tx: &Transaction<'_>,
    request: &str,
    p: &Principal,
    fingerprint: &str,
) -> Result<Option<LeaseToken>> {
    let old: Option<(String, String, String)> = tx
        .query_row(
            "SELECT subject,fingerprint,token FROM requests WHERE request_id=?1",
            [request],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    match old {
        None => Ok(None),
        Some((subject, saved, token)) if subject == p.subject && saved == fingerprint => {
            Ok(Some(serde_json::from_str(&token)?))
        }
        Some(_) => Err(Error::RequestConflict),
    }
}
fn remember(
    tx: &Transaction<'_>,
    request: &str,
    p: &Principal,
    fingerprint: &str,
    token: &LeaseToken,
    now: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO requests VALUES(?1,?2,?3,?4,?5)",
        params![
            request,
            p.subject,
            fingerprint,
            serde_json::to_string(token)?,
            request_timestamp(request, now)? + REQUEST_WINDOW
        ],
    )?;
    Ok(())
}

fn request_timestamp(request: &str, now: i64) -> Result<i64> {
    let (timestamp, nonce) = request
        .split_once(':')
        .ok_or_else(|| Error::Invalid("request id must be unix_seconds:nonce".into()))?;
    let timestamp: i64 = timestamp
        .parse()
        .map_err(|_| Error::Invalid("request timestamp".into()))?;
    if !license::valid_id(nonce)
        || timestamp < 0
        || timestamp <= now - REQUEST_WINDOW
        || timestamp > now + CLOCK_TOLERANCE
    {
        return Err(Error::Invalid("request id outside retry window".into()));
    }
    Ok(timestamp)
}
fn check_request_budget(tx: &Transaction<'_>, p: &Principal) -> Result<()> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM requests WHERE subject=?1",
        [&p.subject],
        |r| r.get(0),
    )?;
    if count >= MAX_REQUESTS_PER_SUBJECT {
        return Err(Error::RateLimit);
    }
    Ok(())
}
fn active_users(tx: &Transaction<'_>, now: i64) -> Result<Vec<String>> {
    let mut statement = tx.prepare("SELECT subject FROM leases WHERE expires_at>?1 GROUP BY subject ORDER BY MIN(issued_at), subject")?;
    let rows = statement.query_map([now], |r| r.get(0))?;
    Ok(rows.collect::<std::result::Result<Vec<String>, _>>()?)
}
