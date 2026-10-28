use crate::error::{Error, Result};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn request_id() -> String {
    format!("{}:{}", unix_now(), uuid::Uuid::new_v4())
}
pub struct Clock {
    wall: i64,
    monotonic: Instant,
}
impl Default for Clock {
    fn default() -> Self {
        Self {
            wall: unix_now(),
            monotonic: Instant::now(),
        }
    }
}
impl Clock {
    pub fn now(&self) -> Result<i64> {
        let wall = unix_now();
        let floor = self.wall + self.monotonic.elapsed().as_secs() as i64;
        if wall < floor - 300 {
            return Err(Error::Clock);
        }
        Ok(wall.max(floor))
    }
}
