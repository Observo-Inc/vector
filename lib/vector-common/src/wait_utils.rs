use std::{fmt::Debug, future::Future, time::{Duration, SystemTime}};
use tokio::time::{self, timeout};

pub const A_BIT: Duration = Duration::from_millis(1000);

pub async fn await_ok_upto<T, E>(loc: String, dur: Duration, f: impl Future<Output = std::result::Result<T, E>>) -> T
where E: Debug {
    match await_upto(loc.clone(), dur, f).await {
        Ok(res) => res,
        Err(e) => panic!("Expected Ok, got Err: {:?} @{}", e, loc),
    }
}

pub async fn await_upto<T>(loc: String, dur: Duration, f: impl Future<Output = T>) -> T {
    match timeout(dur, f).await {
        Ok(t) => t,
        Err(_) => {
            let now = SystemTime::now();
            let dt: chrono::DateTime<chrono::Utc> = now.into();
            panic!("Future timed out @{} ({}) (after waiting {}s)", loc, dt.to_rfc3339(), dur.as_secs_f64());
        },
    }
}

pub async fn await_predicate(loc: String, dur: Duration, p: impl Fn() -> bool) {
    let f = async move {
        while !p() {
            time::sleep(A_BIT / 10).await;
        }
    };
    await_upto(loc, dur, f).await;
}

#[macro_export]
macro_rules! await_ok {
    ($f:expr) => {
        vector_common::wait_utils::await_ok_upto(format!("{}:{}", file!(), line!()), A_BIT, $f).await
    };
    ($f:expr, $t:expr) => {
        vector_common::wait_utils::await_ok_upto(format!("{}:{}", file!(), line!()), $t, $f).await
    };
}

#[macro_export]
macro_rules! await_result {
    ($f:expr, $t:expr) => {
        $crate::wait_utils::await_upto(format!("{}:{}", file!(), line!()), $t, $f).await
    };
    ($f:expr) => {
        await_result!($f, vector_common::wait_utils::A_BIT)
    };
}

#[macro_export]
macro_rules! await_predicate {
    ($p:expr, $t:expr) => {
        $crate::wait_utils::await_predicate(format!("{}:{}", file!(), line!()), $t, $p).await
    };
    ($p:expr) => {
        await_predicate!($p, vector_common::wait_utils::A_BIT)
    };
}
