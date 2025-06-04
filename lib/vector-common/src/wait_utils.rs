use std::{
    fmt::{Debug, Display},
    future::Future,
    time::{Duration, SystemTime},
};
use tokio::time::{self, timeout};

pub const A_BIT: Duration = Duration::from_millis(1000);

#[derive(Clone)]
pub struct Loc {
    file: &'static str,
    line: u32,
}

impl Loc {
    pub fn new(file: &'static str, line: u32) -> Self {
        Loc { file, line }
    }
}

#[macro_export]
macro_rules! loc {
    () => {
        $crate::wait_utils::Loc::new(file!(), line!())
    };
}

impl Display for Loc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

pub async fn await_ok_upto<T, E>(
    loc: Loc,
    dur: Duration,
    f: impl Future<Output = std::result::Result<T, E>>,
) -> T
where
    E: Debug,
{
    match await_upto(loc.clone(), dur, f).await {
        Ok(res) => res,
        Err(e) => panic!("Expected Ok, got Err: {:?} @{}", e, loc),
    }
}

pub async fn await_upto<T>(loc: Loc, dur: Duration, f: impl Future<Output = T>) -> T {
    match timeout(dur, f).await {
        Ok(t) => t,
        Err(_) => {
            let now = SystemTime::now();
            let dt: chrono::DateTime<chrono::Utc> = now.into();
            panic!(
                "Future timed out @{} ({}) (after waiting {}s)",
                loc,
                dt.to_rfc3339(),
                dur.as_secs_f64()
            );
        }
    }
}

pub async fn await_predicate(loc: Loc, dur: Duration, p: impl Fn() -> bool) {
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
        vector_common::wait_utils::await_ok_upto($crate::loc!(), A_BIT, $f).await
    };
    ($f:expr, $t:expr) => {
        vector_common::wait_utils::await_ok_upto($crate::loc!(), $t, $f).await
    };
}

#[macro_export]
macro_rules! await_result {
    ($f:expr, $t:expr) => {
        $crate::wait_utils::await_upto($crate::loc!(), $t, $f).await
    };
    ($f:expr) => {
        await_result!($f, $crate::wait_utils::A_BIT)
    };
}

#[macro_export]
macro_rules! await_predicate {
    ($p:expr, $t:expr) => {
        $crate::wait_utils::await_predicate($crate::loc!(), $t, $p).await
    };
    ($p:expr) => {
        await_predicate!($p, $crate::wait_utils::A_BIT)
    };
}
