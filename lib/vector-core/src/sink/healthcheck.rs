use futures_util::future::BoxFuture;

pub type Healthcheck = BoxFuture<'static, crate::Result<()>>;
