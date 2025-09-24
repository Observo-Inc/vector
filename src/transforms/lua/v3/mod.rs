/**
This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
Proprietary and Confidential – © 2025 Observo Inc.
Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
This file is distributed separately and is not subject to the terms of the MPL-2.0.
**/
pub use lv3::LuaConfigV3;

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Arc;
    use std::time::Duration;
    use lv3::test_scenarios as s;
    use tokio::sync::mpsc::{self, Receiver, Sender};
    use tokio::sync::Mutex;
    use tokio_stream::wrappers::ReceiverStream;
    use crate::test_util::components::assert_transform_compliance;
    use crate::transforms::test::create_topology;
    use crate::{event::Event, test_util};

    struct RunTest {}

    impl RunTest {
        async fn run_transform<T: Future>(
            config: String,
            func: impl FnOnce(Sender<Event>, Arc<Mutex<Receiver<Event>>>) -> T
        ) -> T::Output {
            test_util::trace_init();
            assert_transform_compliance(async move {
                let config = super::super::LuaConfig::V3(toml::from_str(&config).unwrap());
                let (tx, rx) = mpsc::channel(10);
                let (topology, out) = create_topology(ReceiverStream::from(rx), config).await;

                let out = Arc::new(tokio::sync::Mutex::new(out));

                let result = func(tx, Arc::clone(&out)).await;

                topology.stop().await;
                assert_eq!(out.lock().await.recv().await, None);

                result
            })
            .await
        }
    }

    #[async_trait::async_trait]
    impl s::TransformRunner<s::DurationFuture> for RunTest {
        async fn run(
            &self,
            config: String,
            func: impl FnOnce(Sender<Event>, Arc<Mutex<Receiver<Event>>>) -> s::DurationFuture + Send,
        ) -> Duration {
            Self::run_transform(config, func).await
        }
    }

    #[async_trait::async_trait]
    impl s::TransformRunner<s::UnitFuture> for RunTest {
        async fn run(
            &self,
            config: String,
            func: impl FnOnce(Sender<Event>, Arc<Mutex<Receiver<Event>>>) -> s::UnitFuture + Send,
        ) -> () {
            Self::run_transform(config, func).await
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lua_multi_runtime_test() {
        s::lua_multi_runtime_test(RunTest{}).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lua_single_runtime_test() {
        s::lua_single_runtime_test(RunTest{}).await;
    }

    #[tokio::test]
    async fn lua_trivial_test() {
        s::lua_trivial_test(RunTest{}).await;
    }

    #[tokio::test]
    async fn lua_no_event_test() {
        s::lua_no_event_test(RunTest{}).await;
    }

    #[tokio::test]
    async fn lua_metrics_xform_test() {
        s::lua_metric_xform_test(RunTest{}).await;
    }

    #[tokio::test]
    async fn lua_approx_size_function() {
        s::lua_approx_size_function(RunTest{}).await;
    }
}