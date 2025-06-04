/// This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
/// Proprietary and Confidential – © 2025 Observo Inc.
/// Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
/// This file is distributed separately and is not subject to the terms of the MPL-2.0.
use crate::config::{
    DataType, Input, LogNamespace, OutputId, TransformConfig, TransformContext, TransformOutput,
};
use crate::schema;
use crate::transforms::Transform;
use std::collections::HashMap;
use vector_lib::enrichment;

#[async_trait::async_trait]
#[typetag::serde(name = "ssa")]
impl TransformConfig for ssa::SsaConfig {
    async fn build(&self, _context: &TransformContext) -> vector_lib::Result<Transform> {
        ssa::ObservoSsa::new(self).map(Transform::event_task)
    }

    fn input(&self) -> Input {
        Input::all()
    }

    fn outputs(
        &self,
        _: enrichment::TableRegistry,
        _: &[(OutputId, schema::Definition)],
        _: LogNamespace,
    ) -> Vec<TransformOutput> {
        vec![TransformOutput::new(DataType::Log, HashMap::new())]
    }
}

#[cfg(test)]
mod test {
    use crate::event::Event;
    use assert_matches::assert_matches;
    use ssa::test_scenarios::{TransformRunner, UnitFuture};
    use std::future::Future;
    use std::sync::Arc;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::{Receiver, Sender};
    use tokio::sync::{mpsc, Mutex};
    use tokio_stream::wrappers::ReceiverStream;
    // use crate::test_util;
    use crate::test_util::components::assert_transform_compliance;
    use crate::transforms::test::create_topology;

    struct RunTest {}

    impl RunTest {
        async fn run_transform<T: Future>(
            config: String,
            func: impl FnOnce(Sender<Event>, Arc<Mutex<Receiver<Event>>>) -> T,
        ) -> T::Output {
            assert_transform_compliance(async move {
                let config: ssa::SsaConfig = toml::from_str(&config).unwrap();
                let (tx, rx) = mpsc::channel(1);
                tracing::trace!("config: {:#?}", config);
                let (topology, out) = create_topology(ReceiverStream::from(rx), config).await;
                tracing::trace!("topology created");

                let out = Arc::new(Mutex::new(out));

                let result = func(tx, Arc::clone(&out)).await;
                tracing::trace!("result generated");
                let mut ch = out.lock().await;
                let evt = ch.try_recv();
                assert_matches!(evt, Err(TryRecvError::Empty));
                drop(ch);
                trace!("Asserted no events were left in the out-queue");
                topology.sources_finished().await;

                topology.stop().await;
                tracing::trace!("topology stopped");

                drop(out);

                result
            })
            .await
        }
    }

    #[async_trait::async_trait]
    impl TransformRunner<UnitFuture> for RunTest {
        async fn run(
            &self,
            config: String,
            func: impl FnOnce(Sender<Event>, Arc<Mutex<Receiver<Event>>>) -> UnitFuture + Send,
        ) -> () {
            Self::run_transform(config, func).await
        }
    }

    #[tokio::test]
    async fn test_ssa_for_default_fields() {
        ssa::test_scenarios::ssa_for_default_fields(RunTest {}).await;
    }

    #[tokio::test]
    async fn test_ssa_group_by_fields() {
        ssa::test_scenarios::ssa_group_by_fields(RunTest {}).await;
    }

    #[tokio::test]
    async fn test_ssa_combine_fields() {
        ssa::test_scenarios::ssa_combine_fields(RunTest {}).await;
    }

    #[tokio::test]
    async fn test_ssa_metric_for_default_fields() {
        ssa::test_scenarios::ssa_metric_for_default_fields(RunTest {}).await;
    }
}
