#[cfg(test)]
mod test {
    use async_graphql::InputType;
    // use serde_json::json;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    use vector_core::event::{Metric, MetricKind, MetricValue, StatisticKind};
    use vector_core::metric_tags;

    use crate::event::LogEvent;
    use crate::test_util::components::assert_transform_compliance;
    use crate::transforms::stream_analytics::*;
    use crate::transforms::test::create_topology;

    // use vrl::value::Kind;

    // use lookup::owned_value_path;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<StreamAnalyticsConfig>();
    }

        #[tokio::test]
    async fn config_defaults() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"

            "#,
        );

        match config {
            Ok(conf) => {
                assert_eq!(conf.max_events, 1_000_000);
                assert_eq!(conf.calculators.unwrap().len(), 3);
                assert_eq!(conf.error_rate, 0.005);

            },
            Err(_err) => unreachable!("Should not fail."),
        }
    }

    // fn default_ssa_message(size_quantiles: bool) -> LogEvent {
    //     let mut e_1 = LogEvent::default();
    //     e_1.insert("group_by", Value::from(BTreeMap::new()));
    //     e_1.insert("cardinality", Value::from(BTreeMap::new()));
    //     let mut summary = BTreeMap::new();
    //     summary.insert("events_processed".to_string(), Value::from(0));
    //     e_1.insert("stats_summary", Value::from(summary));
    //     if size_quantiles {
    //         e_1.insert("size_quantiles", Value::from(BTreeMap::new()));
    //     }
    //     e_1.insert("top_n", Value::from(BTreeMap::new()));
    //     e_1
    // }

    #[tokio::test]
    async fn ssa_for_default_fields() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
quantiles = [0.99]
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");
            e_5.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();

            assert_eq!(output_1.get(".size_quantiles").is_some(), true);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "5");

            // println!("cardinality = {:?}", output_1.get("cardinality").unwrap().to_string_lossy().to_string());

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 5.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1,\"4\":1,\"5\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_1.get("top_n.field_4").is_some(), true);

            // println!("size_quantiles = {:?}", output_1.get("size_quantiles").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("size_quantiles.field_1").is_some(), true);
            assert!(output_1.get("size_quantiles.field_2.percent_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 2.0 <= 0.9999);
            assert!(output_1.get("size_quantiles.field_2.raw_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 3.0 <= 0.9);

            assert_eq!(output_1.get("size_quantiles.field_3").is_some(), true);
            assert!(output_1.get("size_quantiles.field_4.percent_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 6.0 <= 0.9999);
            assert!(output_1.get("size_quantiles.field_4.raw_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 8.0 <= 0.9);

            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(true));
            assert_eq!(out.recv().await, None);

        })
            .await;
    }

    #[tokio::test]
    async fn ssa_no_size_quantiles() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
quantiles = [0.99]
calculators = [ "top_n", "cardinality"]
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");
            e_5.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();

            assert_eq!(output_1.get(".size_quantiles").is_some(), false);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "5");

            // println!("cardinality = {:?}", output_1.get("cardinality").unwrap().to_string_lossy().to_string());

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 5.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1,\"4\":1,\"5\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_1.get("top_n.field_4").is_some(), true);

            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(false));
            assert_eq!(out.recv().await, None);

        })
            .await;
    }

    #[tokio::test]
    async fn ssa_combine_fields() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 6
quantiles = [0.99]
max_top_n_values = 8
calculators = [ "top_n", "cardinality"]
combine_by_fields = {"combined_field" = ["field_1", "field_2"], "combined_field2" = ["field_1", "field_2.inside.leaf"] }
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");
            e_1.insert("field_2.inside.leaf", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_2.insert("field_2.inside.leaf", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_2.inside.leaf", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");

            e_5.insert("field_4", "value1");

            let mut e_6 = LogEvent::from("test message 6");
            e_6.insert("field_1", 6);
            e_6.insert("field_2", "2");
            e_6.insert("field_2.inside.leaf", "2");

            e_6.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into(), e_6.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();
            println!("output_1 = {}", output_1.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_1.get(".size_quantiles").is_some(), false);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "6");

            // println!("cardinality = {:?}", output_1.get("cardinality").unwrap().to_string_lossy().to_string());

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 6.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.combined_field"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.combined_field2"].as_float().unwrap().as_ref() - 4.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1,\"4\":1,\"5\":1,\"6\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_1.get("top_n.field_4").is_some(), true);
            assert_eq!(output_1.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"1\":2,\"2\":2}");
            assert_eq!(output_1.get("top_n.combined_field").unwrap().to_string_lossy(), "{\"3#~#1\":1,\"5#~#2\":1}");
            assert_eq!(output_1.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"1#~#1\":1,\"2#~#2\":1,\"4#~#1\":1,\"6#~#2\":1}");


            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(false));
            assert_eq!(out.recv().await, None);
        })
            .await;
    }

    #[tokio::test]
    async fn ssa_group_by_fields() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 3
flush_period_ms = 1000
quantiles = [0.99]
max_top_n_values = 8
calculators = [ "top_n", "cardinality"]
group_by = ["field_3", "field_4"]
skip_fields = ["_ob", "time", "date"]
combine_by_fields = {"combined_field" = ["field_1", "field_2"], "combined_field2" = ["field_1", "field_2.inside.leaf"] }
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("_ob", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");
            e_1.insert("field_2.inside.leaf", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_2.insert("field_2.inside.leaf", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_9._ob.source", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_2.inside.leaf", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");

            e_5.insert("field_4", "value1");

            let mut e_6 = LogEvent::from("test message 6");
            e_6.insert("field_1", 6);
            e_6.insert("field_2", "2");
            e_6.insert("field_2.inside.leaf", "2");
            e_6.insert("field_3", "yep");

            e_6.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();
            println!("output_1 = {}", output_1.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_1.get(".size_quantiles").is_some(), false);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.contains("cardinality.\"field_9._ob.source\""), true);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "3");

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 3.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert_eq!(output_1.get("cardinality.field_3"), None);
            assert_eq!(output_1.get("cardinality.field_4"), None);
            assert!(output_1["cardinality.combined_field"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.combined_field2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3"), None);
            assert_eq!(output_1.get("top_n.field_4"), None);
            assert_eq!(output_1.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1}");
            assert_eq!(output_1.get("top_n.combined_field").unwrap().to_string_lossy(), "{\"3#~#1\":1}");
            assert_eq!(output_1.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"1#~#1\":1,\"2#~#2\":1}");

            assert_eq!(output_1.get("group_by").is_some(), true);
            assert_eq!(output_1.get("group_by.field_3").unwrap().to_string_lossy(), "<null>");
            assert_eq!(output_1.get("group_by.field_4").unwrap().to_string_lossy(), "<null>");

            tx.send(e_4.into()).await.unwrap();
            let output_2 = out.recv().await.unwrap().into_log();
            println!("output_2 = {}", output_2.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_2.get(".size_quantiles").is_some(), false);
            assert_eq!(output_2.get(".top_n").is_some(), true);
            assert_eq!(output_2.get(".cardinality").is_some(), true);
            assert_eq!(output_2.get(".stats_summary").is_some(), true);

            assert_eq!(output_2.get("cardinality.time"), None);
            assert_eq!(output_2.get("cardinality.date"), None);
            assert_eq!(output_2.get("top_n.time"), None);
            assert_eq!(output_2.get("top_n.date"), None);
            assert_eq!(output_2.get("stats_summary.events_processed").unwrap().to_string_lossy(), "1");

            assert!(output_2["cardinality.field_1"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_2["cardinality.\"field_2.inside.leaf\""].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_2["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            assert_eq!(output_2.get("cardinality.field_4"), None);
            assert_eq!(output_2.get("cardinality.combined_field"), None);
            assert!(output_2["cardinality.combined_field2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_2.get("top_n.field_1").unwrap().to_string_lossy(), "{\"4\":1}");
            assert_eq!(output_2.get("top_n.field_2").is_some(), false);
            assert_eq!(output_2.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_2.get("top_n.field_4"), None);
            assert_eq!(output_2.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"1\":1}");
            assert_eq!(output_2.get("top_n.combined_field"), None);
            assert_eq!(output_2.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"4#~#1\":1}");

            assert_eq!(output_2.get("group_by").is_some(), true);
            assert_eq!(output_2.get("group_by.field_3").unwrap().to_string_lossy(), "yep");
            assert_eq!(output_2.get("group_by.field_4").unwrap().to_string_lossy(), "<null>");


            tx.send(e_5.into()).await.unwrap();
            let output_3 = out.recv().await.unwrap().into_log();
            println!("output_3 = {}", output_3.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_3.get(".size_quantiles").is_some(), false);
            assert_eq!(output_3.get(".top_n").is_some(), true);
            assert_eq!(output_3.get(".cardinality").is_some(), true);
            assert_eq!(output_3.get(".stats_summary").is_some(), true);

            assert_eq!(output_3.get("cardinality.time"), None);
            assert_eq!(output_3.get("cardinality.date"), None);
            assert_eq!(output_3.get("top_n.time"), None);
            assert_eq!(output_3.get("top_n.date"), None);
            assert_eq!(output_3.get("stats_summary.events_processed").unwrap().to_string_lossy(), "1");

            assert!(output_3["cardinality.field_1"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_3["cardinality.field_2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_3["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            assert_eq!(output_3.get("cardinality.field_3"), None);
            assert_eq!(output_3.get("cardinality.combined_field2"), None);
            assert!(output_3["cardinality.combined_field"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_3.get("top_n.field_1").unwrap().to_string_lossy(), "{\"5\":1}");
            assert_eq!(output_3.get("top_n.field_2").is_some(), true);
            assert_eq!(output_3.get("top_n.field_4").unwrap().to_string_lossy(), "{\"value1\":1}");
            assert_eq!(output_3.get("top_n.field_3"), None);
            assert_eq!(output_3.get("top_n.\"field_2.inside.leaf\""), None);
            assert_eq!(output_3.get("top_n.combined_field2"), None);
            assert_eq!(output_3.get("top_n.combined_field").unwrap().to_string_lossy(), "{\"5#~#2\":1}");

            assert_eq!(output_3.get("group_by").is_some(), true);
            assert_eq!(output_3.get("group_by.field_4").unwrap().to_string_lossy(), "value1");
            assert_eq!(output_3.get("group_by.field_3").unwrap().to_string_lossy(), "<null>");

            tx.send(e_6.into()).await.unwrap();
            let output_4 = out.recv().await.unwrap().into_log();
            println!("output_4 = {}", output_4.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_4.get(".size_quantiles").is_some(), false);
            assert_eq!(output_4.get(".top_n").is_some(), true);
            assert_eq!(output_4.get(".cardinality").is_some(), true);
            assert_eq!(output_4.get(".stats_summary").is_some(), true);

            assert_eq!(output_4.get("cardinality.time"), None);
            assert_eq!(output_4.get("cardinality.date"), None);
            assert_eq!(output_4.get("top_n.time"), None);
            assert_eq!(output_4.get("top_n.date"), None);
            assert_eq!(output_4.get("stats_summary.events_processed").unwrap().to_string_lossy(), "1");

            assert!(output_4["cardinality.field_1"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert_eq!(output_4.get("cardinality.field_2"), None);
            assert!(output_4["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_4["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert_eq!(output_4.get("cardinality.combined_field"), None);
            assert!(output_4["cardinality.combined_field2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_4.get("top_n.field_1").unwrap().to_string_lossy(), "{\"6\":1}");
            assert_eq!(output_4.get("top_n.field_2").is_some(), false);
            assert_eq!(output_4.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_4.get("top_n.field_4").unwrap().to_string_lossy(), "{\"value1\":1}");
            assert_eq!(output_4.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"2\":1}");
            assert_eq!(output_4.get("top_n.combined_field"), None);
            assert_eq!(output_4.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"6#~#2\":1}");

            assert_eq!(output_4.get("group_by").is_some(), true);
            assert_eq!(output_4.get("group_by.field_3").unwrap().to_string_lossy(), "yep");
            assert_eq!(output_4.get("group_by.field_4").unwrap().to_string_lossy(), "value1");

            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(false));
            assert_eq!(out.recv().await, None);
        })
            .await;
    }

    #[tokio::test]
    async fn ssa_default_sanitised_config() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
"#,
        )
            .unwrap();

        let sanitised_config = StreamAnalyticsSanitisedConfig::new(&config)
            .expect("Can't fail in sanitised config creation.");
        assert_eq!(sanitised_config.calculators.unwrap()
                   , vec![ Calculator::TopN, Calculator::Cardinality, Calculator::SizeQuantile ]);
        assert_eq!(sanitised_config.skip_fields
                   , vec!["time".to_string(), "timestamp".to_string(), "date".to_string(), "datetime".to_string()]);
        assert_eq!(sanitised_config.max_events, 5);
        assert_eq!(sanitised_config.flush_period, Duration::from_millis(300000));
        assert_eq!(sanitised_config.quantiles, vec![0.5, 0.75, 0.9, 0.95, 0.99]);
        assert_eq!(sanitised_config.max_processing_limit, 256);
        assert_eq!(sanitised_config.max_top_n_labels, 16);
        assert_eq!(sanitised_config.max_top_n_values, 5);

    }

    #[tokio::test]
    async fn ssa_check_limits_sanitised_config() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
max_top_n_labels = 3280
max_processing_limit = 2000
max_top_n_values = 33
"#,
        )
            .unwrap();

        let sanitised_config = StreamAnalyticsSanitisedConfig::new(&config)
            .expect("Can't fail in sanitised config creation.");
        assert_eq!(sanitised_config.calculators.unwrap()
                   , vec![ Calculator::TopN, Calculator::Cardinality, Calculator::SizeQuantile ]);
        assert_eq!(sanitised_config.skip_fields
                   , vec!["time".to_string(), "timestamp".to_string(), "date".to_string(), "datetime".to_string()]);
        assert_eq!(sanitised_config.max_events, 5);
        assert_eq!(sanitised_config.flush_period, Duration::from_millis(300000));
        assert_eq!(sanitised_config.quantiles, vec![0.5, 0.75, 0.9, 0.95, 0.99]);
        assert_eq!(sanitised_config.max_processing_limit, 1024);
        assert_eq!(sanitised_config.max_top_n_labels, 1024);
        assert_eq!(sanitised_config.max_top_n_values, 32);

    }

    fn get_test_metrics() -> Vec<Event> {
        let m1 = Metric::new(
            "counter",
            MetricKind::Absolute,
            MetricValue::Counter { value: 1.0 },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                }));

        let m2 = Metric::new(
            "counter",
            MetricKind::Absolute,
            MetricValue::Counter { value: 1.0 },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                    "set_tag" => "tag_v1",
                    "set_tag" => "tag_v2",
                    "set_tag" => "tag_v3",
                }));

        let m3 = Metric::new(
            "gauge",
            MetricKind::Absolute,
            MetricValue::Gauge { value: 1.0 },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                }));

        let m4 = Metric::new(
            "gauge",
            MetricKind::Absolute,
            MetricValue::Gauge { value: 1.0 },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                    "set_tag" => "tag_v1",
                    "set_tag" => "tag_v2",
                    "set_tag" => "tag_v3",
                }));

        let m5 = Metric::new(
            "set",
            MetricKind::Absolute,
            MetricValue::Set {
                values: vec!["one".into(), "two".into()].into_iter().collect(),
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                }));

        let m6 = Metric::new(
            "set",
            MetricKind::Absolute,
            MetricValue::Set {
                values: vec!["one".into(), "two".into()].into_iter().collect(),
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                    "set_tag" => "tag_v1",
                    "set_tag" => "tag_v2",
                    "set_tag" => "tag_v3",
                }));

        let m7 = Metric::new(
            "distro",
            MetricKind::Absolute,
            MetricValue::Distribution {
                samples: vector_core::samples![1.0 => 10, 2.0 => 20],
                statistic: StatisticKind::Histogram,
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                }));

        let m8 = Metric::new(
            "distro",
            MetricKind::Absolute,
            MetricValue::Distribution {
                samples: vector_core::samples![1.0 => 10, 2.0 => 20],
                statistic: StatisticKind::Histogram,
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                    "set_tag" => "tag_v1",
                    "set_tag" => "tag_v2",
                    "set_tag" => "tag_v3",
                }));

        let m9 = Metric::new(
            "histo",
            MetricKind::Absolute,
            MetricValue::AggregatedHistogram {
                buckets: vector_core::buckets![1.0 => 10, 2.0 => 20],
                count: 30,
                sum: 50.0,
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                }));

        let m10 = Metric::new(
            "histo",
            MetricKind::Absolute,
            MetricValue::AggregatedHistogram {
                buckets: vector_core::buckets![1.0 => 10, 2.0 => 20],
                count: 30,
                sum: 50.0,
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                    "set_tag" => "tag_v1",
                    "set_tag" => "tag_v2",
                    "set_tag" => "tag_v3",
                }));

        let m11 = Metric::new(
            "summary",
            MetricKind::Absolute,
            MetricValue::AggregatedSummary {
                quantiles: vector_core::quantiles![50.0 => 10.0, 90.0 => 20.0],
                count: 30,
                sum: 50.0,
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                }));

        let m12 = Metric::new(
            "summary",
            MetricKind::Absolute,
            MetricValue::AggregatedSummary {
                quantiles: vector_core::quantiles![50.0 => 10.0, 90.0 => 20.0],
                count: 30,
                sum: 50.0,
            },
        )
            .with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
                    "set_tag" => "tag_v1",
                    "set_tag" => "tag_v2",
                    "set_tag" => "tag_v3",
                }));

        vec![
            Event::from(m1), Event::from(m2),
            Event::from(m3), Event::from(m4),
            Event::from(m5), Event::from(m6),
            Event::from(m7), Event::from(m8),
            Event::from(m9), Event::from(m10),
            Event::from(m11), Event::from(m12),
        ]
    }


    #[tokio::test]
    async fn ssa_metric_for_default_fields() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
    max_events = 12
    quantiles = [0.99]
    "#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            // 1st set is skipped to build in top_n metric set
            for event in get_test_metrics() {
                tx.send(event).await.unwrap();
            };
            tx.send(Event::from(Metric::new(
                "counter_noop",
                MetricKind::Absolute,
                MetricValue::Counter { value: 1.0 },
            ).with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
            })))).await.unwrap();


            // in total this test should process only 6 events
            for event in get_test_metrics() {
                tx.send(event).await.unwrap();
            };

            let mut output: HashMap<String, LogEvent> = HashMap::new();
            for _i in 0..6 {
                let out_log = out.recv().await.unwrap().into_log();
                // println!("{:?}", out_log);
                output.insert(out_log.get("group_by.metric_name").unwrap().to_string_lossy().to_string(), out_log);
            }
            // println!("{:?}", output);

            output.iter().for_each(|(_metric_name, log)| {
                assert_eq!(log.get(".size_quantiles").is_some(), false);
                assert_eq!(log.get(".top_n").is_some(), true);
                assert_eq!(log.get(".cardinality").is_some(), true);
                assert_eq!(log.get(".stats_summary").is_some(), true);
                assert_eq!(log.get("stats_summary.events_processed").unwrap().to_string_lossy(), "2");

                assert!(log["cardinality.host"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
                assert!(log["cardinality.some_tag"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
                assert!(log["cardinality.set_tag"].as_float().unwrap().as_ref() - 3.0 <= 0.005);

                assert_eq!(log.get("top_n.host").unwrap().to_string_lossy(), "{\"localhost\":2}");
                assert_eq!(log.get("top_n.some_tag").unwrap().to_string_lossy(), "{\"some_value\":2}");
                assert_eq!(log.get("top_n.set_tag").unwrap().to_string_lossy(), "{\"tag_v1\":1,\"tag_v2\":1,\"tag_v3\":1}");
            });

            assert_eq!(output.len(), 6);

            vec!["counter", "gauge", "set", "distro", "histo", "summary"].iter().for_each(|metric_name| {
                assert_eq!(output.contains_key(*metric_name), true);
            });

            drop(tx);
            topology.stop().await;
            assert_eq!(out.recv().await, None);
        })
            .await;
    }

    #[tokio::test]
    async fn ssa_metric_for_limited_top_metric() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
    max_events = 12
    max_top_metrics = 2
    quantiles = [0.99]
    "#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let send_metrics = get_test_metrics();

            // 1st set is skipped to build in top_n metric set
            tx.send(send_metrics[0].clone()).await.unwrap();
            tx.send(send_metrics[0].clone()).await.unwrap();
            tx.send(send_metrics[1].clone()).await.unwrap();
            tx.send(send_metrics[1].clone()).await.unwrap();

            tx.send(send_metrics[2].clone()).await.unwrap();
            tx.send(send_metrics[2].clone()).await.unwrap();
            tx.send(send_metrics[3].clone()).await.unwrap();
            tx.send(send_metrics[3].clone()).await.unwrap();

            tx.send(send_metrics[4].clone()).await.unwrap();
            tx.send(send_metrics[6].clone()).await.unwrap();
            tx.send(send_metrics[8].clone()).await.unwrap();
            tx.send(send_metrics[10].clone()).await.unwrap();

            tx.send(Event::from(Metric::new(
                "counter_noop",
                MetricKind::Absolute,
                MetricValue::Counter { value: 1.0 },
            ).with_tags(Some(metric_tags! {
                    "host" => "localhost",
                    "some_tag" => "some_value",
            })))).await.unwrap();

            // in total this test should process only 6 events
            for event in get_test_metrics() {
                tx.send(event).await.unwrap();
            };

            let mut output: HashMap<String, LogEvent> = HashMap::new();
            for _i in 0..2 {
                let out_log = out.recv().await.unwrap().into_log();
                println!("{:?}", out_log);
                output.insert(out_log.get("group_by.metric_name").unwrap().to_string_lossy().to_string(), out_log);
            }
            // println!("{:?}", output);

            output.iter().for_each(|(_metric_name, log)| {
                assert_eq!(log.get(".size_quantiles").is_some(), false);
                assert_eq!(log.get(".top_n").is_some(), true);
                assert_eq!(log.get(".cardinality").is_some(), true);
                assert_eq!(log.get(".stats_summary").is_some(), true);
                assert_eq!(log.get("stats_summary.events_processed").unwrap().to_string_lossy(), "2");

                assert!(log["cardinality.host"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
                assert!(log["cardinality.some_tag"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
                assert!(log["cardinality.set_tag"].as_float().unwrap().as_ref() - 3.0 <= 0.005);

                assert_eq!(log.get("top_n.host").unwrap().to_string_lossy(), "{\"localhost\":2}");
                assert_eq!(log.get("top_n.some_tag").unwrap().to_string_lossy(), "{\"some_value\":2}");
                assert_eq!(log.get("top_n.set_tag").unwrap().to_string_lossy(), "{\"tag_v1\":1,\"tag_v2\":1,\"tag_v3\":1}");
            });

            assert_eq!(output.len(), 2);

            vec!["counter", "gauge"].iter().for_each(|metric_name| {
                assert_eq!(output.contains_key(*metric_name), true);
            });

            vec!["set", "distro", "histo", "summary"].iter().for_each(|metric_name| {
                assert_eq!(output.contains_key(*metric_name), false);
            });

            drop(tx);
            topology.stop().await;
            assert_eq!(out.recv().await, None);
        })
            .await;
    }
}
