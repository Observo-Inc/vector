use super::*;
use crate::event::{LogEvent};
use crate::test_util::components::assert_transform_compliance;
use crate::transforms::test::create_topology;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<HashReplaceConfig>();
}

#[tokio::test]
async fn config_defaults() {
    let config = toml::from_str::<HashReplaceConfig>(
        r#"
                replace_keys= ["test"]
            "#,
    );

    match config {
        Ok(conf) => {
            assert_eq!(conf.max_events, 1_000_000);
            assert_eq!(conf.sample_rate, 100);
            assert_eq!(conf.get_hash_key_name(), "hashes");
        },
        Err(_err) => unreachable!("Should not fail."),
    }
}

#[tokio::test]
async fn check_replace() {
    let config = toml::from_str::<HashReplaceConfig>(
        r#"
            replace_keys = ["field_1"]
            sample_rate = 1000
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
        e_2.insert("date", "good dates");

        let mut e_3 = LogEvent::from("test message 3");
        e_3.insert("field_1", 3);
        e_3.insert("field_2", "1");

        let mut e_4 = LogEvent::from("test message 4");
        e_4.insert("field_1", 1);
        e_4.insert("field_2", "1");
        e_4.insert("field_3", "yep");

        let mut e_5 = LogEvent::from("test message 5");
        e_5.insert("field_1", 1);
        e_5.insert("field_2", "2");
        e_5.insert("field_4", "value1");

        for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
            tx.send(event).await.unwrap();
        };

        let output_1 = out.recv().await.unwrap().into_log();
        let output_2 = out.recv().await.unwrap().into_log();
        let output_3 = out.recv().await.unwrap().into_log();
        let output_4 = out.recv().await.unwrap().into_log();
        let output_5 = out.recv().await.unwrap().into_log();

        for event in vec![output_1.clone(), output_2.clone(), output_3.clone(), output_4.clone(), output_5.clone()] {
            println!("output log = {:?}", event.value().to_string_lossy().to_string());
            assert_eq!(event.get(".hashes").is_some(), true);
            assert_eq!(event.get(".hashes.field_1").is_some(), true);
        }

        assert_eq!(output_1.get(".hashes.field_1"), output_4.get(".hashes.field_1"));
        assert_eq!(output_4.get(".hashes.field_1"), output_5.get(".hashes.field_1"));

        assert_ne!(output_1.get(".hashes.field_1"), output_2.get(".hashes.field_1"));
        assert_ne!(output_2.get(".hashes.field_1"), output_3.get(".hashes.field_1"));
        assert_ne!(output_1.get(".hashes.field_1"), output_3.get(".hashes.field_1"));

        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_2.get(".field_1").is_some()
                && output_3.get(".field_1").is_some()
            , true);

        assert_eq!(
            output_1.get(".field_1").is_some()
            && output_4.get(".field_1").is_some()
            && output_5.get(".field_1").is_some()
            , false);

        drop(tx);
        topology.stop().await;
        // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(true));
        assert_eq!(out.recv().await, None);
    }).await;
}



#[tokio::test]
async fn check_replace_and_flush() {
    let config = toml::from_str::<HashReplaceConfig>(
        r#"
            replace_keys = ["field_1"]
            sample_rate = 1000
            flush_period_ms = 1
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
        e_2.insert("date", "good dates");

        let mut e_3 = LogEvent::from("test message 3");
        e_3.insert("field_1", 3);
        e_3.insert("field_2", "1");

        let mut e_4 = LogEvent::from("test message 4");
        e_4.insert("field_1", 1);
        e_4.insert("field_2", "1");
        e_4.insert("field_3", "yep");

        let mut e_5 = LogEvent::from("test message 5");
        e_5.insert("field_1", 1);
        e_5.insert("field_2", "2");
        e_5.insert("field_4", "value1");

        for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
            tx.send(event).await.unwrap();
        };

        let output_1 = out.recv().await.unwrap().into_log();
        let output_2 = out.recv().await.unwrap().into_log();
        let output_3 = out.recv().await.unwrap().into_log();
        let output_4 = out.recv().await.unwrap().into_log();
        let output_5 = out.recv().await.unwrap().into_log();

        for event in vec![output_1.clone(), output_2.clone(), output_3.clone(), output_4.clone(), output_5.clone()] {
            println!("output log = {:?}", event.value().to_string_lossy().to_string());
            assert_eq!(event.get(".hashes").is_some(), true);
            assert_eq!(event.get(".hashes.field_1").is_some(), true);
        }

        assert_eq!(output_1.get(".hashes.field_1"), output_4.get(".hashes.field_1"));
        assert_eq!(output_4.get(".hashes.field_1"), output_5.get(".hashes.field_1"));

        assert_ne!(output_1.get(".hashes.field_1"), output_2.get(".hashes.field_1"));
        assert_ne!(output_2.get(".hashes.field_1"), output_3.get(".hashes.field_1"));
        assert_ne!(output_1.get(".hashes.field_1"), output_3.get(".hashes.field_1"));

        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_2.get(".field_1").is_some()
                && output_3.get(".field_1").is_some()
            , true);

        // as we flush in 1 ms. One of the output4 or 5 will have field_1=1 again
        assert_eq!(
            output_4.get(".field_1").is_some()
            || output_5.get(".field_1").is_some()
            , true);

        drop(tx);
        topology.stop().await;
        // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(true));
        assert_eq!(out.recv().await, None);
    }).await;
}

#[tokio::test]
async fn check_replace_two_fields() {
    let config = toml::from_str::<HashReplaceConfig>(
        r#"
            replace_keys = ["field_1", "field_2.inside"]
            sample_rate = 1000
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
        e_1.insert("field_2.inside", "inside_1");

        let mut e_2 = LogEvent::from("test message 2");
        e_2.insert("field_1", 2);
        e_2.insert("field_2", "2");
        e_2.insert("field_2.inside", "inside_1");
        e_2.insert("date", "good dates");

        let mut e_3 = LogEvent::from("test message 3");
        e_3.insert("field_1", 3);
        e_3.insert("field_2", "1");
        e_3.insert("field_2.inside", "inside_1");


        let mut e_4 = LogEvent::from("test message 4");
        e_4.insert("field_1", 1);
        e_4.insert("field_2", "1");
        e_4.insert("field_3", "yep");

        let mut e_5 = LogEvent::from("test message 5");
        e_5.insert("field_1", 1);
        e_5.insert("field_2", "2");
        e_5.insert("field_4", "value1");

        for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
            tx.send(event).await.unwrap();
        };

        let output_1 = out.recv().await.unwrap().into_log();
        let output_2 = out.recv().await.unwrap().into_log();
        let output_3 = out.recv().await.unwrap().into_log();
        let output_4 = out.recv().await.unwrap().into_log();
        let output_5 = out.recv().await.unwrap().into_log();

        for event in vec![output_1.clone(), output_2.clone(), output_3.clone(), output_4.clone(), output_5.clone()] {
            println!("output log = {:?}", event.value().to_string_lossy().to_string());
            assert_eq!(event.get(".hashes").is_some(), true);
            assert_eq!(event.get(".hashes.field_1").is_some(), true);
        }

        assert_eq!(output_1.get(".hashes.field_2.inside").is_some(), true);
        assert_eq!(output_2.get(".hashes.field_2.inside").is_some(), true);
        assert_eq!(output_3.get(".hashes.field_2.inside").is_some(), true);

        assert_eq!(output_1.get(".hashes.field_1"), output_4.get(".hashes.field_1"));
        assert_eq!(output_4.get(".hashes.field_1"), output_5.get(".hashes.field_1"));

        assert_eq!(output_1.get(".hashes.field_2.inside"), output_2.get(".hashes.field_2.inside"));
        assert_eq!(output_2.get(".hashes.field_2.inside"), output_3.get(".hashes.field_2.inside"));


        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_2.get(".field_1").is_some()
                && output_3.get(".field_1").is_some()
            , true);

        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_4.get(".field_1").is_some()
                && output_5.get(".field_1").is_some()
            , false);

        assert_eq!(
            output_1.get(".field_2.inside").is_some()
                && output_2.get(".field_2.inside").is_some()
                && output_3.get(".field_2.inside").is_some()
            , false);

        drop(tx);
        topology.stop().await;
        assert_eq!(out.recv().await, None);
    }).await;
}



#[tokio::test]
async fn check_replace_two_fields_nested() {
    let config = toml::from_str::<HashReplaceConfig>(
        r#"
            replace_keys = ["field_1", "field_2"]
            sample_rate = 1000
           "#,
    )
        .unwrap();

    assert_transform_compliance(async move {
        let (tx, rx) = mpsc::channel(1);
        let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

        let mut e_1 = LogEvent::from("test message 1");
        e_1.insert("field_1", 1);
        e_1.insert("time", "good times");
        e_1.insert("field_2.inside", "inside_1");
        e_1.insert("field_2.inside_2", "inside_2");

        let mut e_2 = LogEvent::from("test message 2");
        e_2.insert("field_1", 2);
        e_2.insert("field_2", "2");
        e_2.insert("field_2.inside", "inside_1");
        e_2.insert("field_2.inside_2", "inside_2");
        e_2.insert("date", "good dates");

        let mut e_3 = LogEvent::from("test message 3");
        e_3.insert("field_1", 3);
        e_3.insert("field_2", "1");
        e_3.insert("field_2.inside", "inside_1");
        e_3.insert("field_2.inside_2", "inside_2");

        let mut e_4 = LogEvent::from("test message 4");
        e_4.insert("field_1", 1);
        e_4.insert("field_2", "1");
        e_4.insert("field_3", "yep");

        let mut e_5 = LogEvent::from("test message 5");
        e_5.insert("field_1", 1);
        e_5.insert("field_2", "2");
        e_5.insert("field_4", "value1");

        for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
            tx.send(event).await.unwrap();
        };

        let output_1 = out.recv().await.unwrap().into_log();
        let output_2 = out.recv().await.unwrap().into_log();
        let output_3 = out.recv().await.unwrap().into_log();
        let output_4 = out.recv().await.unwrap().into_log();
        let output_5 = out.recv().await.unwrap().into_log();

        for event in vec![output_1.clone(), output_2.clone(), output_3.clone(), output_4.clone(), output_5.clone()] {
            println!("output log = {:?}", event.value().to_string_lossy().to_string());
            assert_eq!(event.get(".hashes").is_some(), true);
            assert_eq!(event.get(".hashes.field_1").is_some(), true);
        }

        assert_eq!(output_1.get(".hashes.field_2.inside").is_some(), false);
        assert_eq!(output_2.get(".hashes.field_2.inside").is_some(), false);
        assert_eq!(output_3.get(".hashes.field_2.inside").is_some(), false);

        assert_eq!(output_1.get(".hashes.field_2").is_some(), true);
        assert_eq!(output_2.get(".hashes.field_2").is_some(), true);
        assert_eq!(output_3.get(".hashes.field_2").is_some(), true);

        assert_eq!(output_1.get(".hashes.field_1"), output_4.get(".hashes.field_1"));
        assert_eq!(output_4.get(".hashes.field_1"), output_5.get(".hashes.field_1"));

        assert_eq!(output_1.get(".hashes.field_2"), output_2.get(".hashes.field_2"));
        assert_eq!(output_2.get(".hashes.field_2"), output_3.get(".hashes.field_2"));


        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_2.get(".field_1").is_some()
                && output_3.get(".field_1").is_some()
            , true);

        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_4.get(".field_1").is_some()
                && output_5.get(".field_1").is_some()
            , false);

        assert_eq!(
            output_1.get(".field_2").is_some()
                && output_2.get(".field_2").is_some()
                && output_3.get(".field_2").is_some()
            , false);

        drop(tx);
        topology.stop().await;
        assert_eq!(out.recv().await, None);
    }).await;
}


#[tokio::test]
async fn check_replace_with_custom_hash_key_name() {
    let config = toml::from_str::<HashReplaceConfig>(
        r#"
            replace_keys = ["field_1"]
            sample_rate = 1000
            hash_key_name = "custom_hashes"
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
        e_4.insert("field_1", 1);
        e_4.insert("field_2", "1");
        e_4.insert("field_3", "yep");

        let mut e_5 = LogEvent::from("test message 5");
        e_5.insert("field_1", 1);
        e_5.insert("field_2", "2");
        e_5.insert("field_4", "value1");

        for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
            tx.send(event).await.unwrap();
        };

        let output_1 = out.recv().await.unwrap().into_log();
        let output_2 = out.recv().await.unwrap().into_log();
        let output_3 = out.recv().await.unwrap().into_log();
        let output_4 = out.recv().await.unwrap().into_log();
        let output_5 = out.recv().await.unwrap().into_log();

        for event in vec![output_1.clone(), output_2.clone(), output_3.clone(), output_4.clone(), output_5.clone()] {
            println!("output log = {:?}", event.value().to_string_lossy().to_string());
            assert_eq!(event.get(".custom_hashes").is_some(), true);
            assert_eq!(event.get(".custom_hashes.field_1").is_some(), true);
        }

        assert_eq!(output_1.get(".custom_hashes.field_1"), output_4.get(".custom_hashes.field_1"));
        assert_eq!(output_4.get(".custom_hashes.field_1"), output_5.get(".custom_hashes.field_1"));

        assert_ne!(output_1.get(".custom_hashes.field_1"), output_2.get(".custom_hashes.field_1"));
        assert_ne!(output_2.get(".custom_hashes.field_1"), output_3.get(".custom_hashes.field_1"));
        assert_ne!(output_1.get(".custom_hashes.field_1"), output_3.get(".custom_hashes.field_1"));

        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_2.get(".field_1").is_some()
                && output_3.get(".field_1").is_some()
            , true);

        assert_eq!(
            output_1.get(".field_1").is_some()
                && output_4.get(".field_1").is_some()
                && output_5.get(".field_1").is_some()
            , false);

        drop(tx);
        topology.stop().await;
        // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(true));
        assert_eq!(out.recv().await, None);
    }).await;
}