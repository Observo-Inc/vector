use crate::config::TransformConfig;
use crate::template::Template;
use crate::test_util::components::assert_transform_compliance;
use crate::test_util::metrics::{generate_f64s, get_aggregated_histogram, get_counter, get_distribution, get_gauge};
use crate::transforms::sample::config::SampleConfig;
use crate::transforms::sample::sample_provider;
use crate::transforms::sample::sample_provider::{ModuloSampleProvider, RandomSampleProvider, SampleProvider, SampleProviders};
use crate::transforms::test::create_topology;
use crate::transforms::{FunctionTransform, OutputBuffer};
use crate::{
    conditions::{Condition, ConditionalConfig, VrlConfig},
    config::log_schema,
    event::{Event, LogEvent, TraceEvent},
    test_util::random_lines,
    transforms::sample::config::default_sample_rate_key,
    transforms::sample::transform::Sample,
    transforms::test::transform_one,
};
use approx::assert_relative_eq;
use rand::prelude::SmallRng;
use rand::{RngCore, SeedableRng};
use std::cmp::{max, min};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use vector_lib::event::MetricKind;
use vector_lib::lookup::lookup_v2::OptionalValuePath;
use vrl::owned_value_path;

#[tokio::test]
async fn emits_internal_events() {
    assert_transform_compliance(async move {
        let config = SampleConfig {
            rate: 1,
            key_field: None,
            group_by: None,
            exclude: None,
            sample_rate_key: default_sample_rate_key(),
            sample_random: None,
        };
        assert_eq!(config.enable_concurrency(), false);
        let (tx, rx) = mpsc::channel(1);
        let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

        let log = LogEvent::from("hello world");
        tx.send(log.into()).await.unwrap();

        _ = out.recv().await;

        drop(tx);
        topology.stop().await;
        assert_eq!(out.recv().await, None);
    })
    .await
}

#[test]
fn hash_samples_at_roughly_the_configured_rate() {
    let num_events = 10000;

    let events = random_events(num_events);
    let mut sampler = Sample::new(
        "sample".to_string(),
        2,
        log_schema().message_key().map(ToString::to_string),
        None,
        Some(condition_contains(
            log_schema().message_key().unwrap().to_string().as_str(),
            "na",
        )),
        default_sample_rate_key(),
        None,
    );
    let total_passed = events
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .count();
    let ideal = 1.0f64 / 2.0f64;
    let actual = total_passed as f64 / num_events as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.5);

    let events = random_events(num_events);
    let mut sampler = Sample::new(
        "sample".to_string(),
        25,
        log_schema().message_key().map(ToString::to_string),
        None,
        Some(condition_contains(
            log_schema().message_key().unwrap().to_string().as_str(),
            "na",
        )),
        default_sample_rate_key(),
        None,
    );
    let total_passed = events
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .count();
    let ideal = 1.0f64 / 25.0f64;
    let actual = total_passed as f64 / num_events as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.5);
}

#[test]
fn hash_consistently_samples_the_same_events() {
    let events = random_events(1000);
    let mut sampler = Sample::new(
        "sample".to_string(),
        2,
        log_schema().message_key().map(ToString::to_string),
        None,
        Some(condition_contains(
            log_schema().message_key().unwrap().to_string().as_str(),
            "na",
        )),
        default_sample_rate_key(),
        None,
    );

    let first_run = events
        .clone()
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();
    let second_run = events
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();

    assert_eq!(first_run, second_run);
}

#[test]
fn always_passes_events_matching_pass_list() {
    for key_field in &[None, log_schema().message_key().map(ToString::to_string)] {
        let event = Event::Log(LogEvent::from("i am important"));
        let mut sampler = Sample::new(
            "sample".to_string(),
            0,
            key_field.clone(),
            None,
            Some(condition_contains(
                log_schema().message_key().unwrap().to_string().as_str(),
                "important",
            )),
            default_sample_rate_key(),
            None,
        );
        let iterations = 0..1000;
        let total_passed = iterations
            .filter_map(|_| {
                transform_one(&mut sampler, event.clone()).map(|result| assert_eq!(result, event))
            })
            .count();
        assert_eq!(total_passed, 1000);
    }
}

#[test]
fn handles_group_by() {
    for group_by in &[None, Some(Template::try_from("{{ other_field }}").unwrap())] {
        let mut event = Event::Log(LogEvent::from("nananana"));
        let log = event.as_mut_log();
        log.insert("other_field", "foo");
        let mut sampler = Sample::new(
            "sample".to_string(),
            0,
            log_schema().message_key().map(ToString::to_string),
            group_by.clone(),
            Some(condition_contains(
                log_schema().message_key().unwrap().to_string().as_str(),
                "na",
            )),
            default_sample_rate_key(),
            None,
        );
        let iterations = 0..1000;
        let total_passed = iterations
            .filter_map(|_| {
                transform_one(&mut sampler, event.clone()).map(|result| assert_eq!(result, event))
            })
            .count();
        assert_eq!(total_passed, 1000);
    }
}

#[test]
fn handles_key_field() {
    for key_field in &[None, Some("other_field".into())] {
        let mut event = Event::Log(LogEvent::from("nananana"));
        let log = event.as_mut_log();
        log.insert("other_field", "foo");
        let mut sampler = Sample::new(
            "sample".to_string(),
            0,
            key_field.clone(),
            None,
            Some(condition_contains("other_field", "foo")),
            default_sample_rate_key(),
            None,
        );
        let iterations = 0..1000;
        let total_passed = iterations
            .filter_map(|_| {
                transform_one(&mut sampler, event.clone()).map(|result| assert_eq!(result, event))
            })
            .count();
        assert_eq!(total_passed, 1000);
    }
}

#[test]
fn sampler_adds_sampling_rate_to_event() {
    for key_field in &[None, log_schema().message_key().map(ToString::to_string)] {
        let events = random_events(10000);
        let message_key = log_schema().message_key().unwrap().to_string();
        let mut sampler = Sample::new(
            "sample".to_string(),
            10,
            key_field.clone(),
            None,
            Some(condition_contains(&message_key, "na")),
            default_sample_rate_key(),
            None,
        );
        let passing = events
            .into_iter()
            .filter(|s| !s.as_log()[&message_key].to_string_lossy().contains("na"))
            .find_map(|event| transform_one(&mut sampler, event))
            .unwrap();
        assert_eq!(passing.as_log()["sample_rate"], "10".into());

        let events = random_events(10000);
        let mut sampler = Sample::new(
            "sample".to_string(),
            25,
            key_field.clone(),
            None,
            Some(condition_contains(&message_key, "na")),
            OptionalValuePath::from(owned_value_path!("custom_sample_rate")),
            None,
        );
        let passing = events
            .into_iter()
            .filter(|s| !s.as_log()[&message_key].to_string_lossy().contains("na"))
            .find_map(|event| transform_one(&mut sampler, event))
            .unwrap();
        assert_eq!(passing.as_log()["custom_sample_rate"], "25".into());
        assert!(passing.as_log().get("sample_rate").is_none());

        let events = random_events(10000);
        let mut sampler = Sample::new(
            "sample".to_string(),
            50,
            key_field.clone(),
            None,
            Some(condition_contains(&message_key, "na")),
            OptionalValuePath::from(owned_value_path!("")),
            None,
        );
        let passing = events
            .into_iter()
            .filter(|s| !s.as_log()[&message_key].to_string_lossy().contains("na"))
            .find_map(|event| transform_one(&mut sampler, event))
            .unwrap();
        assert!(passing.as_log().get("sample_rate").is_none());

        // If the event passed the regex check, don't include the sampling rate
        let mut sampler = Sample::new(
            "sample".to_string(),
            25,
            key_field.clone(),
            None,
            Some(condition_contains(&message_key, "na")),
            default_sample_rate_key(),
            None,
        );
        let event = Event::Log(LogEvent::from("nananana"));
        let passing = transform_one(&mut sampler, event).unwrap();
        assert!(passing.as_log().get("sample_rate").is_none());
    }
}

#[test]
fn handles_trace_event() {
    let event: TraceEvent = LogEvent::from("trace").into();
    let trace = Event::Trace(event);

    let mut sampler = Sample::new(
        "sample".to_string(),
        2,
        None,
        None,
        None,
        default_sample_rate_key(),
        None,
    );

    let iterations = 0..2;
    let total_passed = iterations
        .filter_map(|_| transform_one(&mut sampler, trace.clone()))
        .count();
    assert_eq!(total_passed, 1);
}

#[test]
fn test_sample_provider() {
    let mut provider = sample_provider::ModuloSampleProvider::new(10);
    let mut min_val: u64 = 100;
    let mut max_val: u64 = 0;
    for i in 0..100 {
        let sample_val = provider.next_u64();
        assert_eq!(sample_val, i % 10);
        min_val = min(min_val, sample_val);
        max_val = max(max_val, sample_val);
    }
    assert_eq!(min_val, 0);
    assert_eq!(max_val, 9);

    min_val = 100;
    max_val = 0;
    provider = sample_provider::ModuloSampleProvider::new(17);
    for i in 0..100 {
        let sample_val = provider.next_u64();
        assert_eq!(sample_val, i % 17);
        min_val = min(min_val, sample_val);
        max_val = max(max_val, sample_val);
    }
    assert_eq!(min_val, 0);
    assert_eq!(max_val, 16);
}
#[test]
fn test_random_sample_provider() {
    let mut provider = sample_provider::RandomSampleProvider::new(7);
    let limit = 10000;
    let mut approx_sample_count = 0;
    for _ in 0..limit {
        let rand = provider.next_u64();
        if rand == 0 {
            approx_sample_count += 1;
        }
        assert!(rand < 7);
    }
    let ideal = 1.0f64 / 7.0f64;
    let actual = approx_sample_count as f64 / limit as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.05);
}

#[test]
fn hash_samples_at_roughly_the_configured_rate_with_random_true() {
    let num_events = 10000;

    let events = random_events(num_events);
    let mut sampler = Sample::new(
        "sample".to_string(),
        2,
        log_schema().message_key().map(ToString::to_string),
        None,
        Some(condition_contains(
            log_schema().message_key().unwrap().to_string().as_str(),
            "na",
        )),
        default_sample_rate_key(),
        Some(true),
    );
    let total_passed = events
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .count();
    let ideal = 1.0f64 / 2.0f64;
    let actual = total_passed as f64 / num_events as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.5);

    let events = random_events(num_events);
    let mut sampler = Sample::new(
        "sample".to_string(),
        25,
        log_schema().message_key().map(ToString::to_string),
        None,
        Some(condition_contains(
            log_schema().message_key().unwrap().to_string().as_str(),
            "na",
        )),
        default_sample_rate_key(),
        None,
    );
    let total_passed = events
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .count();
    let ideal = 1.0f64 / 25.0f64;
    let actual = total_passed as f64 / num_events as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.5);
}

#[test]
fn hash_consistently_samples_the_same_events_with_random_true() {
    let events = random_events(1000);
    let mut sampler = Sample::new(
        "sample".to_string(),
        2,
        log_schema().message_key().map(ToString::to_string),
        None,
        Some(condition_contains(
            log_schema().message_key().unwrap().to_string().as_str(),
            "na",
        )),
        default_sample_rate_key(),
        Some(true),
    );

    let first_run = events
        .clone()
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();
    let second_run = events
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();

    assert_eq!(first_run, second_run);
}

#[test]
fn always_passes_events_matching_pass_list_with_random_true() {
    for key_field in &[None, log_schema().message_key().map(ToString::to_string)] {
        let event = Event::Log(LogEvent::from("i am important"));
        let mut sampler = Sample::new(
            "sample".to_string(),
            0,
            key_field.clone(),
            None,
            Some(condition_contains(
                log_schema().message_key().unwrap().to_string().as_str(),
                "important",
            )),
            default_sample_rate_key(),
            Some(true),
        );
        let iterations = 0..1000;
        let total_passed = iterations
            .filter_map(|_| {
                transform_one(&mut sampler, event.clone()).map(|result| assert_eq!(result, event))
            })
            .count();
        assert_eq!(total_passed, 1000);
    }
}

fn condition_contains(key: &str, needle: &str) -> Condition {
    let vrl_config = VrlConfig {
        source: format!(r#"contains!(."{}", "{}")"#, key, needle),
        runtime: Default::default(),
    };

    vrl_config
        .build(&Default::default())
        .expect("should not fail to build VRL condition")
}

fn random_events(n: usize) -> Vec<Event> {
    random_lines(10)
        .take(n)
        .map(|e| Event::Log(LogEvent::from(e)))
        .collect()
}

fn get_hosts() -> Vec<String> {
    ('a'..='z').map(|c| c.to_string()).collect()
}
// Metric tests
fn random_hosts() -> (Vec<String>, RandomSampleProvider) {
    let rand_host = RandomSampleProvider::new(26);
    let hostnames: Vec<String> = get_hosts();

    (hostnames, rand_host)
}

fn get_host_selection() -> HashMap<String, bool> {
    let mut host_selection = HashMap::new();
    get_hosts().iter().for_each(|hostname| {
        let hash = seahash::hash(hostname.as_bytes()) % 2;
        // println!("{hostname} -> {hash}");
        host_selection.insert(hostname.to_string(), hash == 0);
    });
    host_selection
}

fn random_metric_events() -> Vec<Event> {
    let first_value = 3.14;
    let second_value = 7.6709;
    let third_value = 16.19;
    let samples1 = generate_f64s(1, 100);

    let mut samples2 = samples1.clone();
    samples2.extend(generate_f64s(75, 125));

    let samples11 = generate_f64s(1, 100);
    let samples12 = generate_f64s(1, 125);

    let metrics = vec![
        get_counter(third_value, MetricKind::Incremental),
        get_counter(first_value, MetricKind::Incremental),
        get_counter(second_value, MetricKind::Absolute),
        get_gauge(first_value, MetricKind::Absolute),
        get_gauge(second_value, MetricKind::Absolute),
        get_distribution(samples1, MetricKind::Absolute),
        get_distribution(samples2, MetricKind::Absolute),
        get_aggregated_histogram(samples11, MetricKind::Absolute),
        get_aggregated_histogram(samples12, MetricKind::Absolute),
        get_counter(third_value, MetricKind::Incremental),
    ];
    let mut rand_int = sample_provider::RandomSampleProvider::new(100);
    let (hostnames, mut rand_host) = random_hosts();
    let tag_values = random_lines(16).take(100).collect::<Vec<_>>();

    let events: Vec<Event> = metrics.into_iter().map(|mut metric| {
        metric.replace_tag("host".to_string(), hostnames[rand_host.next_u64() as usize].to_string());
        metric.replace_tag("tag1".to_string(), tag_values[rand_int.next_u64() as usize].to_string());
        metric.replace_tag("tag2".to_string(), tag_values[rand_int.next_u64() as usize].to_string());
        Event::Metric(metric)
    }).collect();

    let mut result = Vec::with_capacity(events.len() * 1000);
    for _ in 0..1000 {
        for event in &events {
            result.push(event.clone());
        }
    }
    result
}

#[test]
fn metric_normal_sampling() {
    // Generate metrics
    let metrics: Vec<Event> = random_metric_events();
    let num_metrics = metrics.len();

    let mut sampler = Sample::new(
        "sample".to_string(),
        17,
        None,
        None,
        None,
        OptionalValuePath::from(owned_value_path!("sample_rate")),
        None, // Normal (modulo) sampling
    );


    let total_passed = metrics
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .count();

    let ideal = 1.0f64 / 17.0f64;
    let actual = total_passed as f64 / num_metrics as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.05);
}

#[test]
fn metric_random_sampling() {

    // Generate metrics
    let metrics: Vec<Event> = random_metric_events();
    let num_metrics = metrics.len();
    let rate = 10;

    let mut sampler = Sample::new(
        "sample".to_string(),
        rate,
        None,
        None,
        None,
        OptionalValuePath::from(owned_value_path!("sample_rate")),
        Some(true), // Random sampling
    );

    let total_passed = metrics
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .count();

    let ideal = 1.0f64 / rate as f64;
    let actual = total_passed as f64 / num_metrics as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.05);
}

#[test]
fn metric_with_key_field() {
    // Generate metrics
    let metrics: Vec<Event> = random_metric_events();
    let num_metrics = metrics.len();
    let rate = 2;

    let mut sampler = Sample::new(
        "sample".to_string(),
        rate,
        Some("host".to_string()), // This should generate a warning for metrics
        None,
        None,
        OptionalValuePath::from(owned_value_path!("sample_rate")),
        None,
    );

    let sampled = metrics
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();
    let total_passed = sampled.len();

    let select_host = get_host_selection();
    sampled.into_iter().for_each(|sample| {
        match sample {
            Event::Metric(metric) => {
                let host = metric.tag_value("host").unwrap();
                assert!(select_host.get(&host).unwrap(), "Host {} selected is wrong", host);
            }
            _ => assert!(false, "Expected Metric"),
        }
    });

    let ideal = 1.0f64 / rate as f64;
    let actual = total_passed as f64 / num_metrics as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.5);
}


#[test]
fn metric_normal_key_field_sampling() {
    // Generate metrics
    let metrics: Vec<Event> = random_metric_events();
    let num_metrics = metrics.len();
    let rate = 2;

    let mut sampler = Sample::new(
        "sample".to_string(),
        rate,
        Some("host".to_string()),
        None,
        None,
        OptionalValuePath::from(owned_value_path!("sample_rate")),
        Some(true), //this will be ignored when key_field is given
    );


    let sampled = metrics
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();

    let total_passed = sampled.len();
    sampled.into_iter().for_each(|event| {
        match event {
            Event::Metric(metric) => {
                let sample_value = metric.tag_value("sample_rate");
                assert!(sample_value.is_some(), "Sample rate is missing in tags");
                assert_eq!(sample_value.unwrap().parse::<u64>().unwrap(), rate);
            }
            _ => assert!(false, "Expected Metric"),
        }
    });

    let ideal = 1.0f64 / rate as f64;
    let actual = total_passed as f64 / num_metrics as f64;
    assert_relative_eq!(ideal, actual, epsilon = ideal * 0.5);
}

#[test]
fn metric_with_key_field_same_rate_same_values() {
    // Generate metrics
    let metrics: Vec<Event> = random_metric_events();
    let rate = 31;
    let mut sampler = Sample::new(
        "sample".to_string(),
        rate,
        Some("host".to_string()), // This should generate a warning for metrics
        None,
        None,
        OptionalValuePath::from(owned_value_path!("my_custom_sample_rate")),
        if SmallRng::from_entropy().next_u64() % rate == 0 { Some(true) } else { None }, //this will be ignored when key_field is given
    );

    let first_run = metrics
        .clone()
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();
    let second_run = metrics
        .into_iter()
        .filter_map(|event| {
            let mut buf = OutputBuffer::with_capacity(1);
            sampler.transform(&mut buf, event);
            buf.into_events().next()
        })
        .collect::<Vec<_>>();
    first_run.clone().into_iter()
        .for_each(|event: Event| {
            match event {
                Event::Metric(metric) => {
                    let sample_value = metric.tag_value("my_custom_sample_rate");
                    assert!(sample_value.is_some(), "Sample rate is missing in tags");
                    assert_eq!(sample_value.unwrap().parse::<u64>().unwrap(), rate);
                }
                _ => assert!(false, "Expected Metric"),
            }
        });
    second_run.clone().into_iter()
        .for_each(|event: Event| {
            match event {
                Event::Metric(metric) => {
                    let host_value = metric.tag_value("host");
                    assert!(host_value.is_some(), "Host is missing in tags");
                    assert_eq!(seahash::hash(host_value.unwrap().as_bytes()) % rate, 0);
                }
                _ => assert!(false, "Expected Metric"),
            }
        });
    assert_eq!(first_run, second_run);
}


#[test]
fn metric_handles_group_by() {
    for group_by in &[None, Some(Template::try_from("{{ tags.host }}").unwrap())] {
        let metrics: Vec<Event> = random_metric_events();
        let rate = 2;

        let mut sampler = Sample::new(
            "sample".to_string(),
            rate,
            None,
            group_by.clone(),
            Some(Condition::IsLog),
            default_sample_rate_key(),
            None,
        );

        let sampled = metrics.clone()
            .into_iter()
            .filter_map(|event| {
                let mut buf = OutputBuffer::with_capacity(1);
                sampler.transform(&mut buf, event);
                buf.into_events().next()
            })
            .collect::<Vec<_>>();

        assert_eq!(sampled.len(), 5000);
        if group_by.is_some() {
            let mut index = 0;
            let mut host_counter: HashMap<String, SampleProviders> = HashMap::new();
            for hostname in get_hosts() {
                host_counter.insert(hostname, SampleProviders::Default(ModuloSampleProvider::new(rate)));
            }
            for mut event in metrics {
                let host = event.as_metric().tag_value("host").unwrap();
                if host_counter.get_mut(&host).unwrap().next_u64() == 0 {
                    let event_metrics = event.as_mut_metric();
                    event_metrics.replace_tag("sample_rate".to_string(), rate.to_string());
                    assert_eq!(event_metrics, sampled[index].as_metric());
                    index += 1;
                }
            }
        }
    }
}

#[test]
fn metric_handles_exclude() {
    for group_by in &[None, Some(Template::try_from("{{ tags.host }}").unwrap())] {
        let metrics: Vec<Event> = random_metric_events();
        let rate = 2;

        let mut sampler = Sample::new(
            "sample".to_string(),
            rate,
            None,
            group_by.clone(),
            Some(Condition::IsMetric),
            default_sample_rate_key(),
            None,
        );

        let total_passed = metrics
            .into_iter()
            .filter_map(|event| {
                let mut buf = OutputBuffer::with_capacity(1);
                sampler.transform(&mut buf, event);
                buf.into_events().next()
            })
            .count();
        assert_eq!(total_passed, 10000);
    }
}