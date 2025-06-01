
use std::{collections::HashMap, pin::Pin, time::Duration, cmp::max, fmt::Formatter, time::Instant, fmt};
use std::collections::hash_map::DefaultHasher;
use std::fmt::Debug;
use std::hash::Hash;

use async_stream::stream;
use cuckoofilter::CuckooFilter;
use futures::{stream, Stream, StreamExt};


use crate::{
    event::Event,
    transforms::TaskTransform,
    internal_events::{HashReplaceFlushed, HashReplaceKeysProcessError}
};

use vector_lib::event::Value;
use rand::{distributions::{Distribution, Uniform}, rngs::SmallRng, SeedableRng};

use xxhash_rust::xxh3::xxh3_64;
use config::HashReplaceConfig;

mod config;
#[cfg(test)]
mod test;


struct AMQFilter {
    filter: CuckooFilter<DefaultHasher>,
    key: String,
    capacity: usize,
}

impl Debug for AMQFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
         "Shouldn't print CuckooFilter details".fmt(f)
    }
}

impl AMQFilter {
    fn new(key: String, capacity: usize) -> Self {
        let capacity = max(capacity, cuckoofilter::DEFAULT_CAPACITY);
        AMQFilter {
            key,
            capacity,
            filter: CuckooFilter::with_capacity(capacity),
        }
    }

    fn check_and_add<T: ?Sized + Hash>(&mut self, value: &T) -> bool {
        let present = self.filter.contains(value);
        if !present {
            match self.filter.add(value) {
                Ok(_) => { trace!(message =  "Hash value calculated for key.", Key=%self.key.clone())}
                Err(err) => {
                    emit!(HashReplaceKeysProcessError{
                        error: "Error in adding key to AMQ filter".to_string()
                        ,key: self.key.clone(),
                    });
                    warn!(message = "Error in adding value to AMQ filter.", Key=%self.key.clone()
                        , Err=%err, internal_log_rate_limit=true);
                }
            };
        }
        return present;
    }

    fn reset(&mut self) {
        self.filter = CuckooFilter::with_capacity(self.capacity);
    }
}



#[derive(Debug, Derivative)]
pub struct HashReplaceState {
    current_events_count: u64,
    last_flush: Instant,
    capacity: usize,
    amq_filter: HashMap<String, AMQFilter>,
}

impl HashReplaceState {
    fn should_flush(&mut self, max_events: u64, duration: Duration) -> bool {
        if (Instant::now() - self.last_flush) >= duration {
            return true;
        }
        self.current_events_count += 1;
        if self.current_events_count >= max_events {
            self.current_events_count = 0;
            return true;
        }
        false
    }

    fn flushed(&mut self) {
        self.amq_filter.iter_mut().for_each(|(key, filter)| {
            debug!(message="Resetting AMQ filter for key", Key=%key, internal_log_rate_limit=true);
            filter.reset();
        });
        self.current_events_count = 0;
        self.last_flush = Instant::now();
    }

    fn check_and_add(&mut self, key: &str, value: &Value) -> bool {
        if !self.amq_filter.contains_key(key) {
            emit!(HashReplaceKeysProcessError{
                    error: ("AMQ filter map can't be empty for key ".to_owned() + key).to_string()
                    ,key: key.to_string()
                });
            warn!(message = "Adding to map but AMQ filter hash can't be empty for key.", Key=%key, internal_log_rate_limit=true);
            self.amq_filter.insert(key.to_string(), AMQFilter::new(key.to_string(), self.capacity));
        }
        match self.amq_filter.get_mut(key) {
            None => {
                emit!(HashReplaceKeysProcessError{
                    error: "AMQ filter map empty even after adding key".to_string()
                    ,key: key.to_string()
                });
                error!(message = "AMQ filter map empty even after adding key", Key=%key, internal_log_rate_limit=true);
                false
            }
            Some(filter) => {
                filter.check_and_add(value)
            }
        }
    }
}

#[derive(Debug, Derivative)]
pub struct HashReplace {
    config: HashReplaceConfig,
    rng: SmallRng,
    uniform_distribution: Uniform<u64>,
    hash_replace_state: HashReplaceState,
}

impl HashReplace {
    pub fn new(
        config: &HashReplaceConfig,
    ) -> crate::Result<Self> {
        debug!(message = "HashReplace config.", Config = %config, internal_log_rate_limit=true);
        let mut amq_filter_map: HashMap<String, AMQFilter> = HashMap::new();
        for key in config.replace_keys.iter() {
            amq_filter_map.insert(key.to_string(), AMQFilter::new(key.to_string(), config.amq_filter_capacity));
        }
        Ok(HashReplace {
            config: config.clone(),
            rng: SmallRng::from_entropy(),
            uniform_distribution: Uniform::new_inclusive(0, config.sample_rate), // 0 (inclusive) to 100 (exclusive)
            hash_replace_state: HashReplaceState {
                current_events_count: 0,
                last_flush: Instant::now(),
                capacity: config.amq_filter_capacity,
                amq_filter: amq_filter_map,
            },
        })
    }

    fn modify_event(&mut self, output: &mut Vec<Event>, event: Event) {
        match event {
            Event::Metric(_) => { return; }
            Event::Log(mut log_event) => {
                let hash_key_name = self.config.get_hash_key_name();
                let mut hashes : HashMap<String, String> = HashMap::with_capacity(self.config.replace_keys.len());

                for key in self.config.replace_keys.iter() {
                    let log_value = log_event.get(key.as_str());
                    if let Some(value) = log_value {
                        let field_value = value.to_string_lossy();
                        let hash_value = xxh3_64(field_value.as_bytes());
                        let hash_str = format!("{:x}", hash_value);
                        trace!(message =  "Hash value calculated for key."
                            , Key=%key
                            , Value_str=%field_value.to_string()
                            , Hash=%hash_value
                            , Hash_str=%hash_str.clone()
                            , internal_log_rate_limit=true
                            );
                        hashes.insert(hash_key_name.clone() + "." + key.clone().as_str(), hash_str.clone());
                        if self.hash_replace_state.check_and_add(key.as_str(), value) {
                            trace!(message =  "AMQ contains key."
                            , Key=%key
                            , Value_str=%field_value.to_string()
                            , Hash=%hash_value
                            , Hash_str=%hash_str
                            , internal_log_rate_limit=true
                            );
                            if self.uniform_distribution.sample(&mut self.rng) >= 1 {
                                log_event.remove(key.as_str());
                            }
                        } else {
                            trace!(message =  "AMQ doesn't contains key."
                            , Key=%key
                            , Value_str=%field_value.to_string()
                            , Hash=%hash_value
                            , Hash_str=%hash_str
                            , internal_log_rate_limit=true
                            );
                        }
                    }
                }

                // Add hash to original logs
                for (key, value) in hashes {
                    log_event.insert(key.as_str(), value);
                }

                output.push(Event::from(log_event));
            }
            Event::Trace(_) => { return; }
        }
    }

    fn flush(&mut self) {
        emit!(HashReplaceFlushed{});
        self.hash_replace_state.flushed();
    }

    fn flush_into(&mut self) {
        if self.hash_replace_state.should_flush(self.config.max_events, self.config.flush_period_ms) {
            self.flush();
        }
    }

    fn flush_all_into(&mut self) {
        self.flush();
    }

    fn transform_one(&mut self, output: &mut Vec<Event>, event: Event) {
        self.modify_event(output, event);
        self.flush_into();
    }
}

impl TaskTransform<Event> for HashReplace {
    fn transform(
        self: Box<Self>,
        mut input_rx: Pin<Box<dyn Stream<Item = Event> + Send>>,
    ) -> Pin<Box<dyn Stream<Item = Event> + Send>>
    where
        Self: 'static,
    {
        let mut me = self;

        let poll_period = Duration::from_millis(
            max(me.config.flush_period_ms.as_millis()/3, 5000)
                as u64);

        let mut flush_stream = tokio::time::interval(poll_period);

        Box::pin(
            stream! {
              loop {
                let mut output = Vec::new();
                let done = tokio::select! {
                    _ = flush_stream.tick() => {
                      me.flush_into();
                      false
                    }
                    maybe_event = input_rx.next() => {
                      match maybe_event {
                        None => {
                          me.flush_all_into();
                          true
                        }
                        Some(event) => {
                          me.transform_one(&mut output, event);
                          false
                        }
                      }
                    }
                };
                yield stream::iter(output.into_iter());
                if done { break }
              }
            }
            .flatten(),
        )
    }
}

