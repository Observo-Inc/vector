use vector_core::internal_event::InternalEvent;
use metrics::counter;

use vector_common::internal_event::{
    error_stage, error_type,
};

#[derive(Debug)]
pub struct HashReplaceFlushed {
}

impl InternalEvent for HashReplaceFlushed {
    fn emit(self) {
        counter!(
            "hash_replace_flushes_total", 1,
        );
    }
}

// Error logs and counters
#[derive(Debug)]
pub struct HashReplaceKeysProcessError {
    pub error: String,
    pub key: String,
}

impl InternalEvent for HashReplaceKeysProcessError {
    fn emit(self) {
        let reason = "HashReplace failed to process key.";
        error!(
            message = reason,
            error = ?self.error,
            calculator = self.key.to_lowercase(),
            error_type = error_type::ENCODER_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true
        );
        counter!(
            "component_errors_total", 1,
            "calculator" => self.key.to_lowercase(),
            "error_type" => error_type::ENCODER_FAILED,
            "stage" => error_stage::PROCESSING,
            "message" => reason,
        );
    }

}