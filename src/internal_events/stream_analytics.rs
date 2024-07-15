use metrics::counter;

use vector_common::internal_event::{
    error_stage, error_type,
};
use vector_core::internal_event::InternalEvent;

#[derive(Debug)]
pub struct StreamAnalyticsFieldProcessedTotal {
    pub calculator: String,
    pub total_fields_processed: u64,
}

impl InternalEvent for StreamAnalyticsFieldProcessedTotal {
    fn emit(self) {
        counter!(
            "stream_analytics_fields_processed_total", self.total_fields_processed,
            "calculator" => self.calculator.to_lowercase(),
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}

#[derive(Debug)]
pub struct StreamAnalyticsFlushed {
    pub calculator: String,
}

impl InternalEvent for StreamAnalyticsFlushed {
    fn emit(self) {
        counter!(
            "stream_analytics_flushes_total", 1,
            "calculator" => self.calculator.to_lowercase(),
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}

#[derive(Debug)]
pub struct StreamAnalyticsResets {
    pub calculator: String,
}

impl InternalEvent for StreamAnalyticsResets {
    fn emit(self) {
        counter!(
            "stream_analytics_resets_total", 1,
            "calculator" => self.calculator.to_lowercase(),
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}

#[derive(Debug)]
pub struct StreamAnalyticsError {
    pub error: String,
    pub reason: String,
}

impl InternalEvent for StreamAnalyticsError {
    fn emit(self) {
        error!(
            message = ?self.reason,
            error = ?self.error,
            error_type = error_type::ENCODER_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true
        );
        counter!(
            "component_errors_total", 1,
            "error_type" => error_type::ENCODER_FAILED,
            "stage" => error_stage::PROCESSING,
            "message" => self.error,
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}


// Error logs and counters
#[derive(Debug)]
pub struct StreamAnalyticsFieldProcessError {
    pub error: String,
    pub calculator: String,
}

impl InternalEvent for StreamAnalyticsFieldProcessError {
    fn emit(self) {
        let reason = "StreamAnalytics failed to process event field.";
        error!(
            message = reason,
            error = ?self.error,
            calculator = self.calculator.to_lowercase(),
            error_type = error_type::ENCODER_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true
        );
        counter!(
            "component_errors_total", 1,
            "calculator" => self.calculator.to_lowercase(),
            "error_type" => error_type::ENCODER_FAILED,
            "stage" => error_stage::PROCESSING,
            "message" => reason,
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}

#[derive(Debug)]
pub struct StreamAnalyticsPublishError {
    pub error: String,
    pub calculator: String,
}

impl InternalEvent for StreamAnalyticsPublishError {
    fn emit(self) {
        let reason = "StreamAnalytics failed to publish event.";
        error!(
            message = reason,
            error = ?self.error,
            calculator = self.calculator.to_lowercase(),
            error_type = error_type::WRITER_FAILED,
            stage = error_stage::SENDING,
            internal_log_rate_limit = true
        );
        counter!(
            "component_errors_total", 1,
            "calculator" => self.calculator.to_lowercase(),
            "error_type" => error_type::WRITER_FAILED,
            "stage" => error_stage::SENDING,
            "message" => reason,
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}

#[derive(Debug)]
pub struct StreamAnalyticsResetError {
    pub error: String,
    pub calculator: String,
}

impl InternalEvent for StreamAnalyticsResetError {
    fn emit(self) {
        let reason = "StreamAnalytics failed to reset.";
        error!(
            message = reason,
            error = ?self.error,
            calculator = self.calculator.to_lowercase(),
            error_type = error_type::COMMAND_FAILED,
            stage = error_stage::SENDING,
            internal_log_rate_limit = true
        );
        counter!(
            "component_errors_total", 1,
            "calculator" => self.calculator.to_lowercase(),
            "error_type" => error_type::COMMAND_FAILED,
            "stage" => error_stage::SENDING,
            "message" => reason,
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}


#[derive(Debug)]
pub struct StreamAnalyticsResetPerEventError {
    pub error: String,
    pub calculator: String,
}

impl InternalEvent for StreamAnalyticsResetPerEventError {
    fn emit(self) {
        let reason = "StreamAnalytics failed to reset per event state.";
        error!(
            message = reason,
            error = ?self.error,
            calculator = self.calculator.to_lowercase(),
            error_type = error_type::COMMAND_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true
        );
        counter!(
            "component_errors_total", 1,
            "calculator" => self.calculator.to_lowercase(),
            "error_type" => error_type::COMMAND_FAILED,
            "stage" => error_stage::PROCESSING,
            "message" => reason,
        );
    }

    // fn name(&self) -> Option<&'static str> {
    //     Some(self.calculator.as_str())
    // }
}