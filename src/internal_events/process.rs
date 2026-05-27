use metrics::{counter, gauge};
use vector_lib::internal_event::InternalEvent;
use vector_lib::internal_event::{error_stage, error_type};

use crate::{built_info, config};

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[derive(Debug)]
pub struct VectorStarted;

impl InternalEvent for VectorStarted {
    fn emit(self) {
        info!(
            target: "vector",
            message = "Vector has started.",
            debug = built_info::DEBUG,
            version = built_info::PKG_VERSION,
            arch = built_info::TARGET_ARCH,
            revision = built_info::VECTOR_BUILD_DESC.unwrap_or(""),
        );
        counter!("started_total").increment(1);
        gauge!("valid_config").set(1.0);
    }
}

#[derive(Debug)]
pub struct VectorReloadStarted;

impl InternalEvent for VectorReloadStarted {
    fn emit(self) {
        debug!(target: "vector", message = "Vector is reloading configuration.");
        gauge!("reload_in_progress").set(1.0);
        gauge!("last_reload_started_timestamp_seconds").set(unix_now());
    }
}

#[derive(Debug)]
pub struct VectorReloaded<'a> {
    pub config_paths: &'a [config::ConfigPath],
}

impl InternalEvent for VectorReloaded<'_> {
    fn emit(self) {
        info!(
            target: "vector",
            message = "Vector has reloaded.",
            path = ?self.config_paths
        );
        counter!("reloaded_total").increment(1);
        gauge!("valid_config").set(1.0);
        gauge!("reload_in_progress").set(0.0);
    }
}

#[derive(Debug)]
pub struct VectorStopped;

impl InternalEvent for VectorStopped {
    fn emit(self) {
        info!(
            target: "vector",
            message = "Vector has stopped."
        );
        counter!("stopped_total").increment(1);
    }
}

#[derive(Debug)]
pub struct VectorQuit;

impl InternalEvent for VectorQuit {
    fn emit(self) {
        info!(
            target: "vector",
            message = "Vector has quit."
        );
        counter!("quit_total").increment(1);
    }
}

#[derive(Debug)]
pub struct VectorReloadError;

impl InternalEvent for VectorReloadError {
    fn emit(self) {
        error!(
            message = "Reload was not successful.",
            error_code = "reload",
            error_type = error_type::CONFIGURATION_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "reload",
            "error_type" => error_type::CONFIGURATION_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
        gauge!("valid_config").set(0.0);
        gauge!("reload_in_progress").set(0.0);
    }
}

#[derive(Debug)]
pub struct VectorConfigLoadError;

impl InternalEvent for VectorConfigLoadError {
    fn emit(self) {
        error!(
            message = "Failed to load config files, reload aborted.",
            error_code = "config_load",
            error_type = error_type::CONFIGURATION_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "config_load",
            "error_type" => error_type::CONFIGURATION_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
        gauge!("valid_config").set(0.0);
    }
}

#[derive(Debug)]
pub struct VectorRecoveryError;

impl InternalEvent for VectorRecoveryError {
    fn emit(self) {
        error!(
            message = "Vector has failed to recover from a failed reload.",
            error_code = "recovery",
            error_type = error_type::CONFIGURATION_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "recovery",
            "error_type" => error_type::CONFIGURATION_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}
