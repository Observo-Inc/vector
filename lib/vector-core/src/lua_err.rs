use snafu::Snafu;
use metrics::{counter, gauge};
use vector_common::internal_event::{ComponentEventsDropped, UNINTENTIONAL};

use crate::internal_event::{error_stage, error_type, InternalEvent};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum BuildError {
    #[snafu(display("Invalid \"search_dirs\": {}", source))]
    InvalidSearchDirs { source: mlua::Error },
    #[snafu(display("Cannot evaluate Lua code in \"source\": {}", source))]
    InvalidSource { source: mlua::Error },

    #[snafu(display("Cannot evaluate Lua code defining \"hooks.init\": {}", source))]
    InvalidHooksInit { source: mlua::Error },
    #[snafu(display("Cannot evaluate Lua code defining \"hooks.process\": {}", source))]
    InvalidHooksProcess { source: mlua::Error },
    #[snafu(display("Cannot evaluate Lua code defining \"hooks.shutdown\": {}", source))]
    InvalidHooksShutdown { source: mlua::Error },
    #[snafu(display("Cannot evaluate Lua code defining timer handler: {}", source))]
    InvalidTimerHandler { source: mlua::Error },

    #[snafu(display("Runtime error in \"hooks.init\" function: {}", source))]
    RuntimeErrorHooksInit { source: mlua::Error },
    #[snafu(display("Runtime error in \"hooks.process\" function: {}", source))]
    RuntimeErrorHooksProcess { source: mlua::Error },
    #[snafu(display("Runtime error in \"hooks.shutdown\" function: {}", source))]
    RuntimeErrorHooksShutdown { source: mlua::Error },
    #[snafu(display("Runtime error in timer handler: {}", source))]
    RuntimeErrorTimerHandler { source: mlua::Error },

    #[snafu(display("Cannot call GC in Lua runtime: {}", source))]
    RuntimeErrorGc { source: mlua::Error },

    #[snafu(display("Runtime error in \"process\" function: {}", source))]
    RuntimeErrorProcess { source: mlua::Error },
    #[snafu(display("Cannot evaluate Lua code defining \"process\": {}", source))]
    InvalidProcess { source: mlua::Error },
}

#[derive(Debug)]
pub struct LuaGcTriggered {
    pub used_memory: usize,
}

impl InternalEvent for LuaGcTriggered {
    fn emit(self) {
        gauge!("lua_memory_used_bytes").set(self.used_memory as f64);
    }
}

#[derive(Debug)]
pub struct LuaScriptError {
    pub error: mlua::Error,
}

impl InternalEvent for LuaScriptError {
    fn emit(self) {
        error!(
            message = "Error in lua script.",
            error = ?self.error,
            error_code = mlua_error_code(&self.error),
            error_type = error_type::COMMAND_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => mlua_error_code(&self.error),
            "error_type" => error_type::SCRIPT_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
        emit!(ComponentEventsDropped::<UNINTENTIONAL> {
            count: 1,
            reason: "Error in lua script.",
        });
    }
}

#[derive(Debug)]
pub struct LuaBuildError {
    pub error: BuildError,
}

impl InternalEvent for LuaBuildError {
    fn emit(self) {
        let reason = "Error in building lua script.";
        error!(
            message = reason,
            error = ?self.error,
            error_type = error_type::SCRIPT_FAILED,
            error_code = lua_build_error_code(&self.error),
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => lua_build_error_code(&self.error),
            "error_type" => error_type::SCRIPT_FAILED,
            "stage" => error_stage:: PROCESSING,
        )
        .increment(1);

        emit!(ComponentEventsDropped::<UNINTENTIONAL> { count: 1, reason })
    }
}

fn mlua_error_code(err: &mlua::Error) -> &'static str {
    use mlua::Error::*;

    match err {
        SyntaxError { .. } => "syntax_error",
        RuntimeError(_) => "runtime_error",
        MemoryError(_) => "memory_error",
        SafetyError(_) => "memory_safety_error",
        MemoryControlNotAvailable => "memory_control_not_available",
        RecursiveMutCallback => "mutable_callback_called_recursively",
        CallbackDestructed => "callback_destructed",
        StackError => "out_of_stack",
        BindError => "too_many_arguments_to_function_bind",
        BadArgument { .. } => "bad_argument",
        ToLuaConversionError { .. } => "error_converting_value_to_lua",
        FromLuaConversionError { .. } => "error_converting_value_from_lua",
        CoroutineUnresumable => "coroutine_unresumable",
        UserDataTypeMismatch => "userdata_type_mismatch",
        UserDataDestructed => "userdata_destructed",
        UserDataBorrowError => "userdata_borrow_error",
        UserDataBorrowMutError => "userdata_already_borrowed",
        MetaMethodRestricted(_) => "restricted_metamethod",
        MetaMethodTypeError { .. } => "unsupported_metamethod_type",
        MismatchedRegistryKey => "mismatched_registry_key",
        CallbackError { .. } => "callback_error",
        PreviouslyResumedPanic => "previously_resumed_panic",
        ExternalError(_) => "external_error",
        WithContext { cause, .. } => mlua_error_code(cause),
        _ => "unknown",
    }
}

const fn lua_build_error_code(err: &BuildError) -> &'static str {
    use BuildError::*;

    match err {
        InvalidSearchDirs { .. } => "invalid_search_dir",
        InvalidSource { .. } => "invalid_source",
        InvalidHooksInit { .. } => "invalid_hook_init",
        InvalidHooksProcess { .. } => "invalid_hook_process",
        InvalidHooksShutdown { .. } => "invalid_hook_shutdown",
        InvalidTimerHandler { .. } => "invalid_timer_handler",
        RuntimeErrorHooksInit { .. } => "runtime_error_hook_init",
        RuntimeErrorHooksProcess { .. } => "runtime_error_hook_process",
        RuntimeErrorHooksShutdown { .. } => "runtime_error_hook_shutdown",
        RuntimeErrorTimerHandler { .. } => "runtime_error_timer_handler",
        RuntimeErrorGc { .. } => "runtime_error_gc",
        RuntimeErrorProcess{ .. } => "runtime_error_process",
        InvalidProcess { .. } => "invalid_process",
    }
}