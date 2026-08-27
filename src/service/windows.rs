use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

use crate::status::StatusRole;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

const STOP_WAIT_HINT: Duration = Duration::from_secs(10);

const STOP_PROGRESS_INTERVAL: Duration = Duration::from_secs(2);

// A Win32(0) stop reads to the SCM as a clean shutdown, so the recovery actions
// `install` configures would never run.
const SERVICE_FAILURE_EXIT: ServiceExitCode = ServiceExitCode::ServiceSpecific(1);

fn service_name(role: &str) -> String {
    format!("iroh-tunnel-{role}")
}

fn service_status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}

static SERVICE_ARGS: OnceLock<(StatusRole, PathBuf)> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run_as_service(role: StatusRole, config: &Path) -> Result<()> {
    SERVICE_ARGS
        .set((role, config.to_path_buf()))
        .map_err(|_| anyhow::anyhow!("service arguments were already set"))?;
    service_dispatcher::start(service_name(role.name()), ffi_service_main)
        .context("failed to connect to the service control dispatcher")?;
    // The dispatcher returns once `service_main` has, so its failure is ours.
    match SERVICE_OUTCOME
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

static SERVICE_OUTCOME: Mutex<Option<anyhow::Error>> = Mutex::new(None);

fn service_main(_args: Vec<OsString>) {
    let Err(err) = service_body() else { return };
    tracing::error!("service exited with an error: {err:#}");
    *SERVICE_OUTCOME.lock().unwrap_or_else(|e| e.into_inner()) = Some(err);
}

// The SCM reads a checkpoint that stops advancing as a hung service. Holding
// the lock across the report keeps a stale StopPending from landing after the
// final Stopped.
fn report_stop_progress(handle: ServiceStatusHandle, drained: &Mutex<bool>) {
    let mut checkpoint = 1;
    loop {
        std::thread::sleep(STOP_PROGRESS_INTERVAL);
        let done = drained.lock().unwrap_or_else(|e| e.into_inner());
        if *done {
            return;
        }
        let mut status = service_status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            STOP_WAIT_HINT,
        );
        status.checkpoint = checkpoint;
        let _ = handle.set_service_status(status);
        checkpoint += 1;
    }
}

fn service_body() -> Result<()> {
    let (role, config) = SERVICE_ARGS
        .get()
        .context("service started without captured arguments")?;

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Mutex::new(Some(stop_tx));

    let status_handle: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let handler_handle = Arc::clone(&status_handle);
    let drained = Arc::new(Mutex::new(false));
    let handler_drained = Arc::clone(&drained);

    let handle =
        service_control_handler::register(
            service_name(role.name()),
            move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let mut slot = stop_tx.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(());
                        if let Some(&h) = handler_handle.get() {
                            let _ = h.set_service_status(service_status(
                                ServiceState::StopPending,
                                ServiceControlAccept::empty(),
                                STOP_WAIT_HINT,
                            ));
                            let drained = Arc::clone(&handler_drained);
                            std::thread::spawn(move || report_stop_progress(h, &drained));
                        }
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )
        .context("failed to register the service control handler")?;
    let _ = status_handle.set(handle);

    let outcome = run_until_stopped(handle, stop_rx, *role, config);

    let mut final_status = service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
    );
    if outcome.is_err() {
        final_status.exit_code = SERVICE_FAILURE_EXIT;
    }
    let mut done = drained.lock().unwrap_or_else(|e| e.into_inner());
    *done = true;
    if let Err(e) = handle.set_service_status(final_status) {
        tracing::error!("failed to report the final service status: {e}");
    }
    outcome
}

// Split out so every `Result` error between StartPending and the roles
// returning funnels into service_body's single Stopped report.
fn run_until_stopped(
    handle: ServiceStatusHandle,
    stop_rx: tokio::sync::oneshot::Receiver<()>,
    role: StatusRole,
    config: &Path,
) -> Result<()> {
    handle.set_service_status(service_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(30),
    ))?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the Tokio runtime")?;

    handle.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::ZERO,
    ))?;

    rt.block_on(async {
        let shutdown = async {
            let _ = stop_rx.await;
        };
        match role {
            StatusRole::Serve => crate::serve::run_with_shutdown(config, shutdown).await,
            StatusRole::Access => crate::access::run_with_shutdown(config, shutdown).await,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_is_role_scoped() {
        assert_eq!(service_name("serve"), "iroh-tunnel-serve");
        assert_eq!(service_name("access"), "iroh-tunnel-access");
    }

    #[test]
    fn service_status_reports_success_by_default() {
        let status = service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP,
            Duration::ZERO,
        );
        assert_eq!(status.exit_code, ServiceExitCode::NO_ERROR);
        assert_eq!(status.checkpoint, 0);
    }

    #[test]
    fn failure_exit_code_never_reads_as_a_clean_stop() {
        assert_ne!(SERVICE_FAILURE_EXIT, ServiceExitCode::NO_ERROR);
        assert_ne!(SERVICE_FAILURE_EXIT, ServiceExitCode::Win32(0));
    }
}
