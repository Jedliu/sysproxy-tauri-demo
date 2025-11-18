use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use log::{debug, error};
use tokio::sync::Notify;

use crate::{Autoproxy, Sysproxy};

#[derive(Debug, PartialEq, Clone)]
pub enum GuardType {
    None,
    Sysproxy(Sysproxy),
    Autoproxy(Autoproxy),
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum GuardState {
    Running = 0,
    Stopped,
    NeedRestart,
    Pending,
}

impl GuardState {
    #[inline]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => GuardState::Running,
            1 => GuardState::Stopped,
            2 => GuardState::NeedRestart,
            3 => GuardState::Pending,
            _ => GuardState::Stopped,
        }
    }

    #[inline]
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        matches!(self, GuardState::Running)
    }

    #[inline]
    pub fn is_stopped(&self) -> bool {
        matches!(self, GuardState::Stopped)
    }

    #[inline]
    pub fn is_need_restart(&self) -> bool {
        matches!(self, GuardState::NeedRestart)
    }

    #[inline]
    pub fn is_pendding(&self) -> bool {
        matches!(self, GuardState::Pending)
    }
}

impl fmt::Display for GuardState {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardState::Running => write!(f, "Running"),
            GuardState::Stopped => write!(f, "Stopped"),
            GuardState::NeedRestart => write!(f, "NeedRestart"),
            GuardState::Pending => write!(f, "Pendding"),
        }
    }
}

#[derive(Clone)]
struct TaskConfig {
    guard_type: GuardType,
    interval: Duration,
}

pub struct GuardMonitor {
    guard_type: GuardType,
    interval: Duration,
    notify: Arc<Notify>,
    guard_stat: Arc<AtomicU8>,
}

impl Drop for GuardMonitor {
    #[inline]
    fn drop(&mut self) {
        self.stop();
    }
}

impl GuardMonitor {
    #[inline]
    pub fn new(guard_type: GuardType, interval: Duration) -> Self {
        debug!("Create GuardMonitor with interval: {:?}", interval);
        debug!(
            "GuardType: {:?}",
            match &guard_type {
                GuardType::Sysproxy(sysproxy) => format!("Sysproxy: {:?}", sysproxy),
                GuardType::Autoproxy(autoproxy) => format!("Autoproxy: {:?}", autoproxy),
                GuardType::None => "None".to_string(),
            }
        );
        Self {
            guard_type,
            interval,
            notify: Arc::new(Notify::new()),
            guard_stat: Arc::new(AtomicU8::new(GuardState::Stopped as u8)),
        }
    }

    #[inline]
    pub fn get_state(&self) -> GuardState {
        GuardState::from_u8(self.guard_stat.load(Ordering::Acquire))
    }

    #[inline]
    fn set_state(&self, new: GuardState) {
        debug!("GuardMonitor setting state to: {:?}", new);
        self.guard_stat.store(new as u8, Ordering::Release);
    }

    #[inline]
    pub fn set_interval(&mut self, interval: Duration) {
        debug!("Setting interval: {:?}", interval);
        let should_restart = !self.get_state().is_stopped() && self.interval != interval;
        if should_restart {
            debug!("Interval changed while running, monitor should be restarted.");
            self.set_state(GuardState::NeedRestart);
        }
        self.interval = interval;
    }

    #[inline]
    pub fn set_guard_type(&mut self, guard_type: GuardType) {
        debug!("Setting guard_type: {:?}", guard_type);
        let should_restart = !self.get_state().is_stopped() && self.guard_type != guard_type;
        if should_restart {
            debug!("GuardType changed while running, monitor should be restarted.");
            self.set_state(GuardState::NeedRestart);
        }
        self.guard_type = guard_type;
    }

    #[inline]
    fn guard_sysproxy_static(sysproxy: &Sysproxy) {
        if let Ok(actually_sysproxy) = Sysproxy::get_system_proxy()
            && &actually_sysproxy != sysproxy
        {
            debug!(
                "Sysproxy settings do not match! Expected: {:?}, Actual: {:?}",
                sysproxy, actually_sysproxy
            );
            debug!("Resetting Sysproxy to: {:?}", sysproxy);
            if let Err(e) = sysproxy.set_system_proxy() {
                error!("Failed to set system proxy: {:?}", e);
            }
        }
    }

    #[inline]
    fn guard_autoproxy_static(autoproxy: &Autoproxy) {
        if let Ok(actually_autoproxy) = Autoproxy::get_auto_proxy()
            && &actually_autoproxy != autoproxy
        {
            debug!(
                "Autoproxy settings do not match! Expected: {:?}, Actual: {:?}",
                autoproxy, actually_autoproxy
            );
            debug!("Resetting Autoproxy to: {:?}", autoproxy);
            if let Err(e) = autoproxy.set_auto_proxy() {
                error!("Failed to set auto proxy: {:?}", e);
            }
        }
    }

    #[inline]
    pub fn start(&self) {
        debug!("Starting GuardMonitor...");

        let state = self.get_state();
        if state.is_running() || state.is_pendding() {
            debug!("GuardMonitor is already running or pending, skipping start.");
            return;
        }

        if self.get_state().is_need_restart() {
            debug!("GuardMonitor is in NeedRestart state, stopping and restarting...");
            self.stop();
            std::thread::sleep(Duration::from_millis(50));
        }

        if self
            .guard_stat
            .compare_exchange(
                GuardState::Stopped as u8,
                GuardState::Pending as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            debug!("GuardMonitor is not in Stopped state, skipping start.");
            return;
        }

        let config = TaskConfig {
            guard_type: self.guard_type.clone(),
            interval: self.interval,
        };
        let guard_stat = Arc::clone(&self.guard_stat);
        let notify = Arc::clone(&self.notify);
        tokio::spawn(async move {
            Self::run_monitor_loop(guard_stat, notify, config).await;
        });

        debug!("GuardMonitor spawned successfully.");
    }

    #[inline]
    async fn run_monitor_loop(guard_stat: Arc<AtomicU8>, notify: Arc<Notify>, config: TaskConfig) {
        let mut interval = tokio::time::interval(config.interval);
        debug!("GuardMonitor started with interval: {:?}", config.interval);

        guard_stat.store(GuardState::Running as u8, Ordering::Release);

        loop {
            let state = GuardState::from_u8(guard_stat.load(Ordering::Acquire));
            if state.is_stopped() {
                break;
            }
            if state.is_need_restart() {
                debug!("GuardMonitor detected NeedRestart state, stopping...");
                break;
            }

            tokio::select! {
                _ = interval.tick() => {
                    match &config.guard_type {
                        GuardType::Sysproxy(sysproxy) => {
                            debug!("GuardMonitor checking Sysproxy: {:?}", sysproxy);
                            Self::guard_sysproxy_static(sysproxy);
                        }
                        GuardType::Autoproxy(autoproxy) => {
                            debug!("GuardMonitor checking Autoproxy: {:?}", autoproxy);
                            Self::guard_autoproxy_static(autoproxy);
                        }
                        GuardType::None => {
                            debug!("GuardMonitor has no GuardType set, skipping check.");
                        }
                    }
                }
                _ = notify.notified() => {
                    debug!("GuardMonitor received stop notification.");
                    break;
                }
            }
        }

        guard_stat.store(GuardState::Stopped as u8, Ordering::Release);
    }

    #[inline]
    pub fn stop(&self) {
        debug!("Stopping GuardMonitor...");

        let state = self.get_state();
        if state.is_stopped() || state.is_pendding() {
            debug!("GuardMonitor is already stopped or pending, skipping stop.");
            return;
        }

        self.set_state(GuardState::Stopped);
        self.notify.notify_waiters();

        debug!("GuardMonitor has been stopped.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_guard_monitor_creation() {
        let target_auto_proxy = Autoproxy {
            url: "http://example.com/proxy.pac".to_string(),
            enable: true,
        };

        let guard_monitor = GuardMonitor::new(
            GuardType::Autoproxy(target_auto_proxy.clone()),
            Duration::from_secs(3),
        );

        assert!(!guard_monitor.get_state().is_running());
    }

    #[test]
    fn test_guard_monitor_sysproxy_creation() {
        let sysproxy = Sysproxy {
            enable: true,
            host: "127.0.0.1".to_string(),
            port: 8080,
            bypass: "localhost".to_string(),
        };

        let guard_monitor =
            GuardMonitor::new(GuardType::Sysproxy(sysproxy), Duration::from_secs(5));

        assert!(!guard_monitor.get_state().is_running());
    }

    #[tokio::test]
    async fn test_guard_monitor_start_stop() {
        let target_auto_proxy = Autoproxy {
            url: "http://example.com/proxy.pac".to_string(),
            enable: true,
        };

        let guard_monitor = GuardMonitor::new(
            GuardType::Autoproxy(target_auto_proxy),
            Duration::from_millis(100),
        );

        let monitor = Arc::new(guard_monitor);
        let monitor_clone = Arc::clone(&monitor);

        tokio::spawn(async move {
            let _ = &monitor_clone;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        monitor.start();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(monitor.get_state().is_running());

        monitor.stop();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!monitor.get_state().is_running());
    }

    #[tokio::test]
    async fn test_set_interval() {
        let target_auto_proxy = Autoproxy {
            url: "http://example.com/proxy.pac".to_string(),
            enable: true,
        };

        let mut guard_monitor = GuardMonitor::new(
            GuardType::Autoproxy(target_auto_proxy),
            Duration::from_secs(3),
        );

        guard_monitor.set_interval(Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_set_guard_type() {
        let initial_auto_proxy = Autoproxy {
            url: "http://example.com/proxy.pac".to_string(),
            enable: true,
        };

        let mut guard_monitor = GuardMonitor::new(
            GuardType::Autoproxy(initial_auto_proxy),
            Duration::from_secs(3),
        );

        let new_sysproxy = Sysproxy {
            enable: true,
            host: "192.168.1.1".to_string(),
            port: 3128,
            bypass: "*.local".to_string(),
        };

        guard_monitor.set_guard_type(GuardType::Sysproxy(new_sysproxy));
    }

    #[test]
    fn test_guard_autoproxy_matching() {
        let target_auto_proxy = Autoproxy {
            url: "http://example.com/proxy.pac".to_string(),
            enable: true,
        };

        let guard_monitor = GuardMonitor::new(
            GuardType::Autoproxy(target_auto_proxy.clone()),
            Duration::from_secs(1),
        );

        // This will call guard_autoproxy internally
        if let GuardType::Autoproxy(ref autoproxy) = guard_monitor.guard_type {
            assert_eq!(autoproxy.url, "http://example.com/proxy.pac");
            assert!(autoproxy.enable);
        }
    }

    #[test]
    fn test_guard_sysproxy_matching() {
        let sysproxy = Sysproxy {
            enable: true,
            host: "proxy.example.com".to_string(),
            port: 8888,
            bypass: "localhost,127.0.0.1".to_string(),
        };

        let guard_monitor = GuardMonitor::new(
            GuardType::Sysproxy(sysproxy.clone()),
            Duration::from_secs(2),
        );

        if let GuardType::Sysproxy(ref proxy) = guard_monitor.guard_type {
            assert_eq!(proxy.host, "proxy.example.com");
            assert_eq!(proxy.port, 8888);
            assert!(proxy.enable);
        }
    }

    #[test]
    fn test_guard_monitor_disabled_autoproxy() {
        let disabled_autoproxy = Autoproxy {
            url: "http://example.com/proxy.pac".to_string(),
            enable: false,
        };

        let guard_monitor = GuardMonitor::new(
            GuardType::Autoproxy(disabled_autoproxy.clone()),
            Duration::from_secs(1),
        );

        if let GuardType::Autoproxy(ref autoproxy) = guard_monitor.guard_type {
            assert!(!autoproxy.enable);
        }
    }

    #[test]
    fn test_guard_monitor_disabled_sysproxy() {
        let disabled_sysproxy = Sysproxy {
            enable: false,
            host: "127.0.0.1".to_string(),
            port: 8080,
            bypass: "localhost".to_string(),
        };

        let guard_monitor = GuardMonitor::new(
            GuardType::Sysproxy(disabled_sysproxy.clone()),
            Duration::from_secs(1),
        );

        if let GuardType::Sysproxy(ref proxy) = guard_monitor.guard_type {
            assert!(!proxy.enable);
        }
    }

    // State Machine Tests
    #[test]
    fn test_initial_state() {
        let monitor = GuardMonitor::new(GuardType::None, Duration::from_secs(1));
        assert!(monitor.get_state().is_stopped());
        assert!(!monitor.get_state().is_running());
        assert!(!monitor.get_state().is_pendding());
        assert!(!monitor.get_state().is_need_restart());
    }

    #[tokio::test]
    async fn test_state_transition_stopped_to_running() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(50),
        ));

        assert!(monitor.get_state().is_stopped());

        monitor.start();

        // Wait for state to become Running
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor.get_state().is_running());

        monitor.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(monitor.get_state().is_stopped());
    }

    #[tokio::test]
    async fn test_cannot_start_while_running() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(50),
        ));

        monitor.start();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor.get_state().is_running());

        // Try to start again - should be rejected
        monitor.start(); // This should return immediately

        // Should still be running from the first start
        assert!(monitor.get_state().is_running());

        monitor.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_cannot_start_while_pending() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(100),
        ));

        monitor.start();

        // Immediately try to start again (during Pendding state)
        tokio::time::sleep(Duration::from_millis(5)).await;
        let state = monitor.get_state();
        assert!(state.is_pendding() || state.is_running());

        monitor.start(); // Should be rejected

        monitor.stop();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    #[tokio::test]
    async fn test_stop_while_pending() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(200),
        ));

        monitor.start();

        // Stop immediately while in Pendding state
        tokio::time::sleep(Duration::from_millis(5)).await;
        monitor.stop();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(monitor.get_state().is_stopped());
    }

    #[tokio::test]
    async fn test_multiple_stop_calls() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(50),
        ));

        monitor.start();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor.get_state().is_running());

        // First stop
        monitor.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(monitor.get_state().is_stopped());

        // Second stop - should be safe and do nothing
        monitor.stop();
        assert!(monitor.get_state().is_stopped());
    }

    #[tokio::test]
    async fn test_need_restart_state_stops_monitor() {
        let monitor = GuardMonitor::new(
            GuardType::Autoproxy(Autoproxy {
                url: "http://example.com/proxy.pac".to_string(),
                enable: true,
            }),
            Duration::from_millis(50),
        );

        let monitor_arc = Arc::new(monitor);

        monitor_arc.start();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor_arc.get_state().is_running());

        // Simulate setting NeedRestart state
        monitor_arc.set_state(GuardState::NeedRestart);

        // Monitor should stop itself when it detects NeedRestart
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(monitor_arc.get_state().is_stopped());
    }

    #[tokio::test]
    async fn test_set_interval_while_running() {
        let monitor = GuardMonitor::new(GuardType::None, Duration::from_millis(50));

        let monitor_arc = Arc::new(monitor);

        monitor_arc.start();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor_arc.get_state().is_running());

        // This should set NeedRestart state (requires &mut self, so we can't test directly on Arc)
        // But we can verify the state machine behavior

        monitor_arc.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_concurrent_start_attempts() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(100),
        ));

        let mut handles = vec![];

        // Try to start 5 times concurrently
        for _ in 0..5 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = tokio::spawn(async move {
                monitor_clone.start();
            });
            handles.push(handle);
        }

        // Wait a bit for all attempts to register
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Only one should succeed - monitor should be in Running state
        assert!(monitor.get_state().is_running());

        monitor.stop();

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(monitor.get_state().is_stopped());
    }

    #[tokio::test]
    async fn test_restart_after_stop() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(50),
        ));

        // First start
        monitor.start();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor.get_state().is_running());

        monitor.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(monitor.get_state().is_stopped());

        // Second start - should work after proper stop
        monitor.start();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor.get_state().is_running());

        monitor.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(monitor.get_state().is_stopped());
    }

    #[tokio::test]
    async fn test_drop_stops_monitor() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(50),
        ));

        monitor.start();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(monitor.get_state().is_running());

        // Drop will call stop() implicitly
        drop(monitor);

        tokio::time::sleep(Duration::from_millis(100)).await;
        // Can't check state after drop, but monitor should have stopped gracefully
    }

    #[test]
    fn test_guard_state_conversions() {
        assert_eq!(GuardState::from_u8(0).to_u8(), 0);
        assert_eq!(GuardState::from_u8(1).to_u8(), 1);
        assert_eq!(GuardState::from_u8(2).to_u8(), 2);
        assert_eq!(GuardState::from_u8(3).to_u8(), 3);

        // Invalid value should default to Stopped
        assert!(GuardState::from_u8(99).is_stopped());
    }

    #[test]
    fn test_guard_state_display() {
        assert_eq!(format!("{}", GuardState::Running), "Running");
        assert_eq!(format!("{}", GuardState::Stopped), "Stopped");
        assert_eq!(format!("{}", GuardState::NeedRestart), "NeedRestart");
        assert_eq!(format!("{}", GuardState::Pending), "Pendding");
    }

    #[test]
    fn test_guard_monitor_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<GuardMonitor>();
    }

    #[test]
    fn test_guard_monitor_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<GuardMonitor>();
    }

    #[tokio::test]
    async fn test_send_across_threads() {
        let monitor = Arc::new(GuardMonitor::new(
            GuardType::None,
            Duration::from_millis(50),
        ));

        // Spawn multiple tasks across different threads
        let mut handles = vec![];
        for i in 0..3 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = tokio::spawn(async move {
                if i == 0 {
                    // First task starts the monitor
                    monitor_clone.start();
                } else {
                    // Other tasks try to read state
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let _state = monitor_clone.get_state();
                }
            });
            handles.push(handle);
        }

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(monitor.get_state().is_running());

        monitor.stop();

        for handle in handles {
            let _ = handle.await;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(monitor.get_state().is_stopped());
    }
}
