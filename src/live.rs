//! Frida Core ownership and event delivery. All device/session operations stay on
//! their creating thread; only GLib's thread-safe cancellation crosses threads.
use anyhow::{anyhow, bail, Context, Result};
use frida_sys as ffi;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    collections::HashMap,
    ffi::{c_char, c_void, CStr, CString, OsString},
    marker::PhantomData,
    ptr::{self, NonNull},
    rc::Rc,
    sync::{mpsc, Arc, Mutex, Once},
    thread,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(10);

struct Object<T>(NonNull<T>);
impl<T> Object<T> {
    // Only full, owned GObject references may enter this wrapper.
    unsafe fn owned(p: *mut T) -> Result<Self> {
        NonNull::new(p)
            .map(Self)
            .ok_or_else(|| anyhow!("Frida returned a null object"))
    }
    fn as_ptr(&self) -> *mut T {
        self.0.as_ptr()
    }
}
impl<T> Drop for Object<T> {
    fn drop(&mut self) {
        unsafe { ffi::frida_unref(self.as_ptr().cast()) }
    }
}

struct Cancellation(*mut ffi::GCancellable);
// GLib explicitly allows cancelling a GCancellable from another thread.
unsafe impl Send for Cancellation {}
unsafe impl Sync for Cancellation {}
impl Cancellation {
    fn cancel(&self) {
        unsafe { ffi::g_cancellable_cancel(self.0) }
    }
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        unsafe { ffi::g_object_unref(self.0.cast()) }
    }
}
fn call<T>(
    name: &str,
    f: impl FnOnce(*mut ffi::GCancellable, *mut *mut ffi::GError) -> T,
) -> Result<T> {
    let cancel = Arc::new(Cancellation(unsafe { ffi::g_cancellable_new() }));
    let timer_cancel = cancel.clone();
    let (tx, rx) = mpsc::channel();
    let timer = thread::spawn(move || {
        if rx.recv_timeout(TIMEOUT) == Err(mpsc::RecvTimeoutError::Timeout) {
            timer_cancel.cancel();
        }
    });
    let mut error = ptr::null_mut();
    let value = f(cancel.0, &mut error);
    let _ = tx.send(());
    let _ = timer.join();
    if !error.is_null() {
        let message = unsafe {
            let text = text((*error).message);
            ffi::g_error_free(error);
            text
        };
        bail!("{name}: {message}");
    }
    Ok(value)
}
unsafe fn text(s: *const c_char) -> String {
    if s.is_null() {
        String::new()
    } else {
        CStr::from_ptr(s).to_string_lossy().into_owned()
    }
}

struct ContextLoop {
    raw: *mut ffi::GMainContext,
    _thread: PhantomData<Rc<()>>,
}
impl ContextLoop {
    fn new() -> Self {
        static INIT: Once = Once::new();
        INIT.call_once(|| unsafe { ffi::frida_init() });
        // Use the default loop as in Frida's native embedding example. A custom
        // thread-default context also redirects backend startup and can deadlock
        // macOS simulator discovery against Frida's own worker loop.
        Self {
            raw: unsafe { ffi::g_main_context_ref(ffi::g_main_context_default()) },
            _thread: PhantomData,
        }
    }
    fn pump(&self) {
        // Bound each batch so a busy target cannot starve the host's deadline.
        for _ in 0..256 {
            if unsafe { ffi::g_main_context_iteration(self.raw, 0) } == 0 {
                break;
            }
        }
    }
}
impl Drop for ContextLoop {
    fn drop(&mut self) {
        unsafe { ffi::g_main_context_unref(self.raw) }
    }
}

struct Device {
    device: Object<ffi::FridaDevice>,
    manager: Object<ffi::FridaDeviceManager>,
    context: ContextLoop,
}
impl Device {
    fn kill(&self, pid: u32) -> Result<()> {
        call("kill spawned renderer", |c, e| unsafe {
            ffi::frida_device_kill_sync(self.device.as_ptr(), pid, c, e)
        })
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _ = call("close device manager", |c, e| unsafe {
            ffi::frida_device_manager_close_sync(self.manager.as_ptr(), c, e)
        });
    }
}

#[derive(Debug)]
pub struct Process {
    pub pid: u32,
    pub name: String,
}

pub struct Monitor {
    device: Rc<Device>,
    sender: mpsc::Sender<Value>,
    receiver: mpsc::Receiver<Value>,
}
impl Monitor {
    pub fn new(kind: &str) -> Result<Self> {
        let dtype = match kind {
            "local" => ffi::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL,
            "usb" => ffi::FridaDeviceType_FRIDA_DEVICE_TYPE_USB,
            _ => bail!("unknown device {kind:?}"),
        };
        let context = ContextLoop::new();
        let (manager, device) = {
            unsafe {
                let manager = Object::owned(ffi::frida_device_manager_new())?;
                let device = Object::owned(call("find Frida device", |c, e| {
                    ffi::frida_device_manager_get_device_by_type_sync(
                        manager.as_ptr(),
                        dtype,
                        5000,
                        c,
                        e,
                    )
                })?)?;
                (manager, device)
            }
        };
        let (sender, receiver) = mpsc::channel();
        Ok(Self {
            device: Rc::new(Device {
                device,
                manager,
                context,
            }),
            sender,
            receiver,
        })
    }
    pub fn drain(&self) -> Vec<Value> {
        self.device.context.pump();
        self.receiver.try_iter().collect()
    }
    pub fn processes(&self) -> Result<Vec<Process>> {
        unsafe {
            let list = Object::owned(call("enumerate processes", |c, e| {
                ffi::frida_device_enumerate_processes_sync(
                    self.device.device.as_ptr(),
                    ptr::null_mut(),
                    c,
                    e,
                )
            })?)?;
            let mut result = vec![];
            for i in 0..ffi::frida_process_list_size(list.as_ptr()) {
                let process = Object::owned(ffi::frida_process_list_get(list.as_ptr(), i))?;
                result.push(Process {
                    pid: ffi::frida_process_get_pid(process.as_ptr()),
                    name: text(ffi::frida_process_get_name(process.as_ptr())),
                });
            }
            Ok(result)
        }
    }
    pub fn attach(&self, target: &str) -> Result<Session> {
        let (pid, name) = if let Ok(pid) = target.parse::<u32>() {
            (pid, String::new())
        } else {
            let mut hits = self.processes()?.into_iter().filter(|p| p.name == target);
            let p = hits
                .next()
                .context("no process with that name; use its PID")?;
            if hits.next().is_some() {
                bail!("multiple processes named {target}; use its PID");
            }
            (p.pid, p.name)
        };
        self.attach_pid(pid, name, false, crate::AGENT_SOURCE)
    }
    pub fn spawn(&self, argv: &[OsString]) -> Result<Session> {
        self.spawn_agent(argv, crate::AGENT_SOURCE)
    }
    fn spawn_agent(&self, argv: &[OsString], source: &str) -> Result<Session> {
        if argv.is_empty() {
            bail!("spawn requires an executable");
        }
        let strings: Vec<CString> = argv
            .iter()
            .map(|s| CString::new(s.as_encoded_bytes()))
            .collect::<std::result::Result<_, _>>()?;
        let mut pointers: Vec<*mut c_char> =
            strings.iter().map(|s| s.as_ptr().cast_mut()).collect();
        let pid = unsafe {
            let options = Object::owned(ffi::frida_spawn_options_new())?;
            ffi::frida_spawn_options_set_argv(
                options.as_ptr(),
                pointers.as_mut_ptr(),
                pointers.len().try_into()?,
            );
            call("spawn renderer", |c, e| {
                ffi::frida_device_spawn_sync(
                    self.device.device.as_ptr(),
                    strings[0].as_ptr(),
                    options.as_ptr(),
                    c,
                    e,
                )
            })?
        };
        // attach_pid takes ownership of the suspended spawn on entry, including
        // the attach-failure path. Dropping a session always cleans it up.
        let session = self.attach_pid(pid, argv[0].to_string_lossy().into_owned(), true, source)?;
        call("resume renderer", |c, e| unsafe {
            ffi::frida_device_resume_sync(self.device.device.as_ptr(), pid, c, e)
        })?;
        Ok(session)
    }
    fn attach_pid(&self, pid: u32, name: String, spawned: bool, source: &str) -> Result<Session> {
        let raw = call("attach", |c, e| unsafe {
            ffi::frida_device_attach_sync(self.device.device.as_ptr(), pid, ptr::null_mut(), c, e)
        });
        let raw = match raw.and_then(|p| unsafe { Object::owned(p) }) {
            Ok(raw) => raw,
            Err(e) => {
                if spawned {
                    let _ = self.device.kill(pid);
                }
                return Err(e);
            }
        };
        let state = Arc::new(Mutex::new(State {
            pid,
            name,
            sender: self.sender.clone(),
            capability: json!({}),
            failure: None,
            detached: None,
            replies: HashMap::new(),
        }));
        let mut session = Session {
            pid,
            spawned,
            device: self.device.clone(),
            raw,
            script: None,
            state,
            message_handler: 0,
            detach_handler: 0,
            next_rpc: Cell::new(0),
            closed: false,
        };
        unsafe {
            session.detach_handler = connect(
                session.raw.as_ptr().cast(),
                c"detached",
                Some(std::mem::transmute::<
                    unsafe extern "C" fn(
                        *mut ffi::FridaSession,
                        ffi::FridaSessionDetachReason,
                        *mut ffi::FridaCrash,
                        *mut c_void,
                    ),
                    unsafe extern "C" fn(),
                >(on_detached)),
                &session.state,
            );
            let source = CString::new(source)?;
            session.script = Some(Object::owned(call("create agent", |c, e| {
                ffi::frida_session_create_script_sync(
                    session.raw.as_ptr(),
                    source.as_ptr(),
                    ptr::null_mut(),
                    c,
                    e,
                )
            })?)?);
            let script = session.script.as_ref().unwrap().as_ptr();
            session.message_handler = connect(
                script.cast(),
                c"message",
                Some(std::mem::transmute::<
                    unsafe extern "C" fn(
                        *mut ffi::FridaScript,
                        *const c_char,
                        *mut ffi::GBytes,
                        *mut c_void,
                    ),
                    unsafe extern "C" fn(),
                >(on_message)),
                &session.state,
            );
            call("load agent", |c, e| {
                ffi::frida_script_load_sync(script, c, e)
            })?;
        }
        // The RPC reply is a barrier after all boot messages and verifies that
        // hooks exist before the suspended target is allowed to execute.
        let cap = session.capability()?;
        if !cap["hooks"].as_array().is_some_and(|a| !a.is_empty()) {
            bail!("agent initialized without any usable hooks");
        }
        Ok(session)
    }
}

struct State {
    pid: u32,
    name: String,
    sender: mpsc::Sender<Value>,
    capability: Value,
    failure: Option<String>,
    detached: Option<String>,
    replies: HashMap<u64, std::result::Result<Value, String>>,
}
impl State {
    fn identify(&self, v: &mut Value) {
        v["pid"] = json!(self.pid);
        v["proc"] = json!(self.name);
    }
    fn emit(&self, mut v: Value) {
        self.identify(&mut v);
        let _ = self.sender.send(v);
    }
    fn message(&mut self, message: Value) {
        if message["type"] == "send" {
            let mut payload = message["payload"].clone();
            if payload[0] == "frida:rpc" {
                if let Some(id) = payload[1].as_u64() {
                    let result = if payload[2] == "ok" {
                        Ok(payload[3].clone())
                    } else {
                        Err(payload[3].to_string())
                    };
                    self.replies.insert(id, result);
                }
            } else if payload.is_object() {
                self.identify(&mut payload);
                if payload["type"] == "capability" {
                    self.capability = payload.clone();
                }
                self.emit(payload);
            }
        } else if message["type"] == "error" {
            self.failure = Some(
                message["description"]
                    .as_str()
                    .unwrap_or("unknown agent error")
                    .into(),
            );
            self.emit(json!({"type":"error", "detail":message}));
        }
    }
}
type SharedState = Arc<Mutex<State>>;
unsafe extern "C" fn free_state(data: *mut c_void, _: *mut ffi::GClosure) {
    drop(Box::from_raw(data.cast::<SharedState>()));
}
unsafe fn connect(
    object: *mut c_void,
    signal: &CStr,
    callback: ffi::GCallback,
    state: &SharedState,
) -> u64 {
    ffi::g_signal_connect_data(
        object,
        signal.as_ptr(),
        callback,
        Box::into_raw(Box::new(state.clone())).cast(),
        Some(free_state),
        ffi::GConnectFlags_G_CONNECT_DEFAULT,
    )
}
unsafe extern "C" fn on_message(
    script: *mut ffi::FridaScript,
    message: *const c_char,
    _: *mut ffi::GBytes,
    data: *mut c_void,
) {
    // No Rust unwinding may cross the C callback boundary.
    let _ = std::panic::catch_unwind(|| {
        let state = &*data.cast::<SharedState>();
        if let Ok(v) = serde_json::from_str::<Value>(&text(message)) {
            let completed = v["type"] == "send" && v["payload"]["rule"] == "render-complete";
            state.lock().unwrap_or_else(|e| e.into_inner()).message(v);
            if completed {
                ffi::frida_script_post(
                    script,
                    c"{\"type\":\"hotcell:complete-ack\"}".as_ptr(),
                    ptr::null_mut(),
                );
            }
        }
    });
}
unsafe extern "C" fn on_detached(
    _: *mut ffi::FridaSession,
    reason: ffi::FridaSessionDetachReason,
    crash: *mut ffi::FridaCrash,
    data: *mut c_void,
) {
    let _ = std::panic::catch_unwind(|| {
        let reason = match reason {
            ffi::FridaSessionDetachReason_FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED => {
                "application-requested"
            }
            ffi::FridaSessionDetachReason_FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED => {
                "process-replaced"
            }
            ffi::FridaSessionDetachReason_FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED => {
                "process-terminated"
            }
            ffi::FridaSessionDetachReason_FRIDA_SESSION_DETACH_REASON_CONNECTION_TERMINATED => {
                "connection-terminated"
            }
            ffi::FridaSessionDetachReason_FRIDA_SESSION_DETACH_REASON_DEVICE_LOST => "device-lost",
            _ => "unknown",
        };
        let crash = if crash.is_null() {
            None
        } else {
            Some(text(ffi::frida_crash_get_summary(crash)))
        };
        let mut state = (&*data.cast::<SharedState>())
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.detached = Some(reason.into());
        state.emit(json!({"type":"detached", "reason":reason, "crash":crash}));
    });
}

pub struct Session {
    pub pid: u32,
    spawned: bool,
    device: Rc<Device>,
    raw: Object<ffi::FridaSession>,
    script: Option<Object<ffi::FridaScript>>,
    state: SharedState,
    message_handler: u64,
    detach_handler: u64,
    next_rpc: Cell<u64>,
    closed: bool,
}
impl Session {
    pub fn detached(&self) -> bool {
        self.device.context.pump();
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .detached
            .is_some()
    }
    pub fn capability(&self) -> Result<Value> {
        self.device.context.pump();
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(error) = &state.failure {
                bail!("agent initialization/execution failed: {error}");
            }
            if state.detached.is_some() {
                return Ok(state.capability.clone());
            }
        }
        let id = self.next_rpc.get() + 1;
        self.next_rpc.set(id);
        let request = CString::new(json!(["frida:rpc", id, "call", "status", []]).to_string())?;
        let script = self.script.as_ref().context("agent not loaded")?;
        unsafe { ffi::frida_script_post(script.as_ptr(), request.as_ptr(), ptr::null_mut()) };
        let start = Instant::now();
        loop {
            self.device.context.pump();
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(error) = &state.failure {
                    bail!("agent initialization/execution failed: {error}");
                }
                if let Some(reply) = state.replies.remove(&id) {
                    let mut cap = reply.map_err(|e| anyhow!("agent status RPC: {e}"))?;
                    if !cap.is_object() {
                        bail!("agent returned invalid capabilities");
                    }
                    state.identify(&mut cap);
                    state.capability = cap.clone();
                    return Ok(cap);
                }
                if state.detached.as_deref() == Some("process-terminated") {
                    return Ok(state.capability.clone());
                }
                if let Some(reason) = &state.detached {
                    bail!("target detached during status RPC: {reason}");
                }
            }
            if start.elapsed() >= TIMEOUT {
                bail!("agent status RPC timed out");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if !self.detached() {
            if self.script.is_some() {
                let _ = self.capability();
            }
            if self.spawned {
                let _ = self.device.kill(self.pid);
            }
            let _ = call("detach", |c, e| unsafe {
                ffi::frida_session_detach_sync(self.raw.as_ptr(), c, e)
            });
        }
        self.device.context.pump();
        unsafe {
            if self.message_handler != 0 {
                ffi::g_signal_handler_disconnect(
                    self.script.as_ref().unwrap().as_ptr().cast(),
                    self.message_handler,
                );
            }
            if self.detach_handler != 0 {
                ffi::g_signal_handler_disconnect(self.raw.as_ptr().cast(), self.detach_handler);
            }
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> (State, mpsc::Receiver<Value>) {
        let (sender, receiver) = mpsc::channel();
        (
            State {
                pid: 123,
                name: "probe".into(),
                sender,
                capability: json!({}),
                failure: None,
                detached: None,
                replies: HashMap::new(),
            },
            receiver,
        )
    }

    #[test]
    fn boot_events_are_buffered_with_host_process_identity() {
        let (mut state, receiver) = state();
        state.message(
            json!({"type":"send","payload":{"type":"capability","pid":999,"hooks":["bbox"]}}),
        );
        let event = receiver.try_recv().unwrap();
        assert_eq!(event["pid"], 123);
        assert_eq!(event["proc"], "probe");
        assert_eq!(state.capability, event);
    }

    #[test]
    fn agent_error_is_retained_and_delivered() {
        let (mut state, receiver) = state();
        state.message(json!({"type":"error","description":"initialization failed"}));
        assert_eq!(state.failure.as_deref(), Some("initialization failed"));
        assert_eq!(
            receiver.try_recv().unwrap()["detail"]["description"],
            "initialization failed"
        );
    }

    #[test]
    fn status_rpc_replies_are_separate_from_observed_signals() {
        let (mut state, receiver) = state();
        state.message(json!({"type":"send","payload":["frida:rpc",1,"ok",{"hooks":["bbox"]}]}));
        state.message(json!({"type":"send","payload":["frida:rpc",2,"error","failed"]}));
        assert_eq!(
            state.replies.remove(&1).unwrap().unwrap()["hooks"],
            json!(["bbox"])
        );
        assert!(state.replies.remove(&2).unwrap().is_err());
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "requires local macOS Frida instrumentation"]
    fn startup_failure_never_resumes_and_cleans_up_spawn() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("probe.c");
        let executable = root.path().join("probe");
        let marker = root.path().join("resumed");
        std::fs::write(&source,b"#include <stdio.h>\nint main(int argc,char **argv){FILE *f=fopen(argv[1],\"w\");if(f)fclose(f);return 0;}\n").unwrap();
        assert!(std::process::Command::new("clang")
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success());
        let monitor = Monitor::new("local").unwrap();
        for agent in [
            "throw new Error('controlled boot failure');",
            "send({type:'capability',hooks:[]}); rpc.exports={status(){return {hooks:[]};}};",
        ] {
            let error = monitor
                .spawn_agent(&[executable.clone().into(), marker.clone().into()], agent)
                .err()
                .expect("startup must fail");
            assert!(
                error.to_string().contains("failure") || error.to_string().contains("usable hooks"),
                "{error:#}"
            );
            assert!(
                !marker.exists(),
                "target executed despite failed agent startup"
            );
            let events = monitor.drain();
            let pid = events
                .iter()
                .find_map(|e| e["pid"].as_u64())
                .expect("failure events must retain process identity") as u32;
            assert!(
                !monitor.processes().unwrap().iter().any(|p| p.pid == pid),
                "suspended target leaked after failed initialization"
            );
        }
    }
}
