#![allow(improper_ctypes, non_camel_case_types, non_upper_case_globals, non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::{CStr, CString};
use std::io::pipe;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static GLOBAL_MANAGER_NAME: AtomicU32 = AtomicU32::new(0);
static GLOBAL_MANAGER_VERSION: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn registry_global(
    _data: *mut std::ffi::c_void,
    _registry: *mut wl_registry,
    name: u32,
    interface: *const std::os::raw::c_char,
    version: u32,
) {
    if let Ok(iface) = CStr::from_ptr(interface).to_str() {
        if iface == "wp_security_context_manager_v1" {
            GLOBAL_MANAGER_NAME.store(name, Ordering::Release);
            GLOBAL_MANAGER_VERSION.store(version, Ordering::Release);
        }
    }
}

unsafe extern "C" fn registry_global_remove(
    _data: *mut std::ffi::c_void,
    _registry: *mut wl_registry,
    _name: u32,
) {
}

const REGISTRY_LISTENER: wl_registry_listener = wl_registry_listener {
    global: Some(registry_global),
    global_remove: Some(registry_global_remove),
};

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_: i32) {
    SHOULD_EXIT.store(true, Ordering::SeqCst);
}

fn usage() {
    eprintln!(
        concat!(
            "Usage: wl-container [OPTIONS] SOCKET_PATH\n\n",
            "Create Wayland security context at SOCKET_PATH\n",
            "\t-e ENGINE    Engine ID for security context\n",
            "\t-a APP_ID    App ID for security context\n",
            "\t-i INSTANCE  Instance ID for security context\n",
            "\t-h           Show help and exit\n",
        )
    );
}

fn parse_args() -> Result<Args, String> {
    let mut raw: Vec<String> = std::env::args().collect();
    raw.remove(0);

    let mut sandbox_engine = None;
    let mut app_id = None;
    let mut instance_id = None;

    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "-e" | "--sandbox-engine" => {
                i += 1;
                let v = raw.get(i).ok_or("--sandbox-engine requires a value")?;
                sandbox_engine =
                    Some(CString::new(v.as_bytes()).map_err(|_| "engine name contains null byte")?);
            }
            "-a" | "--app-id" => {
                i += 1;
                let v = raw.get(i).ok_or("--app-id requires a value")?;
                app_id =
                    Some(CString::new(v.as_bytes()).map_err(|_| "app-id contains null byte")?);
            }
            "-i" | "--instance-id" => {
                i += 1;
                let v = raw.get(i).ok_or("--instance-id requires a value")?;
                instance_id = Some(
                    CString::new(v.as_bytes()).map_err(|_| "instance-id contains null byte")?,
                );
            }
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unexpected argument: {other}"));
            }
            _ => break,
        }
        i += 1;
    }

    let path = raw.get(i).ok_or("missing SOCKET_PATH")?;
    i += 1;

    if i < raw.len() {
        return Err(format!("unexpected positional argument: {}", raw[i]));
    }

    Ok(Args {
        socket_path: PathBuf::from(path),
        sandbox_engine,
        app_id,
        instance_id,
    })
}

struct Args {
    socket_path: PathBuf,
    sandbox_engine: Option<CString>,
    app_id: Option<CString>,
    instance_id: Option<CString>,
}

unsafe fn display_get_registry(display: *mut wl_display) -> *mut wl_registry {
    let version = wl_proxy_get_version(display as *mut wl_proxy);
    let mut args = [wl_argument { n: 0 }];
    wl_proxy_marshal_array_flags(
        display as *mut wl_proxy,
        WL_DISPLAY_GET_REGISTRY,
        &wl_registry_interface,
        version,
        0,
        args.as_mut_ptr(),
    ) as *mut wl_registry
}

unsafe fn registry_bind(
    registry: *mut wl_registry,
    name: u32,
    iface: *const wl_interface,
    version: u32,
) -> *mut wl_proxy {
    let iface_name = (*iface).name;
    let mut args = [
        wl_argument { u: name },
        wl_argument {
            s: iface_name,
        },
        wl_argument { u: version },
        wl_argument { n: 0 },
    ];
    wl_proxy_marshal_array_flags(
        registry as *mut wl_proxy,
        WL_REGISTRY_BIND,
        iface,
        version,
        0,
        args.as_mut_ptr(),
    )
}

unsafe fn context_create_listener(
    manager: *mut wl_proxy,
    listen_fd: RawFd,
    close_fd: RawFd,
) -> *mut wl_proxy {
    let version = wl_proxy_get_version(manager);
    let mut args = [
        wl_argument { n: 0 },
        wl_argument { h: listen_fd },
        wl_argument { h: close_fd },
    ];
    wl_proxy_marshal_array_flags(
        manager,
        WP_SECURITY_CONTEXT_MANAGER_V1_CREATE_LISTENER,
        &wp_security_context_v1_interface,
        version,
        0,
        args.as_mut_ptr(),
    )
}

unsafe fn ctx_set(proxy: *mut wl_proxy, opcode: u32, s: *const std::os::raw::c_char) {
    let v = wl_proxy_get_version(proxy);
    let mut a = [wl_argument { s }];
    wl_proxy_marshal_array_flags(proxy, opcode, std::ptr::null(), v, 0, a.as_mut_ptr());
}

unsafe fn ctx_set_sandbox_engine(ctx: *mut wl_proxy, s: *const std::os::raw::c_char) {
    ctx_set(ctx, WP_SECURITY_CONTEXT_V1_SET_SANDBOX_ENGINE, s)
}

unsafe fn ctx_set_app_id(ctx: *mut wl_proxy, s: *const std::os::raw::c_char) {
    ctx_set(ctx, WP_SECURITY_CONTEXT_V1_SET_APP_ID, s)
}

unsafe fn ctx_set_instance_id(ctx: *mut wl_proxy, s: *const std::os::raw::c_char) {
    ctx_set(ctx, WP_SECURITY_CONTEXT_V1_SET_INSTANCE_ID, s)
}

unsafe fn ctx_commit(ctx: *mut wl_proxy) {
    let v = wl_proxy_get_version(ctx);
    wl_proxy_marshal_array_flags(ctx, WP_SECURITY_CONTEXT_V1_COMMIT, std::ptr::null(), v, 0, std::ptr::null_mut());
}

unsafe fn ctx_destroy(ctx: *mut wl_proxy) {
    let v = wl_proxy_get_version(ctx);
    wl_proxy_marshal_array_flags(ctx, WP_SECURITY_CONTEXT_V1_DESTROY, std::ptr::null(), v, WL_MARSHAL_FLAG_DESTROY, std::ptr::null_mut());
}

unsafe fn manager_destroy(mgr: *mut wl_proxy) {
    let v = wl_proxy_get_version(mgr);
    wl_proxy_marshal_array_flags(mgr, WP_SECURITY_CONTEXT_MANAGER_V1_DESTROY, std::ptr::null(), v, WL_MARSHAL_FLAG_DESTROY, std::ptr::null_mut());
}

unsafe fn create_context(
    listen_fd: RawFd,
    close_fd: RawFd,
    sandbox_engine: Option<&CStr>,
    app_id: Option<&CStr>,
    instance_id: Option<&CStr>,
) -> Result<(), String> {
    let display = wl_display_connect(std::ptr::null());
    if display.is_null() {
        return Err("Cannot connect to Wayland display".into());
    }

    let registry = display_get_registry(display);

    GLOBAL_MANAGER_NAME.store(0, Ordering::Release);
    GLOBAL_MANAGER_VERSION.store(0, Ordering::Release);

    if wl_proxy_add_listener(
        registry as *mut wl_proxy,
        &REGISTRY_LISTENER as *const wl_registry_listener as *mut Option<unsafe extern "C" fn()>,
        std::ptr::null_mut(),
    ) < 0
    {
        wl_display_disconnect(display);
        return Err("Cannot add registry listener".into());
    }

    wl_display_roundtrip(display);

    let name = GLOBAL_MANAGER_NAME.load(Ordering::Acquire);
    let ver = GLOBAL_MANAGER_VERSION.load(Ordering::Acquire);
    if name == 0 {
        wl_display_disconnect(display);
        return Err("Compositor does not expose wp_security_context_manager_v1".into());
    }

    let manager = registry_bind(registry, name, &wp_security_context_manager_v1_interface, ver.min(1));
    if manager.is_null() {
        wl_display_disconnect(display);
        return Err("Cannot bind to wp_security_context_manager_v1".into());
    }

    let ctx = context_create_listener(manager, listen_fd, close_fd);
    if ctx.is_null() {
        manager_destroy(manager);
        wl_display_disconnect(display);
        return Err("Cannot create security context listener".into());
    }

    if let Some(e) = sandbox_engine {
        ctx_set_sandbox_engine(ctx, e.as_ptr());
    }
    if let Some(a) = app_id {
        ctx_set_app_id(ctx, a.as_ptr());
    }
    if let Some(i) = instance_id {
        ctx_set_instance_id(ctx, i.as_ptr());
    }

    ctx_commit(ctx);
    ctx_destroy(ctx);
    manager_destroy(manager);

    wl_display_roundtrip(display);
    wl_display_disconnect(display);
    Ok(())
}

struct Socket {
    path: PathBuf,
    _listener: OwnedFd,
}

impl Socket {
    fn new(path: PathBuf) -> Result<Self, String> {
        let listener = UnixListener::bind(&path).map_err(|e| format!("binding socket: {e}"))?;
        let _listener = OwnedFd::from(listener);
        Ok(Self { path, _listener })
    }

    fn listen_fd(&self) -> RawFd {
        self._listener.as_raw_fd()
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn main() {
    unsafe {
        libc::signal(libc::SIGINT, handle_signal as *const () as usize);
        libc::signal(libc::SIGTERM, handle_signal as *const () as usize);
    }

    let args = parse_args().unwrap_or_else(|e| {
        usage();
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    let _socket = Socket::new(args.socket_path).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let listen_fd = _socket.listen_fd();

    let (_r, _w) = pipe().unwrap_or_else(|e| {
        eprintln!("error: creating pipe: {e}");
        std::process::exit(1);
    });
    let close_fd: OwnedFd = _r.into();

    unsafe {
        create_context(
            listen_fd,
            close_fd.as_raw_fd(),
            args.sandbox_engine.as_deref(),
            args.app_id.as_deref(),
            args.instance_id.as_deref(),
        )
    }
    .unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    loop {
        let mut pfd = libc::pollfd {
            fd: close_fd.as_raw_fd(),
            events: libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        match unsafe { libc::poll(&mut pfd, 1, -1) } {
            -1 => {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    if SHOULD_EXIT.load(Ordering::Acquire) {
                        break;
                    }
                    continue;
                }
                eprintln!("error: poll failed: {err}");
                break;
            }
            _ => break,
        }
    }
}
