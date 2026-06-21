#![allow(improper_ctypes, non_camel_case_types, non_upper_case_globals, non_snake_case, dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{pipe, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Registry listener globals (set from C callback)
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
fn usage() {
    eprintln!(
        concat!(
            "Usage: wl-container [OPTIONS] --socket-fd SOCKET_FD\n",
            "       wl-container [OPTIONS] --socket-path SOCKET_PATH\n\n",
            "Create Wayland security context at SOCKET_FD\n",
            "\t-e ENGINE    Engine ID for security context\n",
            "\t-a APP_ID    App ID for security context\n",
            "\t-i INSTANCE  Instance ID for security context\n",
            "\t-c FD        Stop listening when FD closes\n",
            "\t-r FD        Notify readiness on FD\n",
            "\t-h           Show help and exit\n",
            "\nSee 'man wl-container' for details.",
        )
    );
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
fn parse_args() -> Result<Args, String> {
    let mut raw: Vec<String> = std::env::args().collect();
    raw.remove(0);
    let mut a = Args::default();

    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "-s" | "--socket-fd" => {
                i += 1;
                a.socket_fd = Some(
                    raw.get(i)
                        .ok_or("--socket-fd requires a value")?
                        .parse::<RawFd>()
                        .map_err(|_| "invalid fd")?,
                );
            }
            "-S" | "--socket-path" => {
                i += 1;
                a.socket_path = Some(
                    PathBuf::from(raw.get(i).ok_or("--socket-path requires a value")?),
                );
            }
            "-e" | "--sandbox-engine" => {
                i += 1;
                let v = raw.get(i).ok_or("--sandbox-engine requires a value")?;
                a.sandbox_engine =
                    Some(CString::new(v.as_bytes()).map_err(|_| "engine name contains null byte")?);
            }
            "-a" | "--app-id" => {
                i += 1;
                let v = raw.get(i).ok_or("--app-id requires a value")?;
                a.app_id =
                    Some(CString::new(v.as_bytes()).map_err(|_| "app-id contains null byte")?);
            }
            "-i" | "--instance-id" => {
                i += 1;
                let v = raw.get(i).ok_or("--instance-id requires a value")?;
                a.instance_id = Some(
                    CString::new(v.as_bytes()).map_err(|_| "instance-id contains null byte")?,
                );
            }
            "-c" | "--close-fd" => {
                i += 1;
                a.close_fd = Some(
                    raw.get(i)
                        .ok_or("--close-fd requires a value")?
                        .parse::<RawFd>()
                        .map_err(|_| "invalid fd")?,
                );
            }
            "-r" | "--ready-fd" => {
                i += 1;
                a.ready_fd = Some(
                    raw.get(i)
                        .ok_or("--ready-fd requires a value")?
                        .parse::<RawFd>()
                        .map_err(|_| "invalid fd")?,
                );
            }
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unexpected argument: {other}"));
            }
            _ => {
                return Err(format!("unexpected positional argument: {}", raw[i]));
            }
        }
        i += 1;
    }
    Ok(a)
}

struct Args {
    socket_fd: Option<RawFd>,
    socket_path: Option<PathBuf>,
    sandbox_engine: Option<CString>,
    app_id: Option<CString>,
    instance_id: Option<CString>,
    close_fd: Option<RawFd>,
    ready_fd: Option<RawFd>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            socket_fd: None,
            socket_path: None,
            sandbox_engine: None,
            app_id: None,
            instance_id: None,
            close_fd: None,
            ready_fd: None,
        }
    }
}

impl Args {
    fn validate(&self) -> Result<(), String> {
        match (self.socket_fd, &self.socket_path) {
            (Some(_), None) => Ok(()),
            (None, Some(_)) => Ok(()),
            (None, None) => Err("No socket fd or socket path specified".into()),
            (Some(_), Some(_)) => Err("Cannot use both socket fd and socket path".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Wayland helpers — each wraps wl_proxy_marshal_array_flags with typed args
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
fn main() {
    let args = parse_args().unwrap_or_else(|e| {
        usage();
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    if let Err(e) = args.validate() {
        usage();
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    let _keep_listener: Option<OwnedFd>;
    let listen_fd: RawFd = match (args.socket_fd, args.socket_path) {
        (Some(fd), None) => {
            _keep_listener = None;
            fd
        }
        (None, Some(path)) => {
            let listener = UnixListener::bind(path).unwrap_or_else(|e| {
                eprintln!("error: binding socket: {e}");
                std::process::exit(1);
            });
            let owned = OwnedFd::from(listener);
            let fd = owned.as_raw_fd();
            _keep_listener = Some(owned);
            fd
        }
        _ => unreachable!(),
    };

    let ready_fd = args.ready_fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });

    let mut alive_fd = None;
    let close_fd: OwnedFd = if let Some(fd) = args.close_fd {
        unsafe { OwnedFd::from_raw_fd(fd) }
    } else {
        let (r, w) = pipe().unwrap_or_else(|e| {
            eprintln!("error: creating pipe: {e}");
            std::process::exit(1);
        });
        alive_fd = Some(w);
        OwnedFd::from(r)
    };

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

    if let Some(fd) = ready_fd {
        File::from(fd)
            .write_all(b"\n")
            .unwrap_or_else(|e| eprintln!("error: writing to ready-fd: {e}"));
    }

    if alive_fd.is_some() {
        loop {
            std::thread::park();
        }
    }
}
