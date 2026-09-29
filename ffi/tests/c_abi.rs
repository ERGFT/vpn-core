// SPDX-License-Identifier: GPL-3.0-or-later
//! C ABI из Rust (на всех платформах CI; C-программа — scripts/ffi_smoke.sh).

use std::ffi::{c_char, c_int, CStr, CString};
use std::ptr;

use reality::{rc_free_string, rc_reload, rc_request, rc_start, rc_stop, rc_version};

const CONFIG: &str = r#"{
  "inbounds": [{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0 }],
  "outbounds": [{ "type": "direct", "tag": "direct" }, { "type": "block", "tag": "block" }],
  "route": { "final": "direct" }
}"#;

fn take(s: *mut c_char) -> String {
    assert!(!s.is_null());
    let v = unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned();
    unsafe { rc_free_string(s) };
    v
}

fn request(
    core: *mut reality::RcCore,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (c_int, String) {
    let m = CString::new(method).unwrap();
    let p = CString::new(path).unwrap();
    let b = body.map(|b| CString::new(b).unwrap());
    let mut status = 0;
    let r = unsafe {
        rc_request(
            core,
            m.as_ptr(),
            p.as_ptr(),
            b.as_ref().map_or(ptr::null(), |b| b.as_ptr()),
            &mut status,
        )
    };
    (status, take(r))
}

#[test]
fn start_request_reload_stop() {
    let v = unsafe { CStr::from_ptr(rc_version()) }.to_str().unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));

    let mut err: *mut c_char = ptr::null_mut();
    let bad = CString::new("{ битые").unwrap();
    assert!(unsafe { rc_start(bad.as_ptr(), ptr::null(), -1, &mut err) }.is_null());
    assert!(take(err).contains("JSON"));

    let cfg = CString::new(CONFIG).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let core = unsafe { rc_start(cfg.as_ptr(), ptr::null(), -1, &mut err) };
    assert!(!core.is_null(), "{}", take(err));

    let (c, v) = request(core, "GET", "/proxies", None);
    assert_eq!(c, 200);
    let v: serde_json::Value = serde_json::from_str(&v).unwrap();
    assert_eq!(v["proxies"]["direct"]["type"], "Direct");
    let (c, v) = request(core, "patch", "/configs", Some(r#"{"mode":"direct"}"#));
    assert_eq!((c, v.as_str()), (204, ""));
    let (_, v) = request(core, "GET", "/configs", None);
    assert!(v.contains(r#""mode":"Direct""#), "{v}");
    // Потоки — только обратными вызовами.
    assert_eq!(request(core, "GET", "/events", None).0, 400);

    let notes = unsafe { rc_reload(core, cfg.as_ptr(), ptr::null_mut()) };
    assert_eq!(take(notes), r#"{"notes":[]}"#);
    let bad = CString::new(CONFIG.replace(r#""final": "direct""#, r#""final": "nope""#)).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    assert!(unsafe { rc_reload(core, bad.as_ptr(), &mut err) }.is_null());
    let e = take(err);
    assert!(e.contains("nope"), "{e}");
    // Режим пережил перечитывание.
    assert!(request(core, "GET", "/configs", None)
        .1
        .contains(r#""mode":"Direct""#));

    unsafe { rc_stop(core) };
    unsafe { rc_stop(ptr::null_mut()) };
}
