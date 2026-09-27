//! Фаза 3: проверки настроек входа `tun` (без создания интерфейса —
//! для этого нужны права root; сам TUN проверяет scripts/tun_netns.sh).

use reality_core::app::config::Config;
use reality_core::app::App;

const OUT: &str = "[[outbounds]]\ntag='direct'\ntype='direct'\n";
const DNS: &str = "[dns]\n[[dns.servers]]\ntag='up'\naddress='1.1.1.1'\ndetour='direct'\n";

fn err(toml: &str) -> String {
    let cfg = match Config::parse(toml) {
        Ok(c) => c,
        Err(e) => return e.to_string(),
    };
    match App::build(&cfg) {
        Ok(_) => panic!("должна быть ошибка:\n{toml}"),
        Err(e) => e.to_string(),
    }
}

fn ok(toml: &str) {
    App::build(&Config::parse(toml).unwrap()).unwrap_or_else(|e| panic!("{e}\n{toml}"));
}

#[test]
fn tun_config_checks() {
    // Перехват DNS по умолчанию включён — нужен [dns].
    let e = err(&format!("[[inbounds]]\ntype='tun'\n{OUT}"));
    assert!(e.contains("[dns]"), "{e}");
    ok(&format!(
        "[[inbounds]]\ntype='tun'\ndns_hijack=false\n{OUT}"
    ));
    ok(&format!("[[inbounds]]\ntype='tun'\n{OUT}{DNS}"));

    // Системный DNS вместе с TUN — петля.
    let e = err(&format!(
        "[[inbounds]]\ntype='tun'\n{OUT}[dns]\n[[dns.servers]]\ntag='l'\naddress='local'\n"
    ));
    assert!(e.contains("петля"), "{e}");

    let e = err(&format!(
        "[[inbounds]]\ntype='tun'\nlisten='127.0.0.1:1'\n{OUT}{DNS}"
    ));
    assert!(e.contains("listen"), "{e}");
    let e = err(&format!(
        "[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1'\nauto_route=true\n{OUT}"
    ));
    assert!(e.contains("tun"), "{e}");
    let e = err(&format!("[[inbounds]]\ntype='socks'\n{OUT}"));
    assert!(e.contains("listen"), "{e}");
    let e = err(&format!(
        "[[inbounds]]\ntype='tun'\n[[inbounds]]\ntype='tun'\ntag='t2'\n{OUT}{DNS}"
    ));
    assert!(e.contains("только один"), "{e}");
    let e = err(&format!(
        "[[inbounds]]\ntype='tun'\ninet4_address='fd00::1/64'\n{OUT}{DNS}"
    ));
    assert!(e.contains("inet4_address"), "{e}");
    let e = err(&format!(
        "[[inbounds]]\ntype='tun'\ninet4_address='10.0.0.1/31'\n{OUT}{DNS}"
    ));
    assert!(e.contains("/30"), "{e}");
    let e = err(&format!("[[inbounds]]\ntype='tun'\nmtu=500\n{OUT}{DNS}"));
    assert!(e.contains("mtu"), "{e}");
    ok(&format!(
        "[[inbounds]]\ntype='tun'\ninterface_name='t0'\ninet4_address='10.7.0.1/24'\nmtu=9000\n\
         route_exclude=['192.168.0.0/16','fd00::/8']\nsniff=true\n{OUT}{DNS}"
    ));
}
