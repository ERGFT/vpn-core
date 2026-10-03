# API, веб-панели и перечитывание настроек

**Русский** | [English](API.en.md)

Локальное API, совместимое с Clash API: управление из веб-панелей и своих программ. Включается в [файле настроек](CONFIG.md).

API совместимо с **Clash API** (как у sing-box и mihomo): готовые
веб-панели — [metacubexd](https://github.com/MetaCubeX/metacubexd),
[yacd](https://github.com/haishanh/yacd), zashboard — и клиенты, умеющие
Clash API, работают с ядром без переделок. metacubexd и yacd проверены на
настоящем ядре в браузере: группы, выбор сервера, проверка задержки,
соединения, правила, журнал, режим.

```json
"experimental": {
  "clash_api": {
    "external_controller": "127.0.0.1:9090",
    "secret_file": "api-token.txt",
    "external_ui": "ui",
    "default_mode": "rule"
  }
},
"route": { "presets": ["block-ads", "private-direct", "ru-direct"] }
```

- `secret` — токен прямо в файле, `secret_file` (расширение) — в отдельном
  файле; не короче 16 символов.
- `external_ui` — папка с файлами панели (например, распакованный
  `compressed-dist.tgz` metacubexd): она открывается по адресу
  `http://127.0.0.1:9090/ui/`. Скачивать панель сам клиент не умеет
  (`external_ui_download_url` — ошибка): положите файлы в папку.
- `access_control_allow_origin` — сайты панелей, которым можно обращаться к
  API из браузера (`["https://metacubex.github.io"]` или `["*"]`); своя
  панель из `external_ui` разрешена всегда.
  `access_control_allow_private_network: true` — нужно Chrome для панели
  из интернета.
- `allow_query_token` (расширение) — принимать токен в адресе WebSocket
  (`?token=`), как его передают панели. По умолчанию — только когда API
  слушает 127.0.0.1: адрес с токеном оседает в журналах прокси и истории
  браузера. API в сети с панелью из браузера — `"allow_query_token": true`.
- `default_mode` — режим при запуске: `rule` (по правилам), `global` (всё
  через выбранный в группе `GLOBAL` выход) или `direct` (всё напрямую).
  Перехват DNS работает в любом режиме. Группа `GLOBAL` (все выходы,
  по умолчанию — `route.final`) создаётся сама, как у Clash.

Запросы Clash — те же адреса и ответы, что у sing-box:

```sh
T="Authorization: Bearer $(cat api-token.txt)"
curl -H "$T" http://127.0.0.1:9090/proxies                         # выходы и группы
curl -H "$T" -X PUT -d '{"name":"my-panel/Finland"}' http://127.0.0.1:9090/proxies/proxy
curl -H "$T" "http://127.0.0.1:9090/proxies/proxy/delay?url=https://www.gstatic.com/generate_204&timeout=5000"
curl -H "$T" -X PATCH -d '{"mode":"global"}' http://127.0.0.1:9090/configs
curl -H "$T" http://127.0.0.1:9090/connections
curl -H "$T" -X DELETE http://127.0.0.1:9090/connections/42
curl -H "$T" "http://127.0.0.1:9090/dns/query?name=example.com&type=A"
```

| Запрос | Что делает |
|---|---|
| `GET /configs`, `PATCH /configs` | порты входов и режим; сменить режим (`mode`; порты и прочее — только в файле настроек) |
| `PUT /configs` | перечитать файл настроек; с `payload` — применить новые настройки (без записи в файл, как у Clash) |
| `GET /proxies[/{имя}]`, `PUT /proxies/{группа}` | выходы, группы (`now`, `all`), серверы подписок; выбрать участника selector |
| `GET /proxies/{имя}/delay`, `GET /group/{имя}/delay` | проверить задержку выхода или всех участников группы |
| `GET /connections`, `DELETE /connections[/{id}]` | открытые соединения (выход, цепочка, правило, трафик); закрыть |
| `GET /rules` | правила по порядку и `route.final` |
| `GET /providers/proxies[/{имя}]`, `PUT …/{имя}`, `GET …/{имя}/healthcheck` | подписки: серверы, обновить, проверить |
| `GET /dns/query?name=&type=` | спросить DNS клиента |

Свои запросы (в Clash API их нет): `GET /stats` (трафик по выходам),
`GET /groups`, `PUT /groups/{tag}`, `POST /groups/{tag}/check`,
`POST /subscriptions/{tag}/update`, `POST /reload` (с замечаниями в ответе).

**Смена настроек через API** — клиенту не нужно самому писать файл и
перезапускать ядро:

```sh
curl -H "$T" http://127.0.0.1:9090/config               # {"path", "format", "text"}
curl -H "$T" -X PUT --data-binary @new.json "http://127.0.0.1:9090/config?check=1"   # только проверить
curl -H "$T" -X PUT --data-binary @new.json http://127.0.0.1:9090/config             # применить и сохранить
```

- Тело `PUT /config` — настройки целиком, sing-box или Xray (формат
  определяется сам). Они проверяются, применяются без разрыва соединений
  (как перечитывание) и записываются в файл настроек атомарно, прежний —
  в `<файл>.bak`; `?save=0` — применить, не записывая. Ошибка — 400, и
  ничего не меняется. Ответ: `{"applied", "saved", "notes"}` (`notes` —
  что вступит в силу после перезапуска, например адрес API или вход TUN).
- Файлы в таких настройках (`link_file`, `rule_set`, базы, сертификаты…) —
  только из папки настроек, относительным путём без `..`, и не через
  символическую ссылку наружу (проверяется настоящее расположение файла):
  иначе тот, у кого есть токен, мог бы заставить клиент (службу Windows —
  от имени SYSTEM) читать любые файлы компьютера.
- `GET /config` отдаёт файл целиком — вместе с UUID и паролями, как и
  всё API: токен даёт полное управление клиентом.
- Работает, только если клиент запущен с файлом настроек (`--config`).

Потоки — клиент узнаёт о переменах сразу, без опроса. Ответ не кончается,
пока клиент не закроет соединение: по JSON-объекту на строку или, с
`Upgrade: websocket`, по кадру WebSocket на объект.

```sh
curl -N -H "$T" http://127.0.0.1:9090/events            # события
curl -N -H "$T" http://127.0.0.1:9090/traffic           # скорость раз в секунду
curl -N -H "$T" "http://127.0.0.1:9090/logs?level=warning"
```

| Поток | Что присылает |
|---|---|
| `/events` | свои события: `connection_open` (поля — как в `/connections`), `connection_close` (итог трафика, длительность), `group_switch` (группа сменила участника: сама или вручную), `group_check` (задержки после проверки), `subscription_update` (число серверов или ошибка), `reload`, `mode_change`; `lagged` — клиент не успевал, часть событий пропущена (перечитайте `/connections`) |
| `/traffic` | раз в секунду: `up`, `down` — байт за секунду, `upTotal`, `downTotal` — всего |
| `/memory` | раз в секунду: `inuse` — память процесса, байт |
| `/logs?level=info` | журнал: `{"type": "warning", "payload": "…"}`; `level` — `debug`, `info`, `warning`, `error`; подробнее, чем пишется в журнал (`RUST_LOG`), не бывает |
| `/connections` (только WebSocket) | раз в `interval` мс (по умолчанию 1000) — то же, что `GET /connections` |

Пока поток никто не слушает, события не собираются вовсе. Потоков
одновременно — до 16.

- Токен обязателен всегда (`Authorization: Bearer`; WebSocket из браузера —
  `?token=`, см. `allow_query_token`). 5 неверных токенов с адреса (IPv6 —
  с подсети /64) — адрес блокируется на минуту и дольше; 127.0.0.1 не
  блокируется. Без токена отдаются только файлы панели и приветствие `GET /`,
  как у Clash. `Host` должен быть адресом API (защита от DNS rebinding);
  запросы из браузера — только от своей панели и сайтов из
  `access_control_allow_origin`; слушать не на 127.0.0.1 — только с
  `allow_ip`. Адреса сайтов в `/connections` — история посещений, поэтому
  они есть только в API, не в журнале.
- Перечитывание (`PUT /configs`, `POST /reload`, на Linux ещё `kill -HUP`):
  ошибка в файле — работают прежние настройки. Новые выходы, правила, DNS,
  группы и подписки — сразу для новых соединений, открытые живут со
  старыми; выбор в группах и режим сохраняются. Входы перезапускаются,
  только если их настройки изменились; вход TUN и API — после перезапуска
  программы. Таблица fake-IP сохраняется.
- Пресеты (после своих правил, так что своими можно переопределить):
  `block-ads` (geosite `category-ads-all` → первый `block`),
  `private-direct` (частные адреса, `.local`, `.lan` → первый `direct`),
  `ru-direct`, `cn-direct`, `ir-direct` (домены страны, geosite, geoip →
  `direct`).
