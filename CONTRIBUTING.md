[Русский](#как-внести-изменения) | [English](#contributing)

# Как внести изменения

Спасибо, что решили помочь. Коротко о том, как здесь принято. Участвуя,
вы соглашаетесь с [кодексом поведения](CODE_OF_CONDUCT.md).

## Лицензия правок

Проект выпускается под [GPL-3.0-or-later](LICENSE). Присылая pull request,
вы соглашаетесь, что ваши изменения выходят под этой же лицензией.
Подтвердите это строкой `Signed-off-by` в каждом коммите
([Developer Certificate of Origin](https://developercertificate.org/)):

```sh
git commit -s -m "…"
```

Код в `vendor/rustls-reality-patch` — патч rustls, он остаётся под
лицензиями rustls (Apache-2.0 / ISC / MIT). Это код, критичный для
безопасности: правки в нём держите минимальными, после каждой
пересоздавайте `vendor/rustls-reality-patch.diff`
(`scripts/rustls_patch.sh`) и обновляйте таблицу в
[`docs/RUSTLS_PATCH.md`](docs/RUSTLS_PATCH.md).

## Перед pull request

```sh
scripts/ci.sh --quick   # fmt, SPDX-метки, ссылки в документации, clippy без предупреждений, тесты
scripts/ci.sh           # плюс release-сборка, интероп с Xray-core и Go-стендом,
                        # режим библиотеки (C-программа через C ABI)
```

То же запускает CI на GitHub — на Linux и на настоящей Windows.

- У каждого нового исходника (`.rs`, `.go`, `.sh`, `.ps1`, `.py`, `.c`, `.h`)
  первая строка (у скриптов — сразу после `#!`):
  `// SPDX-License-Identifier: GPL-3.0-or-later` (или с `#`).
- Новое поведение — с тестом; всё, что касается протокола, — по
  возможности с проверкой против настоящего Xray-core
  (`scripts/interop_xray.sh`).
- Разбор данных из сети или от провайдера (HTTP, SOCKS5, sniffing, `.srs`,
  ссылки, подписки, Mux, XUDP) — с целью фаззинга в `fuzz/`
  (`cargo +nightly fuzz run -O <цель>`; CI гоняет их каждую ночь,
  `.github/workflows/fuzz.yml`).
- Меняется то, что видит пользователь, — обновите `README.md` и
  `README.en.md`, нужную страницу в `docs/` и допишите строку в
  `CHANGELOG.md` (раздел «Не выпущено»). Где что: README — что доступно
  сейчас и как начать; `docs/` — справочник; `CHANGELOG.md` — что
  изменилось и что планируется; `PLAN.md` — технические решения и история
  этапов. Статусы возможностей — одними словами: «готово»,
  «экспериментально», «не поддерживается», «не проверено на этой
  платформе».
- Меняется решение или открывается риск — `PLAN.md`; меняется устройство
  ядра (новый модуль, путь соединения, предел) — `docs/ARCHITECTURE.md` и
  `docs/ARCHITECTURE.en.md`. С него же удобно начинать знакомство с кодом.
- Комментарии в коде, `PLAN.md` и сообщения коммитов — на русском, как в
  остальном проекте; документация для пользователя — на двух языках
  (`*.md` и `*.en.md`); issue и pull request — на русском или английском.
- **Две языковые версии меняются вместе.** Правите возможности,
  ограничения или инструкции в `README.md` или в `docs/*.md` — в том же
  pull request поправьте `*.en.md` (и наоборот) и перед отправкой сверьте,
  что в обеих версиях одинаковые разделы, команды, статусы и ссылки.

## Уязвимости

Не открывайте публичный issue — см. [SECURITY.md](SECURITY.md).

---


# Contributing

Thanks for helping out. Here is how things are done here. By taking part
you agree to the [Code of Conduct](CODE_OF_CONDUCT.md#contributor-covenant-code-of-conduct).

## License of contributions

The project is released under [GPL-3.0-or-later](LICENSE). By sending a pull
request you agree that your changes are released under the same license.
Confirm it with a `Signed-off-by` line in every commit
([Developer Certificate of Origin](https://developercertificate.org/)):

```sh
git commit -s -m "…"
```

The code in `vendor/rustls-reality-patch` is a patched rustls and stays under
the rustls licenses (Apache-2.0 / ISC / MIT). It is security-critical code:
keep changes there minimal, regenerate `vendor/rustls-reality-patch.diff`
(`scripts/rustls_patch.sh`) after each one and update the table in
[`docs/RUSTLS_PATCH.en.md`](docs/RUSTLS_PATCH.en.md).

## Before a pull request

```sh
scripts/ci.sh --quick   # fmt, SPDX headers, links in the docs, clippy with no warnings, tests
scripts/ci.sh           # plus release build, interop with Xray-core and the Go test server,
                        # library mode (a C program over the C ABI)
```

CI on GitHub runs the same — on Linux and on real Windows.

- Every new source file (`.rs`, `.go`, `.sh`, `.ps1`, `.py`, `.c`, `.h`) starts with
  (for scripts — right after `#!`):
  `// SPDX-License-Identifier: GPL-3.0-or-later` (or with `#`).
- New behaviour comes with a test; anything protocol-related — where
  possible with a check against real Xray-core (`scripts/interop_xray.sh`).
- Parsing of data from the network or a provider (HTTP, SOCKS5, sniffing,
  `.srs`, links, subscriptions, Mux, XUDP) comes with a fuzz target in
  `fuzz/` (`cargo +nightly fuzz run -O <target>`; CI runs them nightly,
  `.github/workflows/fuzz.yml`).
- If what the user sees changes, update both `README.md` and `README.en.md`,
  the relevant page in `docs/`, and add a line to `CHANGELOG.md` (the
  "Unreleased" section). Where things go: the README — what is available
  now and how to start; `docs/` — the reference; `CHANGELOG.md` — what
  changed and what is planned; `PLAN.md` — technical decisions and the
  history of stages. Feature statuses use the same words everywhere:
  "ready", "experimental", "not supported", "not tested on this platform".
- If a decision changes or a risk appears — `PLAN.md`; if the core's
  structure changes (a new module, connection path, limit) —
  `docs/ARCHITECTURE.md` and `docs/ARCHITECTURE.en.md`. It is also the best
  place to start reading the code.
- Code comments, `PLAN.md` and commit messages are in Russian, like the rest
  of the project; user documentation is in two languages (`*.md` and
  `*.en.md`); issues and pull requests may be in English or Russian.
- **Both language versions change together.** If you change features,
  limitations or instructions in `README.md` or `docs/*.md`, update the
  `*.en.md` file in the same pull request (and vice versa), and before
  sending check that both versions have the same sections, commands,
  statuses and links.

## Vulnerabilities

Do not open a public issue — see [SECURITY.md](SECURITY.md#security).
