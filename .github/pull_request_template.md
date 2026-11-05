## Что изменено / What changed

## Документация / Documentation

- [ ] При изменении документации сверены [VCTWS 1.0](../docs/STYLE_GUIDE.md) и [глоссарий](../docs/GLOSSARY.md) / For documentation changes, checked [VCTWS 1.0](../docs/STYLE_GUIDE.en.md) and the [glossary](../docs/GLOSSARY.en.md)
- [ ] RU/EN версии имеют одинаковый технический смысл / RU/EN versions have the same technical meaning
- [ ] Приведены источники фактов; проверки действительно выполнены / Fact sources are listed; reported checks were actually run

## Как проверено / How it was tested

- [ ] `scripts/ci.sh --quick` (fmt, SPDX, ссылки / doc links, синтаксис скриптов / script syntax, clippy, тесты / tests)
- [ ] интероп с Xray-core / interop with Xray-core (`scripts/interop_xray.sh`), если затронут протокол / if the protocol is affected
- [ ] README, `docs/`, CHANGELOG.md обновлены, если меняется поведение; русская и английская версии совпадают / README, `docs/`, CHANGELOG.md updated if behaviour changes; Russian and English versions match
- [ ] коммиты подписаны / commits signed off (`git commit -s`), см. / see CONTRIBUTING.md
