# VCTWS 1.0 Technical Writing Standard

[Русский](STYLE_GUIDE.md) | [English](STYLE_GUIDE.en.md) · [Glossary](GLOSSARY.en.md)

This standard defines the project's editorial rules for Russian and English documentation. It adapts selected practices from [ASD-STE100](https://www.asd-ste100.org/about.html), the [Google Developer Documentation Style Guide](https://developers.google.com/style), and the [Microsoft Writing Style Guide](https://learn.microsoft.com/en-us/style-guide). **It is an internal project standard, not a claim of formal compliance with those guides.**

Priority order: technical accuracy → safety and limitations → clarity → contract completeness → navigation → consistency → brevity.

## Rule strength

- **MUST** — mandatory editorial rule. Explain an exception when it affects technical accuracy, safety, limitations, or a public contract.
- **SHOULD** — follow the rule unless it reduces accuracy or clarity.
- **MAY** — permitted option.

These words describe VCTWS editorial requirements. In protocol and API specifications, normative words have the meaning defined by that specification; do not apply VCTWS meanings to them. If a document uses RFC 2119/8174 terms, state that explicitly.

## Document classes and purpose

| Class | Examples | Readers should find |
|---|---|---|
| Overview | Root `README.md` | What the project is, who it serves, how to start, its limits, and where to go next |
| Procedure | `CLI.md`, `TUN.md`, `WINDOWS.md`, `RELEASING.md` | Preconditions, actions, observable results, and troubleshooting |
| Technical reference | `CONFIG.md`, `DNS.md`, `LINK.md`, `API.md`, `LIBRARY.md` | Exact values, contracts, errors, and limitations |
| Engineering description | `ARCHITECTURE.md`, `REPOSITORY.md`, `RUSTLS_PATCH.md`, `APPLICATION_ROUTING.md` | Components, data flows, invariants, design reasons, and boundaries |
| Security and testing | `SECURITY-MODEL.md`, `TESTING.md`, review documents | Conditions, evidence, assumptions, and verification limits |
| Historical | `PLAN.md`, `CHANGELOG.md`, reports | The date, subject, and state at that time |
| Project policy | `CONTRIBUTING.md`, `SECURITY.md`, GitHub templates | Exact rules and reproducible actions |

For each new or updated document, point readers to one primary source for the topic. Do not duplicate a detailed reference in the README or a neighboring guide; keep a short overview and a link. Before removing text, confirm that unique limits and examples are preserved.

### README exception

The README may use a more engaging presentation, comparison tables, and visual elements. It **MUST** keep technical claims supported, show important limits, and distinguish the core/SDK from a ready-made application. Do not promise capabilities or security without evidence.

## Clear technical language

- **SHOULD:** Each sentence conveys one main idea or instruction.
- **SHOULD:** Name the actor and use active voice when possible.
- **SHOULD:** Address the reader directly in procedures: “Run,” “Check,” “Set.”
- **SHOULD:** When practical, state a condition before the action that depends on it.
- **MUST:** Preserve negatives, exceptions, and limitations; do not shorten them away.
- **MUST:** Use one term for one concept. Refer to the [glossary](GLOSSARY.en.md).
- **SHOULD:** Expand an uncommon abbreviation on first use when its meaning is not obvious to the intended reader.
- **MUST:** Distinguish an observation, an inference, and a recommendation. Label an inference.
- **MUST:** Use present tense for current behavior and past tense for completed checks or historical state.
- **SHOULD:** Keep each paragraph on one topic and place a limitation next to the claim it qualifies.
- **MUST:** In security descriptions and public contracts, accuracy takes priority over brevity.

Do not use words such as “fully,” “securely,” “seamlessly,” “fast,” or “guarantees” without conditions and verifiable evidence. Do not call a feature supported only because its name appears in a configuration option or test.

English guidance: aim for no more than 20 words per instruction and 25 per descriptive sentence. These are editorial targets, not CI requirements. Keep Russian text similarly concise without mechanical counting. A paragraph usually has no more than six sentences.

### Editing examples

These examples use project contracts and terminology. The “before” text illustrates a common ambiguity; it is not a quotation from a specific document version.

**Procedure — verify the result**

- Before: “Start the client; it works.”
- After: “Create `server.txt` with a valid VLESS link and restrict access to the file. Run `reality-client --server-file server.txt --listen 127.0.0.1:1080`. Run `curl --socks5-hostname 127.0.0.1:1080 https://example.com`; a successful response confirms the request was handled by the local SOCKS5 inbound, but does not by itself confirm the selected route or TUN operation.”
- Why: The check result is separated from the conclusion about network connectivity.

**API parameter**

- Before: “`base_dir` is the configuration folder.”
- After: “In `rc_validate(config, base_dir)`, `base_dir` may be `NULL`. See the [library contract](LIBRARY.en.md).”
- Why: The example names the function and states whether `NULL` is allowed; the claim follows the `rc_validate` contract.

**Security**

- Before: “REALITY securely hides the server.”
- After: “If REALITY verification fails, the client does not send the VLESS UUID to that server. An observer can still see the server IP address, connection time, and traffic volume. See the [security model](SECURITY-MODEL.en.md).”
- Why: An absolute promise is replaced with a condition and an explicit limit.

## Procedures and warnings

Use the sections that fit the procedure:

1. Purpose and expected result.
2. Preconditions: platform, version, dependencies, permissions, network access, and starting state.
3. A warning before an action that can disrupt networking, change routes, or expose a secret.
4. Numbered steps, each with one main goal.
5. A result check, including what it does and does not confirm.
6. Troubleshooting: symptom → cause to check → action.
7. Links to related references.

Do not add empty sections to a short procedure. **MUST:** separate steps for different platforms; explain placeholders such as `<SERVER>` and `<PATH>`; state `sudo`/administrator, reboot, and network requirements; describe rollback if a failure can leave the user without network access. Verify error text and expected output against code or a test.

### Warnings

- **WARNING** — risk of network loss, a leak, secret exposure, or an irreversible system change.
- **IMPORTANT** — a condition that materially changes the result.
- **NOTE** — useful information that does not block the procedure.

Put a warning immediately before the relevant step. State the specific risk, condition, and mitigation. Do not use warnings as decoration.

### Short writing examples

These examples show a format. Verify every real command, schema, and behavior against its primary source.

**CLI — a command verified in `docs/CLI.en.md`:**

```sh
reality-client --server-file server.txt --listen 127.0.0.1:1080
```

Before the command, say what `server.txt` must contain, where to get the file, and how to restrict access to it. After the command, state the expected result and a separate connection check.

**JSONC — this is a comment example, not a project configuration:**

```jsonc
{
  "field": "value" // Explain the field; check the schema before publishing.
}
```

Do not call this strict JSON or copy the placeholder field into a working configuration.

**API — document every field from the actual contract:**

| Field | Type | Required | Default | Error |
|---|---|---|---|---|
| `<exact field path>` | `<type from implementation>` | `<yes/no>` | `<confirmed value only>` | `<actual response>` |

The placeholders in this table are not API fields. Replace them with values from the implementation, tests, and public contract.

**TUN — state the risk and platform first:**

> **WARNING:** The next step changes `<verified network state>` on `<named platform>`. Before it, save `<required starting state>`; rollback: `<verified procedure>`.

Replace every placeholder with verified information. Do not use this warning as a ready-to-run instruction unless the risk and rollback are confirmed.

## Technical references and examples

For each parameter, flag, or API field, document the applicable items:

| Field | What to record |
|---|---|
| Name and path | Exact name, case, and field path |
| Type | String, number, enum, array, object, or nullable |
| Purpose | Which behavior the parameter changes |
| Required status and default | Confirmed values and scope only |
| Allowed values | Format, range, and verifiable limits |
| Compatibility | Supported subset of a format or a project-specific extension |
| Error | Actual behavior for invalid input |
| Example and source | Minimal safe example and a link to code, test, or header |

Examples must match the parser and real command. Label every code block with its language: `json`, `jsonc`, `sh`, `powershell`, `rust`, or `c`. If JSON contains comments, call it JSONC. Do not include real UUIDs, keys, tokens, or user addresses. Do not present support for part of Xray or sing-box as full compatibility.

### API, SDK, and C ABI

**MUST:** Verify descriptions against the public header, FFI implementation, consumer tests, and release workflow. State signatures, whether `NULL` is allowed, return values, memory ownership, resource release, object lifetime, call order, threads, callbacks, re-entry, and panic boundaries when they affect integration. Describe static and dynamic linking separately and document each platform. Building or cross-linking a library does not prove that it works on a physical device.

## Architecture

For a major component, describe the relevant items in this order: purpose → responsibility → inputs → outputs → dependencies → processing → invariants → failure → limits → sources and tests. Separate current state, mechanism, design rationale, and future plans. Name existing modules, functions, types, and paths. Add a diagram only when it is accurate and helps explain the flow.

## Security and evidence

Write verifiable claims in this form:

> Under **condition X**, the component provides **property Y**, except for **cases Z**. The property was checked by **method V** / **was not checked by method V**.

Do not turn an interoperability test into a cryptographic guarantee. Do not claim anonymity, zero DNS leaks, or security for every configuration without a threat model, conditions, and evidence. Distinguish an internal review, an interoperability test, and an independent audit. For each check, state its scope and, when the result can change, its date or a link to the current workflow.

## Feature and platform status

Keep the existing status vocabulary in `docs/FEATURES.en.md`: **ready**, **experimental**, **not supported**, **partially verified**, and **not tested on this platform**. Their Russian equivalents are «готово», «экспериментально», «не поддерживается», «проверено частично», and «не проверено на этой платформе». Do not introduce synonyms without a reason. State implementation, platform, and evidence type separately for each feature. Do not conflate:

- inbounds and outbounds, protocols and transports;
- the library/core, CLI client, and a ready-made graphical application;
- compilation, cross-linking, runner tests, interoperability, and on-device execution;
- an experimental feature and a published stable capability;
- the state of `main` and the contents of a published release.

Give changing figures for test counts, benchmarks, platforms, and versions a source, date, and method. Do not generalize one scenario to all configurations.

## Russian and English versions

- **MUST:** Submit technically meaningful RU and EN changes in the same pull request.
- **MUST:** Keep numbers, statuses, identifiers, commands, limits, warnings, and test conclusions consistent in both languages.
- **SHOULD:** Keep a comparable structure, but translate meaning rather than word order.
- **MUST:** Do not translate code identifiers or exact values.
- **MUST:** Each language pair links to the other version.
- **MUST:** Check meaning manually; matching filenames and heading counts do not prove translation accuracy.
- **MAY:** Keep existing bilingual root policies and history instead of creating duplicate `.en.md` files.

## Markdown, links, and navigation

- **MUST:** New documents have one logical H1. Bilingual root documents may have a justified exception.
- **SHOULD:** Use a consistent H2/H3 hierarchy; avoid H4 unless needed.
- **MUST:** Use numbered lists for actions and bullets for independent items.
- **MUST:** Format function names, types, paths, commands, and parameters as code.
- **SHOULD:** Use tables for compact comparisons of fields or options, and prose to explain algorithms.
- **MUST:** Check relative links and anchors after changing headings.
- **MUST:** Do not leave links to missing files, sections, buttons, or unverified artifacts.
- **MUST:** Preserve unique information until its new canonical location is identified.
- **SHOULD:** Add a table of contents and clear headings to long documents.
- **MUST:** Do not change upstream or generated files for editorial consistency.

## Maintaining this standard

Before changing a document, identify its class and primary source of facts. In the pull request, link the sources and list the relevant checks. For documentation changes, run `git diff --check` and `python scripts/check_doc_links.py`; check language pairs, commands, and examples. When changing a C ABI header, also run `python scripts/check_ffi_abi.py`. Required CI must pass for the current PR head before merge.

Scale the review to the change: check the edited content and claims related to it. A typo fix alone does not require a full technical review of the document. Legacy documentation can be brought into conformance incrementally. However, do not treat a known material error as verified or leave it unrecorded just because fixing it is outside the current change. Record it for separate work.

Record implementation defects separately. This standard does not authorize changes to code, public API/ABI, configuration formats, or protocol behavior for documentation purposes. Third-party files in `vendor/` are excluded unless the file is project-authored explanatory documentation.
