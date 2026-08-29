---
layout: ../../layouts/ArticleLayout.astro
title: "Command Approval Stored Inside a KeePassXC Database: Understanding _EXEC_CMD"
description: "A source-backed analysis of how KeePassXC persists cmd:// execution approval inside KDBX files, the trust boundary this creates, and its practical limitations."
published: "2026-08-30"
category: "Security Research"
tags:
  - vulnerability-research
  - application-security
  - keepassxc
  - trust-boundaries
draft: false
---

## Executive Summary

KeePassXC is a desktop password manager. It stores passwords and related information in an encrypted `.kdbx` database. Each saved account, called an entry, can include a URL. Activating that URL usually opens a website, but KeePassXC also supports URLs beginning with `cmd://`, which tell the application to launch a local program or command.

KeePassXC normally shows an **Execute command?** dialog before running a `cmd://` URL. The behavior documented here allows a database to arrive with that dialog already suppressed. If another person creates or shares such a database, and the recipient unlocks it and activates the prepared URL, the command runs with the same permissions as the recipient. Opening or unlocking the database is not enough by itself; the recipient must activate the URL.

The reason is that KeePassXC stores the result of its **Remember my choice** option inside the database. Entries can also hold extra named fields, called attributes; one of these, named `_EXEC_CMD`, records the choice. When its value is `1`, KeePassXC treats the command as previously approved. Because both the command and `_EXEC_CMD` travel inside the same `.kdbx` file, an approval recorded on one computer is also loaded when the database is opened elsewhere.

Testing on KeePassXC 2.7.12 running on Windows 10 confirmed the behavior. A prepared entry executed its command without the confirmation dialog in three tests, each begun with a freshly started KeePassXC. An otherwise identical `cmd://` URL without `_EXEC_CMD` showed the dialog in both control tests.

The project maintainers explained that database contents are trusted under KeePassXC's security model and that this flag is meant to prevent accidental execution, not attacks from malicious database content. Under that model, the behavior is intentional. It becomes security-relevant under a different model: one in which a person may trust someone to share passwords, but does not also give that person permission to approve commands on their computer. This article documents that boundary rather than presenting the behavior as a vendor-confirmed vulnerability.

## Background / Feature Behavior

The URL field in a KeePassXC entry is not limited to web addresses. When it begins with `cmd://`, KeePassXC interprets the remaining text as a program and its arguments. The confirmation behavior comes from two changes made in January 2017:

- Commit `7ea306a6` ("Prompt the user before executing a command in a cmd:// URL") introduced the dialog — "Do you really want to execute the following command?" with the default button set to **No** and the command preview masked for password placeholders.
- Commit `01e9d39b` ("Add 'Remember my choice' checkbox") added the persistence mechanism. Source-history review placed the first affected release at **2.1.1**.

When the user checks **Remember my choice**, the decision is written into the entry's attributes under the key `_EXEC_CMD` (constant `EntryAttributes::RememberCmdExecAttr`, defined in `src/core/EntryAttributes.cpp:37`) — the same storage that holds an entry's extra named fields, saved into the database file like all other entry data. The behavior was tested in KeePassXC **2.7.12** and was also present in `develop` at commit `79c3c379`, which matched `origin/develop` when fetched on 2026-08-27. The execution code uses the cross-platform `QProcess::startDetached` API, but runtime verification described here was performed on Windows only.

## Threat Model and Important Limitations

The behavior discussed in this article occurs only under the following preconditions, all of which must hold:

1. **A user receives a database created, modified, or saved and shared by another person** — for example, a shared vault or template — and has the credentials needed to unlock it.
2. **The user opens and unlocks the database, then activates the prepared entry URL** — by double-clicking the URL column, clicking the URL in the preview pane, or choosing Entries → Open URL. Source review shows that the execution path is reached only when a user activates an entry's URL; opening or unlocking the database alone does not invoke it.
3. The entry carries a `cmd://` URL and the attribute `_EXEC_CMD = 1`.

Explicitly outside scope — what this finding does **not** provide:

- **This does not let someone alter a database they cannot unlock.** KDBX integrity protection prevents a person without the database key from simply inserting `_EXEC_CMD` into an existing database. The demonstrated scenario requires a newly created database or one the other person is already able to decrypt, modify, and save.
- **No prior access to the recipient's machine or session is required** — but no capability beyond the recipient's own user account results. Demonstrated payloads were `cmd.exe /c calc.exe` and `cmd.exe /c whoami > %TEMP%\kpxc_pwned.txt`.
- **Not verified** (and therefore not claimed): automatic import through KeeShare, KeePassXC's folder-sharing feature, as a delivery vector; and runtime behavior on macOS/Linux, which share the code path but were not tested.
- The dialog suppression applies to `cmd://` execution only. It does not bypass database encryption, authentication, or any other KeePassXC security mechanism.

## Relevant Source Code

All locations were verified against the project's development branch (`develop`, commit `79c3c379`); the installed 2.7.12 release contains the same logic.

**1. The approval lookup and execution sink — `DatabaseWidget::openUrlForEntry()`, `src/gui/DatabaseWidget.cpp:997-1070`.**

```cpp
if (cmdString.startsWith("cmd://")) {
    bool launch = (entry->attributes()->value(EntryAttributes::RememberCmdExecAttr) == "1");

    if (!launch && cmdString.length() > 6) {
        ...
        int result = msgbox.exec();
        launch = (result == QMessageBox::Yes);
        if (remember) {
            entry->attributes()->set(EntryAttributes::RememberCmdExecAttr,
                                    result == QMessageBox::Yes ? "1" : "0");
        }
    }

    if (launch) {
        const QString cmd = cmdString.mid(6);
        QStringList cmdList = QProcess::splitCommand(cmd);
        if (!cmdList.isEmpty()) {
            const QString program = cmdList.takeFirst();
            QProcess::startDetached(program, cmdList);
        }
    }
}
```

- Line 1007 reads the remembered launch state from entry attributes without recording whether it originated from a dialog on the current machine or arrived in the file.
- Lines 1010–1040 contain the confirmation branch, which is reached only when `launch` is false. A loaded `_EXEC_CMD = 1` therefore skips it.
- Line 1038 writes the remembered result back into the entry attribute store, making it part of database state.
- Lines 1043–1047 split the URL remainder into a program and arguments and pass them to `QProcess::startDetached()`.

Repository-wide review found no configuration option that disables this dialog; `_EXEC_CMD` is the state used to suppress it.

**2. The load path — `KdbxXmlReader::parseEntryString()`, `src/format/KdbxXmlReader.cpp:834-875`.**

```cpp
if (keySet && valueSet) {
    ...
    entry->attributes()->set(key, value, protect);
}
```

- Line 870 copies each parsed `<String>` key and value into the entry attribute store with no special filtering for `_EXEC_CMD`.
- A KDBX containing `<Key>_EXEC_CMD</Key><Value>1</Value>` therefore loads the approval state through the same generic path as other entry attributes.
- `KdbxXmlWriter` (`src/format/KdbxXmlWriter.cpp:416-436`) writes custom attribute keys back on save, so the flag survives closing and reopening the database instead of being forgotten on close.

**3. The binding the GUI enforces — `Entry::setUrl()`, `src/core/Entry.cpp:781-790`.**

```cpp
void Entry::setUrl(const QString& url)
{
    bool remove = url != m_attributes->value(EntryAttributes::URLKey)
                  && (m_attributes->value(EntryAttributes::RememberCmdExecAttr) == "1"
                      || m_attributes->value(EntryAttributes::RememberCmdExecAttr) == "0");
    if (remove) {
        m_attributes->remove(EntryAttributes::RememberCmdExecAttr);
    }
    ...
}
```

A repository-wide search for `RememberCmdExecAttr` found this as the removal path. Editing an entry's URL through the GUI therefore clears the remembered decision and binds that decision to the current URL in the normal edit path. This observation describes the implementation; it does not establish whether the binding is intended as an anti-attack boundary. The XML reader writes attributes directly rather than calling `setUrl()`, so a URL and a pre-set `_EXEC_CMD` can be loaded together directly from the file.

**4. Trigger surface.** The URL-column activation dispatch in `DatabaseWidget::entryActivationSignalReceived()` (`src/gui/DatabaseWidget.cpp:1581-1593`) maps the default action (0, "Open entry URL") to `openUrlForEntry()`. Equivalent triggers are the preview-pane URL link (`src/gui/DatabaseWidget.cpp:207`) and the Open URL action (`DatabaseWidget::openUrl()`, `src/gui/DatabaseWidget.cpp:939-945`). The entry view activates on double-click (`src/gui/entry/EntryView.cpp:92`) and keyboard confirmation.

## Data Flow / Trust Flow

The full path from the shared file to execution:

```
KDBX file authored by another party
  ├─ URL = "cmd://<program> <arguments>"       ← executable content
  └─ _EXEC_CMD = "1"                          ← the pre-recorded approval
        │
        └─ KdbxXmlReader::parseEntryString()
             └─ entry->attributes()->set(key, value, protect)  (:870)
                    │
                    └─ DatabaseWidget::openUrlForEntry()
                         ├─ resolve entry URL into cmdString    (:1004)
                         ├─ launch = (value("_EXEC_CMD") == "1") (:1007)
                         ├─ skip dialog because launch is true (:1010)
                         ├─ split cmdString into program/args   (:1043-1046)
                         └─ QProcess::startDetached(program, args) (:1047)
                              └─ command executes in the user's session
```

The provenance distinction is lost at the `attributes()->set()` call during load: state originating in file content becomes indistinguishable from state produced by a local dialog choice. Downstream code treats both forms identically. Whether that is a security-boundary crossing depends on whether the database author and the executing user are considered the same trusted principal.

## Reproduction

Test environment: KeePassXC **2.7.12** (scoop build, Qt 5.15), Windows 10 19045 x64, default settings. Proof-of-concept artifacts: `poc_cmdexec.kdbx` (KDBX 4, password `CorrectHorseBatteryStaple`), generator `make_poc.py` (Python 3.14.7, pykeepass 4.2.0), and the decrypted inner XML `poc_inner.xml`. The crafted database round-trips through the independent pykeepass parser with the attribute intact, confirming it is ordinary in-file data.

Relevant entries:

| Entry | URL | `_EXEC_CMD` | Demonstrates |
|---|---|---|---|
| Corporate VPN Portal | `cmd://cmd.exe /c calc.exe` | `1` | Silent execution, no dialog (E12) |
| Audit proof | `cmd://cmd.exe /c whoami > %TEMP%\kpxc_pwned.txt` | `1` | Auditable artifact in `%TEMP%` (E8/E10/E11) |
| CONTROL no flag (working copy) | `cmd://cmd.exe /c calc.exe` | — | Negative control (E9) |

Steps: open the database, unlock it, and activate the prepared entry URL. The `cmd://` value may be visible wherever KeePassXC displays the URL; the demonstrated behavior is specifically that no separate execution-confirmation dialog appears when `_EXEC_CMD = 1` is present.

Controlled results (fresh process per round, artifact file deleted between rounds, GUI automation driving unlock and URL activation):

- **3/3 rounds**: the "Audit proof" URL executed silently; `%TEMP%\kpxc_pwned.txt` was created containing the `whoami` output, and an automated check of the windows belonging to the KeePassXC process found no "Execute command?" dialog (E8, E10, E11).
- **1/1**: the `cmd://cmd.exe /c calc.exe` variant launched Calculator silently (E12).
- **Negative control, 2/2**: the identical `cmd://` URL on an entry *without* `_EXEC_CMD` produced the confirmation dialog (captured text: "Do you really want to execute the following command? cmd.exe /c calc.exe", default button No); declining executed nothing, and the dialog reappeared on re-activation (E9).

The only difference between silent execution and the dialog is the attribute supplied in the file.

A note on methodology: the automation harness activated the URL via a click on the URL cell plus Enter, which exercises the same `EntryView` activation → `DatabaseWidget::openUrlForEntry` path as the default double-click; a separate manual session using real double-clicks produced the same result (E14). A Linux-equivalent payload (`cmd://sh -c 'id > /tmp/kpxc_pwned'`) follows the same code path but was not tested at runtime.

## Why the Behavior Occurs

Mechanically, three implementation details combine:

1. The XML reader treats every `<String>` as entry data and stores it through the generic attribute path, with no special filtering for `_EXEC_CMD`.
2. The lookup in `openUrlForEntry()` uses that attribute as the remembered launch state, with no provenance distinction between a decision recorded through a local dialog and a decision supplied in the file.
3. The writer persists the attribute, so the state survives save/load cycles and — because the file as a whole is what gets shared — travels to every recipient.

The result is that "Remember my choice" is functionally a property of the *database*, not of the user, machine, or session that made the choice. Producing such a file does not require direct XML manipulation: a database author can add a `cmd://` entry, activate it on their own machine, click **Yes** with **Remember my choice** checked (which writes `_EXEC_CMD = 1` at `DatabaseWidget.cpp:1038`), save, and distribute the file. Recipients then load the same remembered state. Editing the entry's URL through the GUI clears the state.

## Security-Relevant Scenario

**Minimal reproduction** (as above): crafted database, one URL activation, command executes with no prompt.

**Credential-handoff scenario.** During onboarding or a contractor handoff, a user receives a shared `.kdbx` plus its password. The vault contains an entry titled *Corporate VPN Portal* whose URL is `cmd://<payload>` with `_EXEC_CMD = 1`. If the recipient activates that URL, the payload runs in their session without the confirmation dialog. In an authorized social-engineering assessment, the same delivery could be staged as a fake IT credential handoff. A co-holder can also create the state through the ordinary interface by approving a command with **Remember my choice** and distributing the saved database. The scenario becomes security-relevant only when the recipient trusts the sender to provide vault data but does not intend to delegate authority over local execution.

**Detection and incident-response view.** The controlled tests verified the resulting process and filesystem side effects, not what endpoint security tooling would report (EDR telemetry). Based on the verified execution path, an analyst investigating such an event would look for process creation around a KeePassXC URL activation, including the configured program and command line — for example, `cmd.exe /c whoami ...` — followed by the resulting child-process or file activity. Exact parent-child representation and event fields depend on the endpoint sensor and were not measured here. The absent confirmation dialog is a GUI condition and may not itself appear in process telemetry.

**Artifact-triage scenario.** KDBX files can move through shared storage, incident-response collections, malware-analysis queues, and cyber-threat-intelligence (CTI) workflows. If a collected vault and usable unlock credentials are available, an analyst who opens the database should treat entry URLs as active content and avoid activating them during initial triage. This research does not establish how frequently usable vault-and-password pairs occur in logs stolen by credential-stealing malware ("infostealers"); it identifies the handling risk when such a pair is present.

**Benign / intended scenario.** A user maintains their own vault, uses a `cmd://` URL to launch a local SSH wrapper or VPN client with parameters, and checks **Remember my choice**. The stored decision suppresses later prompts after save and reopen. Here the database author and executor are the same trusted party, so persisting the choice in the database provides the intended convenience.

**Explicitly not possible.** A party who possesses only a copy of an existing `.kdbx`, without the credentials needed to decrypt and re-encrypt it, cannot use this finding to add `_EXEC_CMD`. The behavior provides no primitive against databases that party cannot author or legitimately modify.

## Why This May or May Not Be Considered a Vulnerability

It is worth separating three layers:

**A. What the code objectively does.** The confirmed facts: `_EXEC_CMD` is file-persisted entry data; the reader accepts it from a database; `openUrlForEntry()` uses it as the remembered launch decision; the dialog branch is skipped when its value is `1`; and `QProcess::startDetached` executes the parsed program and arguments. These points were reproduced under controlled conditions and verified in source.

**B. The security assumption that decides whether A is acceptable.** Under KeePassXC's stated model, database contents are trusted, and the flag protects against mishaps rather than hostile database content. In that model, loading the stored decision is expected behavior. An alternative model can separate authority to author or share database content from authority to approve command execution on a recipient's machine. Under that assumption, the same persisted state becomes security-relevant.

**C. The threat models under which it matters.** If a user receives databases from parties who are not trusted to authorize local execution, `_EXEC_CMD = 1` can suppress the prompt that user might otherwise rely on before a `cmd://` action. In that alternative threat model, the behavior can be described as a potential bypass of local approval. If opening a database means trusting its active contents, the same behavior is outside the project's security boundary, and the confirmation mechanism serves the purpose the maintainers describe: preventing accidental rather than malicious execution.

The difference in classification is therefore a difference in threat-model boundaries, not a disagreement about the observed code path. The implementation permits the database to carry both the command and the state indicating that execution has previously been approved. KeePassXC's model treats both as trusted database content. The alternative model examined here treats the command as transferable content but the approval decision as local to the executing user or device.

## Impact Boundaries

The risk described here is narrow and specific: **the transferability of a persisted approval decision across users and machines via shared file content**. It is not a general indictment of the application — database encryption, authentication, auto-type, and browser integration are unaffected.

What the demonstrated behavior provides, at maximum: execution of a command chosen by the database author, with arguments, at the privilege of the user who opened the database, given delivery of a database authored by another party plus one URL activation. On current evidence it does not provide any privilege beyond the user's own account or any ability to modify an existing database without its key, and no network-facing component is involved.

Self-authored databases, and databases exchanged only among parties who fully trust one another's active content, are outside the alternative trust boundary examined here. The behavior becomes relevant when `.kdbx` files cross a boundary where their authors are trusted to provide data but are not trusted to authorize local command execution.

## Related Observations

- **`file://` dispatch.** In the same `DatabaseWidget::openUrlForEntry()` function, URLs that are neither `cmd://` nor `kdbx://` are passed to `QDesktopServices::openUrl()` without a KeePassXC confirmation step (`src/gui/DatabaseWidget.cpp:1056-1063`). On Windows 10, activating `file:///C:/Windows/System32/calc.exe` launched Calculator with no `_EXEC_CMD` attribute and no dialog (E13). This behavior was reported separately to the project and is not part of the primary `_EXEC_CMD` mechanism.
- **Unverified extensions.** UNC/SMB delivery, credential-material disclosure, and handler chaining through `.hta`, `.lnk`, or similar artifacts were not tested and are not claimed as demonstrated.
- **Possible hardening.** A project that wants a single approval policy for active entry URLs could apply confirmation treatment to non-`http(s)` schemes before `QDesktopServices::openUrl()`. The trade-off would be additional prompts for users who intentionally open local files or other registered URL handlers.

## Potential Hardening Approaches

These are design options for projects that choose to treat recipient-side execution approval as a security boundary; none is claimed to be required under the project's stated threat model.

- **Stop honoring the attribute at load time.** Strip `_EXEC_CMD` in `KdbxXmlReader::parseEntryString()` or ignore file-loaded values in `openUrlForEntry()`, making remembered approval local runtime state. Trade-off: the legitimate "remember across restarts on my own machine" convenience is lost unless replaced.
- **Store remembered approval outside the KDBX**, in application settings keyed by database identity + entry UUID + a hash of the command string — mirroring the binding `Entry::setUrl()` already enforces when the URL is edited. Trade-off: approval no longer survives purely file-based migration between machines, and a settings store becomes part of the security state.
- **Ask once per entry per session** instead of remembering the answer permanently in the file. Trade-off: recurring friction for power users of `cmd://` URLs.
- **Differentiate file-provided state from locally generated state**, for example by authenticating remembered decisions with a local installation key and binding them to the database, entry, and command identity. Trade-off: additional state-management and migration complexity.
- **Offer an administrative configuration to disable `cmd://` execution entirely** in managed deployments, which currently have no policy lever for this path (no such setting exists today).

Each option gives the person running KeePassXC a way to distinguish approval recorded on their own machine from state supplied in the database. That distinction is relevant only for projects or deployments that choose to make per-user execution approval a security boundary.

## Disclosure Note

This behavior was privately reported to the project maintainers before publication. The maintainers clarified that database contents are considered trusted under the project's security model and that the flag is intended to prevent mishaps rather than attacks. This article documents the implementation behavior and examines its security implications under alternative trust assumptions. It should be read as a security-relevant trust-boundary analysis, not as a vendor-confirmed vulnerability.

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-08-27 | The behavior was reported privately to the KeePassXC maintainers. |
| 2026-08-27–28 | The maintainers clarified that database contents are trusted and that the flag prevents mishaps rather than attacks; the report was closed. |
| 2026-08-30 | Published as a technical research article. |

## Conclusion

KeePassXC's **Remember my choice** option for `cmd://` execution stores its decision in the database file, where the same state can be loaded on another user or machine. Source review and controlled testing confirmed that `_EXEC_CMD = 1` suppresses the dialog and that activating the entry URL then runs the command in the user's context. The project intentionally places database contents inside its trusted boundary and describes the flag as protection against mishaps, so this is not a vulnerability under its stated model. It becomes security-relevant under a narrower model in which shared or imported database content is trusted as data but local execution approval is not transferable. Users operating under that model can treat incoming databases as active content and, before activating their URLs, inspect or remove `_EXEC_CMD` through **Edit entry → Attributes**. Projects or deployments can also consider the optional hardening designs described above.
