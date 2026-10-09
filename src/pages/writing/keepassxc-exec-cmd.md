---
layout: ../../layouts/ArticleLayout.astro
title: "Command Approval Stored Inside a KeePassXC Database: Understanding _EXEC_CMD"
description: "How a remembered cmd:// decision travels with a KeePassXC database, what the Windows tests showed, and why the maintainers classify the behavior as trusted content."
published: "2026-08-30"
category: "Security Research"
lang: en
tags:
  - vulnerability-research
  - application-security
  - keepassxc
  - trust-boundaries
draft: false
---

KeePassXC can launch a program from an entry URL beginning with `cmd://`. Normally, activating that URL displays an **Execute command?** confirmation. My August 2026 research found that the database can carry the remembered answer: an entry attribute named `_EXEC_CMD`, set to `1`, suppresses the dialog when the entry URL is activated.

The significant detail is where that answer lives. It travels inside the encrypted `.kdbx` database, alongside the command. A person opening a shared database can therefore inherit a decision recorded by its author. **Opening or unlocking the database does not execute the command; activating the prepared URL is required.**

The maintainers closed the report as working as intended. Their explanation was that database contents are trusted and that this flag prevents accidental execution rather than attacks. This article preserves that disposition while explaining the observed behavior and the different trust assumption that motivated the report. It does not present the finding as a vendor-confirmed vulnerability or claim a CVE or fix.

*Research performed on August 27, 2026; article revised October 10, 2026 from the preserved test record, source checkout, and maintainer correspondence. No new runtime tests were performed for this revision.*

## What the feature remembers

A KeePassXC entry contains ordinary fields such as title, username, password, and URL, plus additional named attributes. The command confirmation's **Remember my choice** option writes one of those attributes:

```text
URL        = cmd://cmd.exe /c calc.exe
_EXEC_CMD  = 1
```

This is the benign Calculator example used in the historical tests. The attribute is not a setting held only on the computer where the dialog appeared. It is database entry data.

The source history separates the two parts of the feature. The [confirmation dialog was introduced on January 27, 2017](https://github.com/keepassxreboot/keepassxc/commit/7ea306a61a7769042012ec267db64ca3b1a2c3ac), and [remembering the answer followed on January 28](https://github.com/keepassxreboot/keepassxc/commit/01e9d39b63b500944c59adbe163e6d5a8bfa57b0). In the retained repository history, 2.1.1 is the earliest release tag containing the persistence change. That establishes the feature's history, not a runtime test of every intervening release.

Runtime testing covered KeePassXC **2.7.12**, the Scoop build using Qt 5.15, on **Windows 10 19045 x64**. Source review used development commit [`79c3c379acf53a5d402059148aaf4d2f5f1c2475`](https://github.com/keepassxreboot/keepassxc/commit/79c3c379acf53a5d402059148aaf4d2f5f1c2475), which the research log records as matching upstream on August 27. These are historical version bounds; this article does not assert the state of later releases.

## The path from database content to a process

Four pieces of source explain the result.

**First, the name is a normal entry attribute.** [`EntryAttributes.cpp`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/core/EntryAttributes.cpp#L37) defines `RememberCmdExecAttr` as `_EXEC_CMD`. The database's decrypted XML represents it as a `<String>` key/value pair, like other additional entry fields:

```xml
<String>
  <Key>_EXEC_CMD</Key>
  <Value Protected="False">1</Value>
</String>
```

The `Protected` marker concerns protection of the field within the KDBX representation; setting it does not establish who approved execution. The complete database remains encrypted. This is not an attack on that encryption.

**Second, loading restores the field as data.** [`KdbxXmlReader::parseEntryString()`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/format/KdbxXmlReader.cpp#L834-L875) parses each key and value and ultimately calls:

```cpp
entry->attributes()->set(key, value, protect);
```

The reader performs normal structural validation, including a duplicate-key check, but does not treat `_EXEC_CMD` as recipient-local state. The [XML writer iterates the entry's attribute keys](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/format/KdbxXmlWriter.cpp#L416-L450) when saving, so the value survives save and reload.

**Third, URL activation consumes the value as approval.** The relevant branch of [`DatabaseWidget::openUrlForEntry()`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/gui/DatabaseWidget.cpp#L997-L1053) is equivalent to the following abridged code:

```cpp
bool launch =
    (entry->attributes()->value(EntryAttributes::RememberCmdExecAttr) == "1");

if (!launch && cmdString.length() > 6) {
    // Show the confirmation dialog; default answer is No.
    // A remembered answer is written back to the entry attributes.
}

if (launch) {
    const QString cmd = cmdString.mid(6);
    QStringList cmdList = QProcess::splitCommand(cmd);
    if (!cmdList.isEmpty()) {
        const QString program = cmdList.takeFirst();
        QProcess::startDetached(program, cmdList);
    }
}
```

The loaded value `1` makes `launch` true before the dialog branch. The remaining URL text is split into a program and arguments, then passed to `QProcess::startDetached`. In the Calculator example, `cmd.exe` is explicitly part of the URL; KeePassXC is not implicitly treating every URL as shell script text.

**Fourth, editing and loading use different paths.** [`Entry::setUrl()`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/core/Entry.cpp#L781-L790) removes the remembered attribute when an entry's URL changes. Normal URL editing therefore clears the old decision. Loading the database restores the URL and its attributes through the generic reader, so an already matching URL and `_EXEC_CMD` can arrive together.

```text
Shared database
  URL = cmd://…       _EXEC_CMD = 1
           │                │
           └───────┬────────┘
                   ▼
         Entry attributes loaded
                   │
        User activates the URL
                   │
                   ▼
        Remembered answer is "yes"
                   │
        Confirmation branch skipped
                   │
                   ▼
     Program starts as the current user
```

The implementation does not distinguish a value created by a dialog on this computer from an identical value supplied in the database. Calling that a security-boundary violation requires a further assumption: that database authors should not be able to supply execution approval for recipients. That assumption is exactly where the report and the maintainers' model differ.

## What the recorded tests established

The historical test database contained both command entries and a working-copy control without the attribute. An independent parser round-trip and inspection of the decrypted XML confirmed that `_EXEC_CMD` was ordinary persisted data.

| Case | Entry state | Recorded result |
|---|---|---|
| Command with remembered approval | A harmless identity-output command, `_EXEC_CMD = 1` | Three fresh-process runs created the expected temporary output file; no **Execute command?** window was found. |
| Calculator with remembered approval | `cmd://cmd.exe /c calc.exe`, `_EXEC_CMD = 1` | Calculator started without the confirmation dialog. |
| Calculator control | The same Calculator URL, attribute absent | The dialog appeared on two activations. Declining produced no Calculator launch. |

For the repeated command case, the output file was removed before each round and recreated after URL activation. Checking a real side effect, rather than only a return value from a launch API, distinguished execution from an attempted launch. The Calculator control isolated the important variable: the command text was the same, but the attribute was absent.

The controlled harness selected the URL cell and pressed Enter. It did not reliably synthesize double-clicks under its changing DPI/session conditions. Source review shows [the URL-column activation route](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/gui/DatabaseWidget.cpp#L1581-L1593) reaching `openUrlForEntry()`. A prior manual session corroborated the behavior but was not counted as a controlled repeat.

The recorded absence of the dialog combines process-window inspection with the branch behavior visible in source. It does not establish that every possible desktop configuration, platform, or later version behaves identically.

## Preconditions and limits

The demonstrated scenario requires all of the following:

1. Another party can author a database or decrypt, modify, and save one they already possess credentials for.
2. The recipient obtains that database and the credentials needed to unlock it.
3. An entry contains both a `cmd://` URL and `_EXEC_CMD = 1`.
4. The recipient activates the entry URL.

No previous access to the recipient's computer was needed for the file-delivery scenario. Conversely, possession of an encrypted database alone does not grant the ability to insert this field. The finding does not bypass KDBX authentication or integrity protection, recover a master password, or elevate privileges. The resulting process runs with the recipient's existing account permissions.

A concrete trust mismatch is a credential handoff. A colleague or contractor shares a vault; the recipient accepts its passwords as useful data and activates an entry URL. The recipient may not realize that the same vault can also carry a remembered command decision. The URL itself may remain visible as `cmd://`; this research did not demonstrate a URL-spoofing mechanism or an automatic trigger at database open.

The source also explains why a specially edited XML file is unnecessary in principle. A database author can use the normal **Remember my choice** workflow and save the resulting database. That is an inference from the save and load paths, separate from the controlled tests, which used a prepared test database.

The record does **not** establish runtime behavior on Linux or macOS, automatic delivery through KeeShare, or any post-execution impact beyond the benign demonstrations. It also contains an independent `file://` observation. That route uses a different branch and execution mechanism; it is not a second stage of this finding.

## The maintainer response and the disputed assumption

The saved report discussion records the following sequence:

| Date | Event |
|---|---|
| August 27, 2026 | The command-approval report was submitted privately. |
| August 27, 2026 | A maintainer closed it, explaining that database contents are trusted and the behavior is intended. |
| August 28, 2026 | A follow-up clarified that the flag prevents mishaps rather than attacks. |
| August 30, 2026 | Original version of this article. |
| October 10, 2026 | Evidence-focused revision and Vietnamese translation. |

The maintainer's concise explanation was:

> “The flag exists to prevent mishaps, not to prevent attacks. Database contents are considered trusted.”

That quotation comes from the retained private report discussion. It is reproduced to explain the disposition; the private HTML export, collaboration metadata, and session material are not published here. The retained record does not supply a public vendor advisory to cite as acceptance of the finding.

My original report treated the confirmation as a local execution-approval boundary: approving a command on one machine should not approve it for another recipient. The maintainers instead place the contents of the unlocked database inside the trusted boundary. Under their model, remembering a decision in the database is consistent with trusting its author, and the dialog can still prevent an accidental first activation.

The observed mechanism does not resolve that policy disagreement by itself. A prompt can be a usability safeguard without promising protection against malicious file content. Likewise, users exchanging vaults can reasonably benefit from knowing how broad the application's trust assumption is. The useful community result is to make both statements explicit.

## Practical lessons

Treat entry URLs in an incoming vault as active content. Inspect the resolved action before activating it. Removing `_EXEC_CMD` restores the `cmd://` confirmation behavior in the reviewed code, but it is not a general safe-opening policy: the separate `file://` path does not consult that attribute.

For applications that *do* want recipient-specific approval, the design lesson is to keep the decision outside content controlled by the author. Local approval could be keyed to a database identity, entry identity, and command value, with changes requiring approval again. Session-only approval is another option. Both introduce migration or usability trade-offs, and neither is presented here as an adopted KeePassXC fix.

The lasting distinction is between trusting a database to supply secrets and trusting it to supply executable actions plus their remembered approval. KeePassXC's maintainer response places both inside one boundary. The tests show what that choice means when a database moves between people or machines.
