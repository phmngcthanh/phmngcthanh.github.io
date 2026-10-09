---
layout: ../../layouts/ArticleLayout.astro
lang: en
title: "Notepad++ Function List and the Missing Upper Bound on langID"
description: "How an XML configuration value became an out-of-bounds owning-pointer assignment, what the boundary tests established, and the published advisory's threat-model limits."
published: "2026-10-10"
category: "Security Research"
tags:
  - notepadpp
  - memory-safety
  - configuration
draft: false
---

Notepad++ uses Function List configuration to decide which parser should extract the functions in a document. In version 8.9.8, an integer in that configuration could also select a position outside the parser table. Opening the Function List panel then reached an out-of-bounds owning-pointer assignment and, for several tested values, terminated the editor.

The project published this finding as [GHSA-9rr8-6vjg-gj52](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-9rr8-6vjg-gj52) on September 24, 2026, crediting `phmngcthanh`. Its public assessment is Moderate, CVSS 3.1 **5.5**, with code execution expressly unclaimed. This article explains the configuration path and the experiments behind the report.

## The configuration path

Function List associates language identifiers with parser definitions. The relevant input is `functionList/overrideMap.xml`, whose association records contain an `id` and, for built-in language associations, a numeric `langID`.

The configuration must be installed where the editor will actually load it. Merely opening an arbitrary XML document in a tab does not exercise this parser. The recorded tests used disposable, plugin-free portable copies on Windows 10 x64, with the configuration alongside Notepad++ 8.9.8.0. A normal installation can instead load the user's Function List directory, with the installed directory as a fallback.

This placement requirement matters. An attacker-supplied profile or configuration package is one possible delivery model. A process that already has permission to rewrite the user's configuration is another, with different security implications. After placement, the recorded trigger was opening **View → Function List**, which initializes the parser manager.

## A lower bound is only half the check

The supplied source snapshot contains this logic in `FunctionParsersManager::getOverrideMapFromXmlTree()`:

```cpp
const int langID = NppXml::intAttribute(childNode, "langID", -1);
if (langID >= 0)
{
    _parsers[langID] = std::make_unique<ParserInfo>(string2wstring(id));
}
```

The check rejects negative values. It does not establish that a non-negative value fits the destination array. The relevant version is available in the [v8.9.8 parser source](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/v8.9.8/PowerEditor/src/WinControls/FunctionList/functionParser.cpp).

The member declaration is:

```cpp
std::unique_ptr<ParserInfo> _parsers[L_EXTERNAL + nbMaxUserDefined];
```

In the examined source, `L_EXTERNAL` is 96 and `nbMaxUserDefined` is 25. The table therefore has **121 entries**, numbered **0 through 120**. Index **121** is already outside it. An early research note estimated approximately 115 entries; the later report corrected that estimate by counting the actual enumeration and testing the exact boundary.

The neighboring branch for user-defined language names checks its growing index against the array extent. This makes the defect particularly clear: two input paths populate the same table, but only one applies an upper bound.

The data flow is short:

```text
Deployed overrideMap.xml
  → association.langID parsed as an integer
  → non-negative check
  → _parsers[langID] owning-pointer assignment
  → access beyond the table when langID ≥ 121
```

## What the attacker controls

The XML value controls the array index, and therefore the offset relative to the parser table. It does **not** supply an arbitrary pointer value. `std::make_unique` creates a new `ParserInfo`; the allocator determines its address. The XML also influences that object's parser identifier.

On the tested x64 build, the table holds eight-byte owning pointers. Assigning through an out-of-range `unique_ptr` is undefined behavior and may involve accessing or disposing of an old pointer as well as storing the new one. A process exit alone does not identify which machine instruction faulted.

That distinction keeps the useful finding precise: an input-controlled index reaches an owning-pointer operation outside a fixed table. It does not establish an arbitrary-address/arbitrary-value write or a working code-execution exploit.

## Boundary tests and controls

The initial experiments used fresh portable copies, changed one association, started the editor, and opened Function List. The later boundary tests compared the last valid index with the first invalid one.

| Configuration | Recorded result | What it establishes |
|---|---|---|
| Unmodified stock file | Panel opened normally | Normal initialization succeeds |
| `langID = 120` | Alive in 3/3 trials | Last valid slot is accepted |
| `langID = 121` | Crash in 3/3 trials, `0xC000041D` | Failure begins at the exact array boundary |
| `langID = 122` | Alive in 3/3 trials | An invalid index need not cause an immediate crash |
| Several larger values, including 200 and 500 | Repeated crashes | The failure is not limited to one value |

`0xC000041D` reports a fatal exception in a user callback. Other runs produced `0xC0000409`, a fail-fast status whose name alone does not prove a stack-buffer overflow.

The source establishes why out-of-range values are unsafe; the controls tie the observed failure to this parsing path. Conversely, an “alive” result does not reveal the exact neighboring object or prove that the write landed harmlessly in padding. The historical notes described non-crashing bands as silent corruption, but did not capture the surrounding allocation layout for each run.

The public advisory contains the original minimal reproduction. The important experimental comparison is **120 versus 121**, alongside an unchanged configuration, rather than a collection of ever-larger crash inputs.

## Security relevance and disclosure

The violated memory-safety invariant is straightforward: a configuration field must not address storage outside the parser table. The protected-security impact still depends on how the configuration enters the system.

Under a malicious-configuration delivery model, the victim installs the supplied configuration and opens the panel. Under a model where only already-trusted code can modify this file, the same defect can be treated as a robustness or hardening issue. The published advisory explicitly preserves that distinction.

| Date | Recorded event |
|---|---|
| August 29, 2026 | Portable-copy experiments recorded repeated failures and passing stock controls |
| September 1, 2026 | Revised report documented the exact 121-entry boundary |
| September 24, 2026 | Maintainer published GHSA-9rr8-6vjg-gj52 |

As checked on October 10, 2026, the advisory lists affected version **8.9.8**, **no known CVE**, and **None** in its patched-versions field. That metadata does not establish the behavior of every later build. Its 5.5 rating describes the published assessment, not a new score assigned here. [Published status and impact](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-9rr8-6vjg-gj52).

## The implementation lesson

A safe parser validates against the actual container extent before indexing. It also decides whether a value is a valid language identifier: fitting in storage and being meaningful to the application are separate checks. Where possible, expressing the bound through the container size avoids repeating an enumeration-dependent constant.

Validating this XML ingestion branch protects this entry point. Other callers that use the parser table still need their own range guarantees; a bound established in one parser does not automatically protect another path.

The broader lesson is that configuration parsers deserve the same bounds discipline as document parsers. A field described as an identifier becomes a memory-safety concern as soon as code uses it directly as an array index.
