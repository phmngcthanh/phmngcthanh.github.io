---
layout: ../../layouts/ArticleLayout.astro
lang: en
title: "ONNX Runtime Reshape Null-Write: Lessons from a Closed MSRC Report"
description: "A malformed initializer, two native fault captures, and MSRC's non-vulnerability verdict: what ONNX-006 taught us about validation, evidence, and security impact."
published: "2026-10-10"
category: "Research Notes"
tags:
  - onnx-runtime
  - native-debugging
  - model-validation
  - research-lessons
draft: false
---

During our ONNX Runtime research, we recorded a native write to address zero while loading a malformed `Reshape` model. Its shape initializer declared two 64-bit integers but supplied only two bytes of raw data. The saved binary analysis explained how a zero-element destination and a nonzero copy length met at `memmove`.

**MSRC closed the case as not meeting Microsoft's definition of a security vulnerability and below the threshold for servicing.** Its final response says the assessed version validates the initializer's `raw_data` byte length before copying. MSRC assessed the impact as a recoverable process crash when an application loads an attacker-supplied model, without a security boundary crossing. No bounty or CVE will be issued, and MSRC will not track the case further.

This article preserves the technical observation and that final disposition. The useful lesson is how to connect a native fault to its actual scope, describe incomplete evidence honestly, and keep a historical binary finding separate from the vendor's assessment.

*ONNX-006 is our internal report identifier, not an MSRC case number. The archived submission is dated September 13, 2026. This article uses existing records; no models or reproduction programs were run for publication.*

## The model's inconsistent promise

`Reshape` takes a data tensor and an `INT64` shape tensor describing the desired output dimensions. A graph can supply that shape through an initializer stored in the model. The [Reshape specification](https://onnx.ai/onnx/operators/onnx__Reshape.html) defines the operator's inputs; the [ONNX IR specification](https://onnx.ai/onnx/repo-docs/IR.html) explains how graph initializers provide values.

An initializer has its own type, dimensions, and serialized data. Those dimensions describe the initializer itself. In this case, `dims=[2]` meant a one-dimensional initializer containing **two shape values**; it was not the requested output shape.

| Property | Recorded malformed initializer |
| --- | --- |
| Element type | `INT64`, eight bytes per element in raw encoding |
| Initializer dimensions | `[2]` |
| Required raw-data length | `2 × 8 = 16` bytes |
| Supplied raw-data length | `2` bytes |

The raw encoding uses fixed-width, little-endian elements. It is distinct from the type-specific `int64_data` protobuf field. Two raw bytes therefore cannot encode the declared two `INT64` elements. [TensorProto schema, ONNX v1.17.0](https://github.com/onnx/onnx/blob/v1.17.0/onnx/onnx.proto).

That mismatch is a validation problem before any useful inference can begin. In the retained experiment, it was encountered during session creation. The evidence does not describe a fault triggered by an ordinary inference request to an already loaded, trusted model.

## Exactly what we examined

The archived report identifies a Windows-shipped `onnxruntime.dll` acquired from **Windows Insider Dev build 10.0.29648.1000**. Both native captures record its runtime version string as **1.17.1** and the same DLL hash.

| Item | Evidence scope |
| --- | --- |
| Component | One hash-identified x64 `onnxruntime.dll` |
| Acquisition build | 10.0.29648.1000, according to the archived report |
| Runtime label | `1.17.1`, recorded by the capture harness |
| Model | `reshape-short-notranspose.onnx`, 108 bytes |
| Harness | x64 Windows, Python with `ctypes`, ONNX Runtime C API |
| Saved native captures | September 12, 2026, at 15:27:38Z and 15:28:10Z |
| Session setup | File-based `CreateSession`; graph optimization disabled in the retained capture script |

The DLL's acquisition build is not the harness host's Windows version. The retained native logs do not identify the exact host OS build or Python version. We do not fill those gaps with environment details from other experiments.

```text
DLL SHA-256
d6e14879a5d697145c722a5e72bcfbffb4c187c5dcf0bf1d597cc060ba04bc72

Model SHA-256
8f1e2ef341ac96c49137aeae46b9359639f38c0670d9442f9993686b213b7484
```

The `1.17.1` string is an identifier reported by this binary. It does not establish an affected range across upstream ONNX Runtime packages, Windows releases, or other DLLs carrying the same label.

## What the native records show

Both retained captures contain these fields:

```text
code=0xC0000005
param[0]=0x0000000000000001
param[1]=0x0000000000000000
fault RVA (onnxruntime+0x75DE7B)
stack[RSP+0x0] = onnxruntime+0x6DDCBF
```

For an access violation, Windows defines the first exception parameter as the access type and the second as the inaccessible address. Here, `1` means a write and the address is zero. This supports the description **native null-write fault**. [EXCEPTION_RECORD documentation](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record).

The captures agree on the DLL and model hashes, the fault RVA, and the stack-top word. That gives us two matching saved observations. An older research note reported more repetitions, but the public evidence pack supports these two directly. [First capture](/evidence/onnx-reshape-null-write/native-run-1.txt), [second capture](/evidence/onnx-reshape-null-write/native-run-2.txt).

The harness output adds a detail that changed how we described the outcome:

```text
OSError: exception: access violation writing 0x0000000000000000
```

`ctypes` surfaced the native exception as an `OSError`, which escaped the harness. The saved record therefore supports failure of this model-loading harness. It does not establish that every application embedding the library would terminate, remain unavailable, or recover in the same way. [Harness output 1](/evidence/onnx-reshape-null-write/harness-output-1.txt), [harness output 2](/evidence/onnx-reshape-null-write/harness-output-2.txt).

The logger also scanned stack words for values inside the DLL's address range. **That scan is not an unwound call stack.** We use the stack-top value as a correspondence with the saved call site below; we do not turn every deeper candidate into an ordered caller chain.

## The allocation and copy used different lengths

The historical report included a complete, 179-instruction export of the function identified as `onnx::ParseData<int64>`, starting at VA `0x1806DDB64`. Its raw-data branch contains this sequence:

```asm
1806ddca2  mov rdx, rdi
1806ddca5  shr rdx, 3
1806ddca9  mov rcx, rsi
1806ddcac  call std::vector<double>::resize(unsigned __int64)
1806ddcb1  mov r8, rdi
1806ddcb4  mov rdx, rbx
1806ddcb7  mov rcx, [rsi]
1806ddcba  call memmove
1806ddcbf  jmp short loc_1806DDC89
```

The saved analysis identifies `rdi` as the raw byte length. The shift divides that length by eight, truncating the result, before resizing the destination. The copy then receives the **original byte length**. For the recorded sample:

```text
raw byte length               2
destination element count    2 >> 3 = 0
copy byte count              2

recorded initialized destination: NULL
resulting operation: memmove(NULL, source, 2)
```

The complete export also shows the destination vector fields being zeroed before this branch. The null destination explanation applies to that initialized vector and the recorded two-byte case. It is not a claim that every empty C++ vector has a null data pointer.

The recovered resize symbol says `std::vector<double>`. We preserve that name as it appears in the export; it is not evidence that the model contained floating-point shape values. The relevant observations are the eight-byte sizing arithmetic, the initialized destination state, and the unchanged byte count passed to the copy. [Complete saved disassembly](/evidence/onnx-reshape-null-write/parsedata-int64-complete.txt).

At image base `0x180000000`, the instruction following the `memmove` call has RVA `0x6DDCBF`. That matches the stack-top word in both native captures. The saved analysis places the fault at RVA `0x75DE7B` inside `memmove`. Together, these artifacts explain the recorded failure without requiring a speculative full stack trace.

The desired loader behavior is to reject the inconsistent initializer before an invalid copy. Explaining this historical path does not establish an arbitrary write primitive, control-flow hijacking, or code execution; none was demonstrated in the submitted evidence.

## What the controls did, and did not, establish

The archived research and submission describe two controls:

| Control | Reported outcome | Qualification |
| --- | --- | --- |
| Correctly encoded `int64_data` shape | Session creation succeeded | This model also included a `Transpose`; it was not a single-variable comparison with the crash model. |
| `Identity` consuming a truncated `INT64` initializer | Clean buffer-size-mismatch rejection | This exercised a different consumption path, not every initializer path. |

Those outcomes are retained research-record assertions. The public pack contains the two native fault captures and their harness output, not separate raw transcripts of those controls. Readers should give them different evidentiary weight.

The capture setup disabled graph optimization and still recorded the fault. That supports the narrower point that this experiment did not depend on enabling those optimizations. It does not mean session creation skipped all parsing, graph resolution, or shape handling.

## MSRC's final verdict

The final response supplied for this article states:

> After careful review, this case does not meet Microsoft's definition of a security vulnerability and is below threshold for servicing.

It also states:

> The reported malformed ONNX Reshape model handling is addressed in the assessed version through validation of the initializer's raw_data byte length before copying.

MSRC assessed the remaining impact as a recoverable process crash when an application loads an attacker-supplied model, without a security boundary crossing. The response says the information was shared with the responsible engineering team for awareness and internal review. It specifies no bounty eligibility, no CVE, and no further MSRC tracking. [Full final response, transcribed from the researcher-supplied text](/evidence/onnx-reshape-null-write/msrc-final-response.txt).

The supplied response does not name the assessed version, a fixing commit, a first fixed release, an MSRC case number, or its original send date. We preserve those as unknowns. The September binary record cannot answer what version MSRC assessed, and the response does not establish a universal fixed-version range.

These are different kinds of evidence: the captures document one historical binary's behavior; the final response records the vendor's assessment and disposition. Sharing a report with engineering is not acceptance of it as a security vulnerability. This is also more than a bounty rejection: MSRC explicitly concluded that the case did not meet its vulnerability definition.

## What we learned

**Describe the outcome at each layer.** The native exception, its conversion to a Python exception, the harness's failure, and a deployed application's availability are separate observations. Our records establish the first three for this harness. They do not supply a victim service's recovery behavior or sustained availability loss.

**Keep units explicit when decoding tensors.** The historical path used an element count for destination sizing and a byte count for copying. The invariant to preserve is that the declared shape, encoded byte length, and destination capacity agree before the copy. MSRC's statement about length validation addresses this same validation concern in its assessed version.

**A model-loading test needs an accurate application context.** The input here was a whole malformed model loaded through the C API. We did not establish remote delivery, a first-party application consuming it, an isolation escape, or a privilege transition. Naming those limits makes the report more useful than attaching a hypothetical service impact to a local harness.

**Preserve identifiers and negative evidence.** Binary hashes prevent a runtime label from becoming an unsupported affected-version claim. Full function context helps explain a short instruction excerpt. Control limitations and the escaping `OSError` remain part of the story even when they narrow the initial interpretation.

**A closed case can still improve engineering practice.** For applications that import models, validation and failure containment remain useful reliability concerns. ONNX Runtime's own documentation recommends inspecting models from untrusted sources and testing them in a safe environment before production use. That general guidance is not a claim that this case bypassed a security boundary. [ONNX Runtime model-validation guidance](https://onnxruntime.ai/docs/#model-validation).

The lesson we carry forward is to make the evidence support the exact claim being made. Here, a well-documented historical null write coexists with a final non-vulnerability verdict. Both belong in the community record.

## Evidence and provenance

The [evidence bundle](/evidence/onnx-reshape-null-write/evidence.zip) contains the two native captures, both harness outputs, the complete saved function export, the supplied final MSRC response, and provenance notes in English and Vietnamese. The [manifest](/evidence/onnx-reshape-null-write/manifest.json) records original and public-file SHA-256 values. Local research-directory prefixes were replaced with `<research-root>`; the notes document formatting changes. This is a collection of historical records, not a newly executed reproduction.

Individual files are available above, with an [English evidence guide](/evidence/onnx-reshape-null-write/README.en.txt) and a [Vietnamese evidence guide](/evidence/onnx-reshape-null-write/README.vi.txt). The model and DLL hashes identify the original inputs; executable artifacts are not included in this text evidence bundle.
