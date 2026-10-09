ONNX Runtime Reshape initializer: historical evidence
Published 2026-10-10 | Archive IDs: VR-2026-006 / ONNX-006

MSRC's final decision is that this case does not meet Microsoft's definition of a security vulnerability and is below the servicing threshold. MSRC assessed a recoverable process crash without a security boundary crossing, stated that the assessed version validates raw_data byte length before copying, and closed the case with no bounty, no CVE and no further MSRC tracking. The final response supersedes the original report's security classification and requests. The response is reproduced separately in msrc-final-response.txt; its technical assessment is attributed to MSRC, not independently reproduced here.

Files

- native-run-1.txt and native-run-2.txt: two saved native exception captures from 2026-09-12, with matching DLL/model hashes. Both record exception 0xC0000005, a write to address zero, fault RVA onnxruntime+0x75DE7B and a stack-top word at onnxruntime+0x6DDCBF.
- harness-output-1.txt and harness-output-2.txt: the associated saved Python tracebacks. Their contents are identical. ctypes surfaces the native exception as an OSError that escapes this harness.
- parsedata-int64-complete.txt: the complete historical ParseData<int64> disassembly export, dated 2026-09-13, containing 179 addressed instructions. The original explanatory header is retained. It describes the hash-identified historical DLL, not every ONNX Runtime release or the version assessed by MSRC.
- manifest.json: original archive filenames and SHA-256 hashes, published filenames and SHA-256 hashes, transformations, DLL/model identities and evidence limits.
- msrc-final-response.txt: final response supplied by the researcher for this publication; not a separately authenticated public Microsoft advisory.

Provenance and limits

The local research directory prefix in the five historical text artifacts was replaced with <research-root>; fault values, addresses and instructions were retained. The original source hashes do not equal the hashes of these sanitized public copies. Use the published hashes in manifest.json to verify downloads.

The disassembly header retains references to original archive filenames. The manifest maps those names to the published files. Its separately mentioned annotated excerpt is not included; the complete function is supplied here.

The native logger scanned raw stack words for addresses inside the module. It did not produce a complete unwound call stack. The stack-top/call-site correspondence is useful; deeper entries must not be presented as an ordered chain of callers.

The source archive reports successful valid-encoding and clean-rejection controls and a broader 5/5 result. This pack contains two saved native captures, not five, and does not include separate raw control-run logs. Those control results remain attributed to the research notes. The valid int64_data control in the original harness also included a Transpose node, so it was not a single-variable graph comparison.

The DLL acquisition build reported in the submission was Windows Insider Dev 10.0.29648.1000. Acquisition and execution environments are separate facts. These ONNX-006 captures do not record an exact host Windows build or Python version. The runtime string 1.17.1 does not establish an upstream affected-version range.

This is an evidence archive for a closed-case lessons-learned article. No model, DLL or executable reproduction harness is distributed here. No new runtime testing was performed for publication. The artifacts do not establish arbitrary write, code execution, privilege escalation or a security boundary crossing. Original labels such as "defect" in the retained export header describe the research interpretation at the time; they do not override MSRC's final disposition.
