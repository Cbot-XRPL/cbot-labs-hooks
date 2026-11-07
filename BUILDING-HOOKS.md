# Building C Hooks

Canonical build note for every repo in this group that compiles a Xahau C hook.
Last rewritten 2026-11-06, after we got reproducibility working end to end.

**Read the decision table, then the one section that applies to you.**

| What you are doing | Use | Reproducible? |
|---|---|---|
| A brand-new hook, nothing live yet | `@xahau/hooks-cli` locally | no, and it doesn't matter |
| Patching a hook that is **already installed on an account holding value** | `hook-repro`, recipe `buildbox-2026-10` | **yes, byte-for-byte** |
| Checking whether any wasm will even install | `hook_validate` RPC | n/a |

The old remote compile service is gone. The replacement is not a drop-in, and if you
treat it as one on a hook that is near the instruction ceiling you will produce a
module that compiles cleanly, is the right size, and that the ledger flatly refuses.

---

## 1. What happened to the buildbox

Every build script in these repos used to POST C source to `hook-buildbox.xrpl.org` and
get WASM back, via `@transia/hooks-toolkit-cli` and `HOOKS_COMPILE_HOST`.

`Xahau/hooks-cli` PR #61, merged **2026-10-19**, removed `HOOKS_COMPILE_HOST` and the
`--xrpl` flag and moved compilation in-process. The hosted origin went away with it. The
hostname still resolves because the Cloudflare record is still there, so you get a **523**
("edge up, origin unreachable") instead of a DNS failure — which is why it reads like an
outage that never ends. The same PR dropped JS Hooks support, so if a JS Hooks endpoint
broke at the same moment, that is this same event.

There is no successor host. Don't go looking; we already did (seven candidate hostnames,
the Hooks Builder IDE's JS bundles pulled apart for every URL in them, its origin probed
for a build API). The compiler's own repo documents only running it yourself, and the only
address it mentions is `localhost:9000`.

---

## 2. The constraint nobody wrote down: 65,535 instructions

This is the single most important thing in this document and none of our scripts
mentioned it before this month.

Xahau's **GuardCheck** walks a hook's worst-case execution path at `SetHook` time and
**refuses any hook whose worst case exceeds 65,535 instructions.** That is a limit on
*execution*, not on bytes. Two modules of nearly identical size can be 60,000 and 330,000.

Why it moves so violently: GuardCheck multiplies each guarded loop's body by that guard's
`maxiter`, and it does that **at every site the loop lands in**. Inline a guarded loop into
six call sites and you have paid for it six times. So a compiler that inlines a little more
aggressively than the original does not nudge the count — it multiplies it.

Measured on the live AMM source, unchanged:

| build | size | worst-case instructions |
|---|---|---|
| live on mainnet (`834741D6`) | 57,623 B | **59,920** — 91% of budget |
| current `@xahau/hooks-cli`, `-O3` | 57,046 B | **328,171** — 5.5× over, refused |

Same source. Same guards — 92 call sites, identical ids, identical maxima, sum 1,726, in
both modules. Same loop count. The size even went *down*. And it will not install.

**Measure before you try to install.** The `hook_validate` RPC gives you the number in
seconds, with no fee and no transaction:

```jsonc
{ "method": "hook_validate", "params": [{ "code": "<WASM AS HEX>" }] }
```

`xahau-vault/scripts/ops/hook-validate.js <file.wasm>` wraps it. Run it on every build.

### Two ways to misread that output

- **It reports each exported function separately.** A hook with a `cbak` gets two numbers.
  I once reported 10,689 as a breakthrough; it was `cbak`'s count and `hook` was still at
  328,171. Read the function name next to the number.
- **An invalid module reports no count at all.** If you get `invalid` with no instruction
  figure, that is almost never a code problem — see the cleaner traps in §6.

`C:\Code\hookz` (community test framework, Python + wasmtime) also does WCE budget
analysis and runs the guard checker, and is worth having for fast local iteration.

---

## 3. New hooks: compile locally

`hooks-compiler` on npm — clang, lld, wasm-opt and hook-cleaner **all compiled to
WebAssembly**, running in Node or the browser. No server, no Docker, no clang install,
no WSL. Needs **Node >= 20.12**.

```bash
npm install --prefix tools/hook-build @xahau/hooks-cli
cd tools/hook-build
node_modules/.bin/c2wasm-cli contracts build            # .c in contracts/, .wasm to build/
node_modules/.bin/c2wasm-cli contracts build --headers headers
```

Or the library, for control the CLI doesn't expose:

```js
// ESM-only. From CommonJS use dynamic import, and on Windows convert the path with
// pathToFileURL first — a bare C:\... path gets read as a URL scheme.
const { pathToFileURL } = require("url");
const { compile, VERSIONS } = await import(pathToFileURL(entryPath).href);
const result = await compile({ files, entry: "my-hook.c", opt: "-O3" });
// result.wasm, result.finalSize, result.sha256, result.logs
```

Two things that will bite you:

- **Headers must be passed in `files`.** It takes a flat virtual filesystem; pass the `.c`
  alone and clang dies on the first `#include`. Key them by **basename** so
  `#include "error.h"` resolves. They ship at
  `node_modules/@xahau/hooks-cli/dist/npm/src/init/c/contracts/include/`.
- **The CLI hard-defaults to `-O2`** with no flag to change it. The library takes
  `opt: "-O0" … "-O3" | "-Os" | "-Oz"`.

This is the right tool for a new hook. It is the wrong tool for §4.

---

## 4. Patching a live hook: reproduce first, then change one thing

**This works. It is proven. The earlier version of this note said it didn't — that was
wrong, and it was wrong because we hadn't found the missing ingredient yet.**

Use [`hook-repro`](https://github.com/Hugegreencandle/hook-repro). It pins an exact
toolchain per recipe in Docker and verifies a local build against the `HookDefinition`
read from two RPC endpoints at the same ledger. Recipe **`buildbox-2026-10`** reproduces
the retired service byte-for-byte.

```bash
# prove the recipe on the UNCHANGED source first
hook-repro build ./src-baseline --recipe buildbox-2026-10 \
  --param CLANG_OPT=-O3 --param WASMOPT=builder2025 --param STAGES=opt,clean \
  --out ./out-baseline

# then the patched source, identical recipe, identical params
hook-repro build ./src-fix --recipe buildbox-2026-10 \
  --param CLANG_OPT=-O3 --param WASMOPT=builder2025 --param STAGES=opt,clean \
  --out ./out-fix
```

`hook-repro verify --hookhash <live hash> --src ./src-baseline` does the ledger comparison
for you. Exit codes: `0` reproduced, `2` mismatch, `3` unverified, `1` usage.

### The missing ingredient was `WASMOPT=builder2025`

Not an optimisation level. A **fixed pass list**, and `wasm-opt` runs **twice**:

```
# 1 — the clang driver's own call, after wasm-ld
/tc/wasm-opt <out> -O3 -o <out>

# 2 — builder2025: a fixed 23-pass list, shrink-level cranked, -O3 last
/tc/wasm-opt --shrink-level=100000000 --coalesce-locals-learning --vacuum --merge-blocks \
  --merge-locals --flatten --ignore-implicit-traps -ffm --const-hoisting --code-folding \
  --code-pushing --dae-optimizing --dce --simplify-globals-optimizing \
  --simplify-locals-nonesting --reorder-locals --rereloop --precompute-propagate \
  --local-cse --remove-unused-brs --memory-packing -c --avoid-reinterprets -O3

# 3 — then the cleaner
/tc/hook-cleaner
```

No single `-O` level reaches that output, which is why sweeping `-O0` through `-Oz` never
matched and made it look like the bytecode was unrecoverable. It was recoverable; we were
guessing at the wrong axis.

What the recipe pins, for the record:

| | |
|---|---|
| recipe digest | `8da93100b630d594e1b282f230cf8ae322d9a1082f2b1f2196287d96105c9d4b` |
| base image | `node@sha256:c7bde48048debf58dba50f8d2ba674854bdf7dfc8c43bd468f19a5212facfdbe` |
| clang | 15.0.0, XRPLF/llvm-project fork via XRPLF/wasi-sdk, prebuilt in `xrpl-hooks-compiler` v1.27 `bin.zip` |
| wasm-opt | binaryen **108**, the static x86-64 binary committed at `xrpl-hooks-compiler docker/wasm-opt` (2022-06-13) |
| hook-cleaner | `XRPLF/hook-cleaner-c` b856a36 |
| guard checker | `RichardAH/guard-checker` de69e8a |
| headers | `Xahau/xahaud` `hook/*.h` at 8bcebdea |

Determinism comes from `SOURCE_DATE_EPOCH=0`, `TZ=UTC`, `LC_ALL=C`, and clang getting
`__DATE__` / `__TIME__` / `__TIMESTAMP__` pinned to the epoch. Don't strip those.

### Why the unchanged build comes first, always

It makes the toolchain a **control**. Reproduce the live hash from untouched source and
every remaining byte of difference in the next build is attributable to your source change
and nothing else. Skip that step and a hash mismatch tells you nothing, because you can't
separate your edit from the compiler.

That is the whole discipline, and it is cheap — a build is about four seconds.

---

## 5. Worked example: the AMM security patch

Three source changes to `amm-v2-remitadd-recv.c`, built through the recipe above:

| | hash | size | instructions |
|---|---|---|---|
| baseline, reproduces mainnet | `834741D6864C005D…` | 57,623 B | 59,920 (91%) |
| patched | `9513A84D9D3F5EF3…` | 57,711 B | 60,517 (92%) |

**+88 bytes, +597 instructions, 5,018 left under the ceiling.** Stage by stage, so you can
see where the bytes go:

```
baseline   clang 57,925 -> wasm-opt 57,845 -> cleaner 57,623
patched    clang 58,014 -> wasm-opt 57,933 -> cleaner 57,711
```

Both VALID, both installable. Being at 91% of budget does not mean a hook can't be
patched — it means you measure each build instead of guessing.

Then testnet, because a hash and an instruction count prove the build, not the behaviour.
`100-2/scripts/battle-test/amm-fix-battle.js` stands up two pools, installs the baseline on
one and the patch on the other, and runs the exploit against both: **16/16 PASS** — both
flaws reproduced on the current build, both refused by the patch, ordinary SWAP / ADD / REM
unaffected. Control-pool reproduction is the point; if the flaw doesn't fire on the
baseline, the finding is wrong and the test says so rather than passing quietly.

---

## 6. Traps, every one of which cost us real time

**`core.autocrlf=true` breaks hook-repro.** It is set globally on the Windows box, so
cloning rewrites every `.sh` with CRLF, and the Linux container then reads
`set -euo pipefail\r` and dies with `set: line 12: illegal option -`. It surfaces as an
opaque `pipeline exit 2` and looks like a Docker problem. Clone repos whose scripts run in
containers with `core.autocrlf=false`, or run `xahau-vault/scripts/ops/fix-crlf.js <dir>`
(it fixed 117 files and was the last thing standing between us and a reproduced hash).

**The guard checker passing does not mean your source loops are guarded.** It inspects the
*wasm*, not the C. A source loop the optimiser fully unrolls leaves no loop in the module,
so an unguarded one is invisible — the baseline AMM passes the guard checker with an
unguarded `for` at line 1443. Change optimiser or compiler and that loop reappears, now
unguarded, and the hook stops installing. **Audit guards in the C, not in the binary.**
`xahau-vault/scripts/ops/find-unguarded-loop.js` does the source pass.

**A hook must not export `memory`, and must carry no custom sections.** Either one gets the
module rejected outright, reported as `invalid` with no instruction count — which reads
like a code failure and isn't. binaryen emits a `name` section (sometimes `producers`) and
both are custom sections, so a module gets refused for carrying debug metadata while the
code is perfectly fine. `hook-cleaner` handles it; if you roll your own pipeline, strip the
`memory` export and every section id 0, and do it **after** `wasm-opt` — strip first and
dead-code elimination takes the memory and data segments with it. See
`xahau-vault/scripts/ops/build-pinned.js`.

**Install Docker rather than rebuilding the toolchain natively.** Chasing a native wasi-sdk
15 burned hours; Docker Desktop took two minutes and hook-repro worked immediately. If
you're on Windows with WSL already installed you are most of the way there.

**`@transia/ripple-binary-codec` has no `HookCanEmit` field.** Any test rig bundling it has
to omit `HookCanEmit` from `SetHook`, which is fine on testnet but means the rig is not
exercising emit restrictions. Don't read a green rig as covering that.

**Check an RPC helper rejects `{"result":{"error":"tooBusy"}}`.** Ours treated it as
success, which presented as "reward fields unset, 0 transactions" and sent us hunting a
chain bug that didn't exist. Reject `r.error` explicitly.

---

## 7. Migrating a repo that still points at the old host

1. `npm install --prefix <workspace> @xahau/hooks-cli`
2. Repoint the build script at `c2wasm-cli` or the library, not
   `@transia/hooks-toolkit-cli`.
3. Delete `HOOKS_COMPILE_HOST` from `.env` and from the script's environment. Leaving it
   set is harmless but tells the next reader a server is still involved.
4. Make the script **fail loudly** when only the old CLI is present, rather than making a
   network call that hangs or 523s.
5. **Add an instruction-count check to the build script**, not just a size check. This is
   the step everyone skips.
6. If the hook is live and holds value, route it through §4 instead.

Reference implementations in `xahau-vault/scripts/ops/`, all copyable:
`hook-validate.js` (measure any wasm — start here), `build-pinned.js` (the four stages,
each skippable), `stage-repro-src.js` (one `.c` per directory; hook-repro compiles a whole
directory), `fix-crlf.js`, `find-unguarded-loop.js`, `guard-census.js`, `loop-weight.js`
(ranks guarded loops by body × maxiter when you need to find what is eating the budget),
`wasm-diff-structure.js`, `amm-determinism-check.js`.

---

## Sources

- [Xahau/hooks-cli PR #61](https://github.com/Xahau/hooks-cli/pull/61) — removes the compile host
- [hooks-compiler on npm](https://www.npmjs.com/package/hooks-compiler)
- [Xahau/xrpl-hooks-compiler](https://github.com/Xahau/xrpl-hooks-compiler)
- [hook-repro](https://github.com/Hugegreencandle/hook-repro) — recipe `buildbox-2026-10`
- [hookz](https://github.com/sublimator/hookz) — local unit-testing + WCE budget analysis
