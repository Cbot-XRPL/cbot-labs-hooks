/* Build src/broker.c -> build/broker.wasm via the Xahau hook buildbox (no local toolchain, no Docker).
 *
 *   npm install      # once — pulls @transia/hooks-toolkit-cli
 *   npm run build
 *
 * The buildbox compiles C -> WASM server-side and supplies hookapi.h, so you need no local toolchain or header
 * (the only includes are hookapi.h + <stdint.h>). Default host https://hook-buildbox.xrpl.org; override with
 * HOOKS_COMPILE_HOST. Prints the on-chain HookHash (sha512half) of the produced wasm.
 */
const fs = require("fs"), path = require("path"), crypto = require("crypto"), { spawnSync } = require("child_process");
const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "node_modules", "@transia", "hooks-toolkit-cli", "bin", "cli.js");
if (!fs.existsSync(CLI)) { console.error("toolchain missing — run: npm install"); process.exit(1); }
const src = path.join(ROOT, "src", "broker.c");
if (!fs.existsSync(src)) { console.error("src/broker.c not found"); process.exit(1); }

// the CLI compiles every .c in <in>/ -> <out>/ (relative to cwd); work in a throwaway dir so nothing is clobbered
const work = path.join(ROOT, ".hookbuild");
const contracts = path.join(work, "contracts"), out = path.join(work, "build");
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(contracts, { recursive: true }); fs.mkdirSync(out, { recursive: true });
fs.copyFileSync(src, path.join(contracts, "broker.c"));

const host = process.env.HOOKS_COMPILE_HOST || "https://hook-buildbox.xrpl.org";
console.log(`compiling src/broker.c via ${host} …`);
const r = spawnSync(process.execPath, [CLI, "compile-c", "contracts", "build"], { cwd: work, encoding: "utf8", env: { ...process.env, HOOKS_COMPILE_HOST: host } });
if (r.stdout) process.stdout.write(r.stdout.split("\n").slice(-12).join("\n") + "\n");
if (r.status !== 0) { console.error("BUILD FAILED:\n" + (r.stderr || "").split("\n").slice(-30).join("\n")); fs.rmSync(work, { recursive: true, force: true }); process.exit(1); }

const wasm = path.join(out, "broker.wasm");
if (!fs.existsSync(wasm)) { console.error("no wasm produced (see log above)"); fs.rmSync(work, { recursive: true, force: true }); process.exit(1); }
const bytes = fs.readFileSync(wasm);
const dst = path.join(ROOT, "build", "broker.wasm");
fs.mkdirSync(path.dirname(dst), { recursive: true });
fs.writeFileSync(dst, bytes);
fs.rmSync(work, { recursive: true, force: true });

const hash = crypto.createHash("sha512").update(bytes).digest("hex").slice(0, 64).toUpperCase();
console.log(`✓ build/broker.wasm  ${bytes.length} B`);
console.log(`  HookHash (sha512half): ${hash}`);
