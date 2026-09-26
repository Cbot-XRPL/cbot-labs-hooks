#!/usr/bin/env node
/*
 * Cbot Labs — AMM v2 pool installer
 * ----------------------------------------------------------------------------
 * Installs the constant-product AMM hook (XAH <-> one IOU) on a FRESH, DEDICATED
 * Xahau account that becomes the pool. The pool account holds the reserves; only
 * its hook moves them, and only in response to ADD / REM / SWAP / DAOCLAIM from
 * the party whose value is moving.
 *
 * It does two things, both signed by the pool account:
 *   1. TrustSet  -> pool trusts the IOU (CUR/ISSUER) so it can hold the second leg
 *   2. SetHook   -> slot 0 <- amm-v2 hook with all 16 install parameters
 *
 * Usage (values are examples — every param is documented in README.md):
 *   POOL_SEED=s... CUR=EVR ISSUER=r... LP_CUR=ELP FEEBPS=30 ADMIN=r... DAO_DEST=r... \
 *     node install-amm.js --network testnet              # DRY-RUN (nothing sent)
 *     node install-amm.js --network testnet --apply      # install
 *     node install-amm.js --network mainnet --apply
 *   flags: --upgrade        re-send the hook + ALL params to a pool that already runs a
 *                           previous AMM build (required: a SetHook without the full
 *                           param set leaves the pool "not initialized")
 *          --maxfee N       refuse a SetHook whose quoted fee is above N XAH (default 80)
 *          --net wss://...  custom node
 *
 * Env params (required):  POOL_SEED  CUR  ISSUER  LP_CUR
 * Env params (optional):  FEEBPS=30  DAO_BPS=0  DAO_DEST=<ADMIN>  DAO_MIN=1 (XAH)
 *                         MINXAH=0.1 (XAH)  MINIOU=0.1 (IOU)  ADMIN=<pool address>
 *                         MAX_RXAH=0 MAX_RIOU=0 MAX_TOTX=0 MAX_TOTY=0 (0 = uncapped)
 *                         CORENS=<64 hex, default all-zero>  FEECCY=0|1
 *
 * The seed is read from the POOL_SEED env var and used only to sign locally — it is
 * never sent anywhere. Nothing is submitted without --apply.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const xrpl = require('@transia/xrpl');

const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const opt = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] != null ? args[i + 1] : d; };
const die = (m) => { console.error('\n' + m); process.exit(1); };

const APPLY = flag('--apply');
const UPGRADE = flag('--upgrade');
const NETWORK = String(opt('--network', 'testnet')).toLowerCase();
if (!['mainnet', 'testnet'].includes(NETWORK)) die('--network must be mainnet or testnet');
const WS = opt('--net', NETWORK === 'mainnet' ? 'wss://xahau.org' : 'wss://xahau-test.net');
const NETID = NETWORK === 'mainnet' ? 21337 : 21338;
const MAX_FEE_XAH = Number(opt('--maxfee', 80));

// AMM v2 hook constants (do not change).
const EXPECT_HASH = 'B549537D6B7F38F94418C510C625315232DE5F527D8B2585BAED423243CF49A2';   /* 2026-09-26: IOU-in reserve fix; was E000F5F0 */
const HOOK_ON = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77FFFFFFFFFFFFFFFFFBFFFFE'; // fires on Payment(0) + Invoke(99)
const NS = crypto.createHash('sha256').update('amm-v2-hook').digest('hex').toUpperCase();
const WASM_PATH = path.join(__dirname, 'hook', 'amm-v2-remitadd.wasm');

/* ---------- encoding helpers ---------- */
const HE = (s) => Buffer.from(s, 'ascii').toString('hex').toUpperCase();
const u32 = (n) => { n = Number(n); if (!Number.isInteger(n) || n < 0 || n > 0xFFFFFFFF) throw new Error('bad u32 ' + n); return n.toString(16).padStart(8, '0').toUpperCase(); };
const u64 = (n) => { const b = BigInt(n); if (b < 0n || b > 0xFFFFFFFFFFFFFFFFn) throw new Error('bad u64 ' + n); return b.toString(16).padStart(16, '0').toUpperCase(); };
const micro = (s, what) => { // "12.345678" -> integer micro-units (drops for XAH, 1e-6 for IOU)
  const m = String(s).trim().match(/^(\d+)(?:\.(\d{1,6}))?$/); if (!m) throw new Error(`${what}: expected a decimal with at most 6 places, got "${s}"`);
  return BigInt(m[1]) * 1000000n + BigInt((m[2] || '').padEnd(6, '0'));
};
const curHex = (c, what) => {
  c = String(c).trim();
  if (/^[0-9A-Fa-f]{40}$/.test(c)) return c.toUpperCase();
  if (/^[A-Za-z0-9]{3}$/.test(c) && c.toUpperCase() !== 'XAH') return ('00'.repeat(12) + HE(c) + '00'.repeat(5)); // standard 160-bit layout, ASCII at bytes 12..14
  if (c.length > 3 && c.length <= 20) return HE(c).padEnd(40, '0');                                            // non-standard code (ASCII, zero-padded)
  throw new Error(`${what}: "${c}" is not a 3-char code, a 4–20 char code, or 40 hex`);
};
const acctHex = (r, what) => { try { return Buffer.from(xrpl.decodeAccountID(String(r).trim())).toString('hex').toUpperCase(); } catch { throw new Error(`${what}: "${r}" is not a classic r-address`); } };
const sha512h = (buf) => crypto.createHash('sha512').update(buf).digest('hex').slice(0, 64).toUpperCase();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function pollTx(c, h, ms = 90000){ const s = Date.now(); while (Date.now() - s < ms){ await sleep(2500); try { const t = await c.request({ command: 'tx', transaction: h }); if (t.result?.validated) return t.result; } catch {} } return null; }
async function curLedger(c){ return Number((await c.request({ command: 'ledger_current' })).result.ledger_current_index); }
async function hooksOf(c, acct){ const r = await c.request({ command: 'account_objects', account: acct, type: 'hook', ledger_index: 'validated' }).catch(() => null); return r?.result?.account_objects?.[0]?.Hooks || []; }

(async () => {
  const E = process.env;
  if (!E.POOL_SEED) die('Set the pool account secret:  POOL_SEED=s... node install-amm.js\n(Nothing is submitted without --apply. The seed is used only to sign locally.)');
  for (const k of ['CUR', 'ISSUER', 'LP_CUR']) if (!E[k]) die(`missing env ${k} (see README.md "Install parameters")`);
  const wallet = xrpl.Wallet.fromSeed(String(E.POOL_SEED).trim());
  const pool = wallet.classicAddress;

  const wasm = fs.readFileSync(WASM_PATH);
  const wasmHash = sha512h(wasm);
  if (wasmHash !== EXPECT_HASH) die(`hook wasm hash mismatch (${wasmHash} != ${EXPECT_HASH}) — refusing to install a modified hook.`);

  /* ---------- build the 16 install params ---------- */
  const ADMIN = E.ADMIN || pool;
  const DAO_DEST = E.DAO_DEST || ADMIN;
  const CORENS = String(E.CORENS || '').trim() || '00'.repeat(32);
  if (!/^[0-9A-Fa-f]{64}$/.test(CORENS)) die('CORENS must be 64 hex chars (or omitted for all-zero)');
  const FEEBPS = Number(E.FEEBPS ?? 30), DAO_BPS = Number(E.DAO_BPS ?? 0), FEECCY = Number(E.FEECCY ?? 0);
  if (FEEBPS > 1000) die('FEEBPS above 1000 (10%) — the hook clamps at 1000; pick something sane');
  if (DAO_BPS > 10000) die('DAO_BPS is a share of the fee in bps; max 10000');
  if (![0, 1].includes(FEECCY)) die('FEECCY must be 0 or 1');
  let P;
  try {
    P = [
      ['CUR',        curHex(E.CUR, 'CUR')],
      ['ISSUER',     acctHex(E.ISSUER, 'ISSUER')],
      ['AMM_LP_CUR', curHex(E.LP_CUR, 'LP_CUR')],
      ['FEEBPS',     u32(FEEBPS)],
      ['MINXAH',     u64(micro(E.MINXAH ?? '0.1', 'MINXAH'))],
      ['MINIOU',     u64(micro(E.MINIOU ?? '0.1', 'MINIOU'))],
      ['DAO_BPS',    u32(DAO_BPS)],
      ['DAO_DEST',   acctHex(DAO_DEST, 'DAO_DEST')],
      ['DAO_MIN',    u64(micro(E.DAO_MIN ?? '1', 'DAO_MIN'))],
      ['ADMIN',      acctHex(ADMIN, 'ADMIN')],
      ['MAX_RXAH',   u64(micro(E.MAX_RXAH ?? '0', 'MAX_RXAH'))],
      ['MAX_RIOU',   u64(micro(E.MAX_RIOU ?? '0', 'MAX_RIOU'))],
      ['MAX_TOTX',   u64(micro(E.MAX_TOTX ?? '0', 'MAX_TOTX'))],
      ['MAX_TOTY',   u64(micro(E.MAX_TOTY ?? '0', 'MAX_TOTY'))],
      ['CORENS',     CORENS.toUpperCase()],
      ['FEECCY',     u32(FEECCY)],
    ];
  } catch (e) { die(String(e.message || e)); }
  const HookParameters = P.map(([n, v]) => ({ HookParameter: { HookParameterName: HE(n), HookParameterValue: v } }));

  console.log('Cbot Labs — AMM v2 pool installer');
  console.log(`  pool    : ${pool}`);
  console.log(`  network : ${NETWORK.toUpperCase()}  (${WS})`);
  console.log(`  hook    : ${wasmHash.slice(0, 16)}…  (${wasm.length} B)   ns ${NS.slice(0, 8)}…`);
  console.log(`  mode    : ${APPLY ? 'APPLY — will submit transactions' : 'DRY-RUN — nothing sent'}${UPGRADE ? '  [upgrade]' : ''}`);
  console.log('\n  params  :');
  for (const [n, v] of P) console.log(`    ${n.padEnd(11)} ${v}`);
  console.log(`\n  in words: fee ${FEEBPS} bps, DAO cut ${DAO_BPS} bps -> ${DAO_DEST} (auto-flush at ${E.DAO_MIN ?? '1'} XAH), admin ${ADMIN}, FEECCY ${FEECCY}, caps ${['MAX_RXAH','MAX_RIOU','MAX_TOTX','MAX_TOTY'].map((k) => E[k] ?? '0').join('/')}`);

  const c = new xrpl.Client(WS, { connectionTimeout: 30000 }); c.apiVersion = 1; await c.connect();
  const ai = (await c.request({ command: 'account_info', account: pool, ledger_index: 'validated' }).catch(() => null))?.result?.account_data;
  if (!ai){ await c.disconnect(); die('pool account not found / not activated on this network.'); }
  const bal = Number(ai.Balance) / 1e6;
  console.log(`\n  current : Balance=${bal.toFixed(2)} XAH  Sequence=${ai.Sequence}  RegularKey=${ai.RegularKey || '-'}  Flags=0x${Number(ai.Flags || 0).toString(16)}`);

  /* ---------- refuse anything but a fresh account (unless --upgrade) ---------- */
  const existing = await hooksOf(c, pool);
  const live = existing.filter((h) => h?.Hook?.HookHash);
  if (live.length && !UPGRADE){ await c.disconnect(); die(`pool ${pool} already carries ${live.length} hook(s) (slot 0 = ${existing[0]?.Hook?.HookHash?.slice(0, 10) || '-'}…).\nAn AMM needs a FRESH dedicated account. To re-send the AMM hook + params to an existing pool, pass --upgrade.`); }
  if (UPGRADE){
    if (!existing[0]?.Hook?.HookHash) console.log('  upgrade : slot 0 is empty — treating as a fresh install into slot 0');
    else if (existing[0].Hook.HookHash === wasmHash) console.log('  upgrade : slot 0 already runs this build — params will be re-sent (state preserved)');
    else console.log(`  upgrade : slot 0 ${existing[0].Hook.HookHash.slice(0, 10)}… -> ${wasmHash.slice(0, 10)}…  (state under ns ${NS.slice(0, 8)}… is preserved; other slots untouched)`);
  }
  if (bal < 25) console.log(`  ⚠ balance ${bal.toFixed(2)} XAH is low: the pool needs owner reserve for the hook, the trust line and the two DEX offers it posts, plus the SetHook fee. 25+ XAH recommended.`);

  /* ---------- 1) trust line to the IOU ---------- */
  const curField = P[0][1].endsWith('00'.repeat(5)) && /^0{24}[0-9A-F]{6}0{10}$/.test(P[0][1]) ? String(E.CUR).trim().toUpperCase() : P[0][1];
  const lines = (await c.request({ command: 'account_lines', account: pool, peer: String(E.ISSUER).trim(), ledger_index: 'validated' }).catch(() => null))?.result?.lines || [];
  const hasLine = lines.some((l) => l.currency === curField);
  if (!hasLine){
    let tx = await c.autofill({ TransactionType: 'TrustSet', Account: pool, NetworkID: NETID, LimitAmount: { currency: curField, issuer: String(E.ISSUER).trim(), value: '1000000000000000' } });
    tx.LastLedgerSequence = await curLedger(c) + 40;
    console.log(`\n[1] TrustSet ${curField}/${E.ISSUER} limit 1e15   Fee ${(Number(tx.Fee) / 1e6).toFixed(6)} XAH`);
    if (APPLY){ const s = wallet.sign(tx); await c.request({ command: 'submit', tx_blob: s.tx_blob }); const r = await pollTx(c, s.hash); console.log(`    -> ${r?.meta?.TransactionResult || 'not validated in time'}`); if (r?.meta?.TransactionResult !== 'tesSUCCESS'){ await c.disconnect(); die('TrustSet did not succeed — stopping before SetHook.'); } await sleep(3000); }
  } else console.log(`\n[1] trust line ${curField}/${E.ISSUER} already exists — skip`);

  /* ---------- 2) SetHook slot 0 with all 16 params ---------- */
  const entry = { Hook: { CreateCode: wasm.toString('hex').toUpperCase(), HookOn: HOOK_ON, HookNamespace: NS, HookApiVersion: 0, Flags: 1, HookParameters } };
  const Hooks = [entry]; // only slot 0 is touched; an omitted trailing slot is left as-is
  let setTx = await c.autofill({ TransactionType: 'SetHook', Account: pool, NetworkID: NETID, Hooks });
  const feeXah = Number(setTx.Fee) / 1e6;
  if (feeXah > MAX_FEE_XAH){ await c.disconnect(); die(`SetHook fee quote ${feeXah.toFixed(2)} XAH > ${MAX_FEE_XAH} cap. Hook-fee quotes spike for a few seconds when the open ledger is busy — wait and re-run (or raise --maxfee if you accept it).`); }
  setTx.LastLedgerSequence = await curLedger(c) + 40;
  console.log(`\n[2] SetHook slot 0 <- amm-v2 (Flags 1 = hsfOVERRIDE, 16 params)   Fee ${feeXah.toFixed(2)} XAH`);
  if (feeXah + 25 > bal) console.log(`    ⚠ fee ${feeXah.toFixed(2)} + ~25 XAH reserve headroom exceeds the balance ${bal.toFixed(2)} — a terINSUF_FEE_B here means the ACCOUNT is short, not that the fee is wrong.`);
  if (APPLY){
    const s = wallet.sign(setTx); const sub = await c.request({ command: 'submit', tx_blob: s.tx_blob });
    console.log(`    submit -> ${sub.result?.engine_result} ${sub.result?.engine_result_message || ''}`);
    const r = await pollTx(c, s.hash); console.log(`    -> ${r?.meta?.TransactionResult || 'not validated in time'}  ${s.hash}`);
    if (r?.meta?.TransactionResult !== 'tesSUCCESS'){ await c.disconnect(); die('SetHook did not apply.'); }
    await sleep(4000);
  }

  if (!APPLY){ console.log('\nDRY-RUN complete — re-run with --apply to install.'); await c.disconnect(); return; }

  /* ---------- verify ---------- */
  const after = await hooksOf(c, pool);
  const h0 = after[0]?.Hook || {};
  // Effective params = the hook definition's defaults (stored there on a first CreateCode install) ⊕ per-account overrides.
  // Same for the namespace: a first install of a new hash records it on the definition, later re-installs on the account object.
  let defParams = [], defNs = '';
  try { const d = await c.request({ command: 'ledger_entry', hook_definition: wasmHash, ledger_index: 'validated' }); defParams = d.result?.node?.HookParameters || []; defNs = d.result?.node?.HookNamespace || ''; } catch {}
  const effNs = h0.HookNamespace || defNs;
  const eff = new Map();
  for (const p of defParams) eff.set(p.HookParameter.HookParameterName, p.HookParameter.HookParameterValue);
  for (const p of (h0.HookParameters || [])) eff.set(p.HookParameter.HookParameterName, p.HookParameter.HookParameterValue);
  const missing = P.filter(([n, v]) => eff.get(HE(n)) !== v).map(([n]) => n);
  console.log('\n=== result ===');
  console.log(`  slot 0 hash   : ${h0.HookHash === wasmHash ? '✓ ' + wasmHash.slice(0, 16) + '…' : '✗ ' + (h0.HookHash || 'none')}`);
  console.log(`  namespace     : ${effNs === NS ? '✓' : '✗ ' + (effNs || 'none')}`);
  console.log(`  params        : ${missing.length === 0 ? '✓ all 16 effective' : '✗ mismatch: ' + missing.join(', ')}`);
  console.log(`  other slots   : ${after.slice(1).filter((h) => h?.Hook?.HookHash).length} (untouched)`);
  console.log('\nNext steps:');
  console.log(`  1. The ISSUER (${E.ISSUER}) must clear NoRipple toward the pool, or every IOU leg fails tecPATH_DRY:`);
  console.log(`       TrustSet { Account: ISSUER, LimitAmount: { currency: "${curField}", issuer: "${pool}", value: "0" }, Flags: 0x00040000 }`);
  console.log(`  2. Bootstrap liquidity with ONE dual-leg Remit from the first LP: CMD=ADD, Amounts = [XAH, ${curField}]. The pool prices from that ratio.`);
  console.log(`  3. LPs need a trust line to the LP token ${String(E.LP_CUR).trim()}/${pool} before their first ADD.`);
  await c.disconnect();
})().catch((e) => { console.error('FATAL:', e?.message || e); process.exit(1); });
