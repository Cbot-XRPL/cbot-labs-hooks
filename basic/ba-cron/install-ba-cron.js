#!/usr/bin/env node
/*
 * Cbot Labs — BA-cron installer
 * ----------------------------------------------------------------------------
 * Installs the autonomous Balance-Reward auto-claim cron on YOUR Xahau account.
 *
 * Xahau pays accounts a "Balance Reward" (~4% APY) that you must claim with a
 * ClaimReward transaction, at most once every ~30 days. This installs a tiny
 * hook + a Cron schedule so your account claims it FOR you, forever, hands-off.
 *
 * It does three things (all signed by you, one account):
 *   1. AccountSet SetFlag 11  -> sets lsfTshCollect (lets a Cron tick run your hook)
 *   2. SetHook (slot)         -> installs the BA-cron hook (Flags: hsfCOLLECT)
 *   3. CronSet                -> schedules a tick every ~30 days (self-re-arming)
 *
 * The hook's HookOn fires on ONLY Cron(92) / SetHook(22) / Invoke(99) — it never
 * runs on Payments or Offers, so it cannot interfere with normal transfers, DEX
 * activity, or cross-chain bridges. Its only action is a ClaimReward crediting
 * YOUR OWN balance. It cannot move or redirect funds.
 *
 * Usage:
 *   SEED=sEd...  node install-ba-cron.js                 # DRY-RUN (nothing sent)
 *   SEED=sEd...  node install-ba-cron.js --apply         # install on MAINNET
 *   SEED=sEd...  node install-ba-cron.js --apply --testnet
 *   flags: --slot N  (force a hook slot; default = first free slot)
 *          --net wss://...  (custom node)
 *
 * Your secret is read from the SEED env var (or --seed) and is used only to sign
 * locally — it is never sent anywhere. Requires: npm install (see package.json).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* The reference codec ships without Xahau's CronSet transaction — teach it the
   type + its three UInt32 fields so we can encode/sign a CronSet. */
(function patchCodec(){
  const glob = (dir, acc = []) => { try { for (const e of fs.readdirSync(dir, { withFileTypes: true })){ const p = path.join(dir, e.name); if (e.isDirectory()) glob(p, acc); else if (e.name === 'definitions.json') acc.push(p); } } catch {} return acc; };
  for (const f of glob(path.join(__dirname, 'node_modules', '@transia', 'ripple-binary-codec'))){
    const d = JSON.parse(fs.readFileSync(f, 'utf8'));
    d.TRANSACTION_TYPES = d.TRANSACTION_TYPES || {};
    if (d.TRANSACTION_TYPES.CronSet !== 93) d.TRANSACTION_TYPES.CronSet = 93;
    const have = new Set((d.FIELDS || []).map((x) => x[0]));
    for (const [n, nth] of [['StartTime', 93], ['RepeatCount', 94], ['DelaySeconds', 95]])
      if (!have.has(n)) d.FIELDS.push([n, { nth, isVLEncoded: false, isSerialized: true, isSigningField: true, type: 'UInt32' }]);
    fs.writeFileSync(f, JSON.stringify(d));
  }
})();

const xrpl = require('@transia/xrpl');
const codec = require('@transia/ripple-binary-codec');
const kp = require('@transia/ripple-keypairs');

const arg = (f) => { const i = process.argv.indexOf(f); return i >= 0 ? process.argv[i + 1] : undefined; };
const APPLY = process.argv.includes('--apply');
const TESTNET = process.argv.includes('--testnet');
const SEED = String(process.env.SEED || arg('--seed') || '').trim();
const SLOT_ARG = arg('--slot') != null ? Number(arg('--slot')) : null;
const WS = arg('--net') || (TESTNET ? 'wss://xahau-test.net' : 'wss://xahau.org');
const HTTP = TESTNET ? 'https://xahau-test.net' : 'https://xahau.org';
const NETID = TESTNET ? 21338 : 21337;

// BA-cron hook constants (do not change).
const POKE_HOOK_ON = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7EFFFFFFFFFFFFFFFFFBFFFFF'; // fires on Cron(92)+SetHook(22)+Invoke(99) only
const NS = crypto.createHash('sha256').update('cron-claim-reward-poke').digest('hex').toUpperCase();
const WASM_PATH = path.join(__dirname, 'hook', 'cron-claim-reward-poke.wasm');
const EXPECT_HASH = '9F2B2E342FF4C65343980B7A9F78200B283D84732C1E80376A80A0E11628F7C6';
const CRON_DELAY = 2603580;  // ~30.13 days (>= the 30-day BA cooldown)
const CRON_REPEAT = 256;     // self-re-arms each tick; ~21 years of monthly claims
const MAX_FEE_DROPS = 50_000_000; // 50 XAH cap — a 1.3 KB SetHook is far cheaper; a spike means retry later

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function pollTx(c, h, ms = 60000){ const s = Date.now(); while (Date.now() - s < ms){ await sleep(2500); try { const t = await c.request({ command: 'tx', transaction: h }); if (t.result?.validated) return t.result; } catch {} } return null; }
async function curLedger(c){ return Number((await c.request({ command: 'ledger_current' })).result.ledger_current_index); }

/* Single-sig submit that also works for CronSet (the higher-level xrpl helpers
   reject the unknown type; we encode + sign the blob directly). */
async function submitBlob(c, tx, wallet){
  const t = JSON.parse(JSON.stringify(tx));
  t.SigningPubKey = wallet.publicKey;
  t.TxnSignature = kp.sign(codec.encodeForSigning(t), wallet.privateKey);
  const blob = codec.encode(t);
  const sub = await fetch(HTTP, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method: 'submit', params: [{ tx_blob: blob }] }) }).then((r) => r.json());
  return { eng: sub?.result?.engine_result, msg: sub?.result?.engine_result_message, hash: sub?.result?.tx_json?.hash };
}

(async () => {
  if (!SEED){ console.error('Set your account secret:  SEED=sEd... node install-ba-cron.js\n(Nothing is submitted without --apply. The seed is used only to sign locally.)'); process.exit(1); }
  const wallet = xrpl.Wallet.fromSeed(SEED);
  const wasm = fs.readFileSync(WASM_PATH);
  const wasmHash = crypto.createHash('sha512').update(wasm).digest('hex').slice(0, 64).toUpperCase();
  if (wasmHash !== EXPECT_HASH){ console.error(`hook wasm hash mismatch (${wasmHash} != ${EXPECT_HASH}) — refusing to install a modified hook.`); process.exit(1); }

  console.log('Cbot Labs — BA-cron installer');
  console.log(`  account : ${wallet.classicAddress}`);
  console.log(`  network : ${TESTNET ? 'TESTNET' : 'MAINNET'}  (${WS})`);
  console.log(`  hook    : ${wasmHash.slice(0, 16)}…  (${wasm.length} B)`);
  console.log(`  mode    : ${APPLY ? 'APPLY — will submit transactions' : 'DRY-RUN — nothing sent'}`);

  const c = new xrpl.Client(WS, { connectionTimeout: 30000 }); c.apiVersion = 1; await c.connect();
  const ai = (await c.request({ command: 'account_info', account: wallet.classicAddress, ledger_index: 'validated' }).catch(() => null))?.result?.account_data;
  if (!ai){ console.error('account not found / not activated on this network.'); await c.disconnect(); process.exit(1); }
  const hasCollect = !!(Number(ai.Flags) & 0x02000000);

  // Find the target slot: honor --slot, else first free slot (0..9).
  const hookObj = (await c.request({ command: 'account_objects', account: wallet.classicAddress, type: 'hook', ledger_index: 'validated' })).result.account_objects[0];
  const existing = hookObj?.Hooks || [];
  let slot = SLOT_ARG;
  if (slot == null){ slot = 0; while (slot < 10 && existing[slot]?.Hook?.HookHash) slot++; }
  const occupied = existing[slot]?.Hook?.HookHash;
  if (occupied && occupied !== wasmHash){ console.error(`\nslot ${slot} already holds hook ${occupied.slice(0, 10)}… — pick a free slot with --slot N (0..9), or --slot ${slot} to overwrite it.`); if (SLOT_ARG == null){ await c.disconnect(); process.exit(1); } }

  console.log(`\n  current : lsfTshCollect=${hasCollect}  Cron=${!!ai.Cron}  RewardTime=${ai.RewardTime || '(unprimed)'}  Balance=${(Number(ai.Balance) / 1e6).toFixed(2)} XAH`);
  console.log(`  target slot: ${slot}${occupied === wasmHash ? ' (re-install)' : ''}`);

  // 1) lsfTshCollect
  if (!hasCollect){
    let tx = await c.autofill({ TransactionType: 'AccountSet', Account: wallet.classicAddress, SetFlag: 11, NetworkID: NETID });
    tx.LastLedgerSequence = await curLedger(c) + 40;
    console.log(`\n[1] AccountSet SetFlag 11 (lsfTshCollect)   Fee ${(Number(tx.Fee) / 1e6).toFixed(4)} XAH`);
    if (APPLY){ const s = wallet.sign(tx); await c.request({ command: 'submit', tx_blob: s.tx_blob }); const r = await pollTx(c, s.hash); console.log(`    -> ${r?.meta?.TransactionResult}`); await sleep(3000); }
  } else console.log('\n[1] lsfTshCollect already set — skip');

  // 2) SetHook
  const entry = { Hook: { CreateCode: wasm.toString('hex').toUpperCase(), HookOn: POKE_HOOK_ON, HookNamespace: NS, HookApiVersion: 0, Flags: 5, HookParameters: [] } };
  const Hooks = []; for (let i = 0; i < slot; i++) Hooks.push({ Hook: {} }); Hooks.push(entry);
  let setTx = await c.autofill({ TransactionType: 'SetHook', Account: wallet.classicAddress, NetworkID: NETID, Hooks });
  if (Number(setTx.Fee) > MAX_FEE_DROPS){ console.error(`\nSetHook fee ${(Number(setTx.Fee) / 1e6).toFixed(2)} XAH > ${MAX_FEE_DROPS / 1e6} cap (open-ledger fee spike). Wait a few ledgers and retry.`); await c.disconnect(); process.exit(1); }
  setTx.LastLedgerSequence = await curLedger(c) + 40;
  console.log(`\n[2] SetHook slot ${slot} <- BA-cron (Flags 5 = hsfOVERRIDE|hsfCOLLECT)   Fee ${(Number(setTx.Fee) / 1e6).toFixed(4)} XAH`);
  if (APPLY){ const s = wallet.sign(setTx); await c.request({ command: 'submit', tx_blob: s.tx_blob }); const r = await pollTx(c, s.hash); console.log(`    -> ${r?.meta?.TransactionResult}`); await sleep(4000); }

  // 3) CronSet
  const seq = (await c.request({ command: 'account_info', account: wallet.classicAddress, ledger_index: 'validated' })).result.account_data.Sequence;
  const cronTx = { TransactionType: 'CronSet', Account: wallet.classicAddress, NetworkID: NETID, StartTime: 0, DelaySeconds: CRON_DELAY, RepeatCount: CRON_REPEAT, Fee: '200000', Sequence: seq, LastLedgerSequence: await curLedger(c) + 40 };
  console.log(`\n[3] CronSet StartTime=0 DelaySeconds=${CRON_DELAY} (~30d) RepeatCount=${CRON_REPEAT}   Fee 0.2 XAH`);
  if (APPLY){ const r = await submitBlob(c, cronTx, wallet); console.log(`    -> ${r.eng} ${r.hash || ''}`); await pollTx(c, r.hash); }

  if (!APPLY){ console.log('\nDRY-RUN complete — re-run with --apply to install.'); await c.disconnect(); return; }

  await sleep(4000);
  const ai2 = (await c.request({ command: 'account_info', account: wallet.classicAddress, ledger_index: 'validated' })).result.account_data;
  const hk = (await c.request({ command: 'account_objects', account: wallet.classicAddress, type: 'hook', ledger_index: 'validated' })).result.account_objects[0]?.Hooks?.[slot]?.Hook;
  console.log('\n=== result ===');
  console.log(`  lsfTshCollect : ${(Number(ai2.Flags) & 0x02000000) ? '✓' : '✗'}`);
  console.log(`  hook slot ${slot}  : ${hk?.HookHash === wasmHash && ((hk.Flags || 0) & 4) ? '✓ installed (hsfCOLLECT)' : '✗'}`);
  console.log(`  Cron schedule : ${ai2.Cron ? '✓ scheduled' : '✗ (public nodes can lag right after a CronSet — check again shortly)'}`);
  console.log('\nDone. Your account will now auto-claim its Balance Reward (~4%/yr) about every 30 days, hands-off.');
  console.log('The schedule re-arms itself on every tick. To stop it later: CronSet RepeatCount 0, and/or SetHook the slot empty.');
  await c.disconnect();
})().catch((e) => { console.error('FATAL:', e?.message || e); process.exit(1); });
