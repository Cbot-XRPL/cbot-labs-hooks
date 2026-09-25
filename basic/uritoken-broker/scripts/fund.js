/* TOP UP the broker's working XAH with a native-XAH Remit.
 *
 * Why not a plain Payment: the broker hook inspects every incoming Payment and rolls back any that lacks the
 * NFTID + BUY params ("missing NFTID tx param"), so a normal transfer can never land. The hook ACCEPTS every
 * non-Payment transaction, so a Remit carrying XAH goes straight through.
 *
 * Config (env):
 *   BROKER        — the broker r-address (the DESTINATION; no broker seed is needed here)
 *   FUND_SEED     — family seed of the wallet that pays (any plain wallet you control; never a user-funds wallet)
 *   AMOUNT        — XAH to send (default 50; capped at 1000)
 *
 *   BROKER=r... FUND_SEED=s... AMOUNT=100 node scripts/fund.js --network mainnet          # DRY RUN
 *   BROKER=r... FUND_SEED=s... AMOUNT=100 node scripts/fund.js --network mainnet --apply
 */
const xrpl = require("@transia/xrpl");
const APPLY = process.argv.includes("--apply");
const NET = (process.argv.includes("--network") ? process.argv[process.argv.indexOf("--network") + 1] : "mainnet").toLowerCase();
const NETS = { mainnet: { ws: "wss://xahau.org", id: 21337 }, testnet: { ws: "wss://xahau-test.net", id: 21338 } };
if (!NETS[NET]) { console.error("--network must be mainnet | testnet"); process.exit(1); }
const { ws: WS, id: NETID } = NETS[NET];
const BROKER = (process.env.BROKER || "").trim();
const AMOUNT = Number(process.env.AMOUNT || 50);
const FEE_CAP = 1_000_000;   // 1 XAH
const KEEP = 20;             // source keeps this much XAH above its reserve
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function pollTx(c, h, lls) { const s = Date.now(); while (Date.now() - s < 180000) { await sleep(2500); try { const t = await c.request({ command: "tx", transaction: h }); if (t.result?.validated) return t.result.meta?.TransactionResult; } catch {} try { const cur = Number((await c.request({ command: "ledger_current" })).result.ledger_current_index); if (cur > lls + 8) return "EXPIRED"; } catch {} } return "TIMEOUT"; }
const bal = async (c, a) => Number((await c.request({ command: "account_info", account: a, ledger_index: "validated" })).result.account_data.Balance) / 1e6;

(async () => {
  if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(BROKER)) { console.error("set BROKER to the broker r-address"); process.exit(1); }
  if (!process.env.FUND_SEED) { console.error("set FUND_SEED to the paying wallet's seed"); process.exit(1); }
  if (!(AMOUNT > 0 && AMOUNT <= 1000)) { console.error("AMOUNT must be 0 < n <= 1000 XAH"); process.exit(1); }
  const w = xrpl.Wallet.fromSeed(process.env.FUND_SEED.trim());
  const SOURCE = w.classicAddress;
  if (SOURCE === BROKER) { console.error("FUND_SEED is the broker itself"); process.exit(1); }
  console.log(`\n── fund broker (${NET}) ──\nsource : ${SOURCE}\nbroker : ${BROKER}\namount : ${AMOUNT} XAH via Remit`);

  const c = new xrpl.Client(WS); c.apiVersion = 1; await c.connect();
  try {
    const bi = (await c.request({ command: "account_info", account: BROKER, ledger_index: "validated" })).result.account_data;
    if (bi.Flags & 0x80000000) throw new Error("broker has DisallowIncomingRemit set — Remit would fail");
    const si = (await c.request({ command: "account_info", account: SOURCE, ledger_index: "validated" })).result.account_data;
    const srv = (await c.request({ command: "server_info" })).result.info.validated_ledger;
    const reserve = Number(srv.reserve_base_xrp) + Number(srv.reserve_inc_xrp) * Number(si.OwnerCount || 0);
    const srcBal = Number(si.Balance) / 1e6, before = Number(bi.Balance) / 1e6;
    console.log(`broker balance before : ${before} XAH\nsource balance        : ${srcBal} XAH (reserve ${reserve})`);
    if (srcBal - AMOUNT < reserve + KEEP) throw new Error(`source would drop below reserve + ${KEEP} XAH — ABORT`);

    const tx = { TransactionType: "Remit", Account: SOURCE, Destination: BROKER, NetworkID: NETID,
      Amounts: [{ AmountEntry: { Amount: String(Math.round(AMOUNT * 1e6)) } }] };
    const pf = await c.autofill(tx, 0); const fee = Number(pf.Fee || 0);
    if (!fee) throw new Error("autofill gave no fee");
    if (fee > FEE_CAP) throw new Error(`fee ${fee / 1e6} XAH exceeds cap ${FEE_CAP / 1e6}`);
    console.log(`fee                   : ${(fee / 1e6).toFixed(6)} XAH`);
    if (!APPLY) { console.log("\n--- DRY RUN. Re-run with --apply to sign + submit. ---"); return; }

    const s = w.sign(pf);
    const lls = Number((await c.request({ command: "ledger_current" })).result.ledger_current_index);
    await c.submit(s.tx_blob);
    console.log(`submitted ${s.hash} — polling…`);
    const res = await pollTx(c, s.hash, lls);
    console.log(`result: ${res}`);
    if (res !== "tesSUCCESS") { process.exitCode = 1; return; }
    await sleep(3000);
    const after = await bal(c, BROKER);
    console.log(`broker balance after  : ${after} XAH  ${Math.abs(after - (before + AMOUNT)) < 1e-6 ? "✓ MATCH" : "✗ MISMATCH"}`);
  } finally { try { await c.disconnect(); } catch {} }
})().catch((e) => { console.error("FAIL", e.message || e); process.exit(1); });
