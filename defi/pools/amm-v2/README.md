# AMM v2 — constant-product pool hook (XAH ⇄ one IOU)

A single-account **automated market maker** for Xahau: native **XAH** on one side, **one IOU**
(currency + issuer chosen at install) on the other, priced on the constant-product curve
`x · y = k`. Liquidity providers receive an LP IOU issued by the pool account; swap fees accrue
to the pool; an optional slice of every fee can be escrowed for a DAO / treasury wallet.

This is the exact build running the three onexah.io pools on mainnet (XAH/EVR, XAH/XXX,
XAH/RVN) with real funds. Source and compiled binary are both here; the binary's hash is
verifiable against those live accounts.

| | |
|---|---|
| Hook hash | `B549537D6B7F38F94418C510C625315232DE5F527D8B2585BAED423243CF49A2` |
| Binary | [`hook/amm-v2-remitadd.wasm`](hook/amm-v2-remitadd.wasm) — 56,579 bytes |
| Source | [`hook/amm-v2-remitadd.c`](hook/amm-v2-remitadd.c) |
| Namespace | `sha256("amm-v2-hook")` = `6691371A…` |
| `HookOn` | `…F77F…BFFFFE` → fires on `Payment` (0) and `Invoke` (99) |
| Live on | `rAMMznwkgL1BB6o4eYWufMAdy6t1LPgnf` (XAH/EVR) · `rLPXFdgvriFHXt7WYybqJSu49Ff5DRzq1u` (XAH/XXX) · `rRLPRi86xXjq8QmuvcpUfN6dg3etmCNHT` (XAH/RVN) |

---

## What it does

| Command | Trigger | Effect |
|---|---|---|
| **ADD** (1-sign) | one `Remit` carrying both the XAH leg and the IOU leg | mints LP shares pro-rata in a single transaction |
| **ADD** (2-step) | a `Payment` of one side, then a `Payment` of the other | first leg is **stashed** per-LP; shares mint when the pair completes |
| **SWAP** | `Payment` of XAH or the IOU with `CMD=SWAP` (+ optional `MINOUT`) | constant-product swap the other way, fee in bps, slippage floor enforced |
| **REM** | tiny XAH `Payment` with `CMD=REM` + `SHARES` (u64 micro-units of LP token) | burns that many of the sender's shares and emits both sides back pro-rata (the dust joins the XAH reserve) |
| **DAOCLAIM** | `Invoke` `CMD=DAOCLAIM` | pays out the escrowed DAO fee slice (auto-flushes above `DAO_MIN`) |
| passive inflow | any XAH/IOU that arrives without a command | **reconciled** into reserves as yield for LPs (never lost, never refunded) |

After every command the pool re-posts a small **bid/ask offer pair on the DEX** (1% of reserves,
600 s expiry) so ordinary path-finding payments can route through it too.

### Where the money sits

Reserves live in the pool account's own XAH balance and IOU trust line; the hook's state only
records the bookkeeping (reserves as it knows them, total shares, fee and DAO accumulators, and
each LP's share/stash records). The hook never sends anything except in response to a command
from the LP or trader that owns the value being moved.

## Security properties

- **Partial payments rejected.** `tfPartialPayment` on any swap or add leg is refused, so a
  payment can never claim to deliver more than it did.
- **Receivability pre-check.** Before a payout is emitted the hook confirms the recipient can
  actually receive it (trust line exists and isn't frozen); otherwise the command fails closed
  and nothing is debited.
- **Callback delivery truth.** The callback reads the emitted transaction's real result: a
  payout that applied as a `tec` is treated as *not delivered* and the LP-share mint it belonged
  to is reverted, so a failed leg can't strand value on either side.
- **Per-user and per-pool caps** (`MAX_RXAH`/`MAX_RIOU`/`MAX_TOTX`/`MAX_TOTY`) — set to `0` for
  no cap. The live pools run uncapped.
- **No hardcoded accounts.** Issuer, DAO destination, admin — everything is an install
  parameter.
- **Admin surface is `CFGUPDATE` / `CFGRESET` / `DBPSUPD` only** (fee, caps and DAO-cut tuning via a
  runtime-override slot), gated to `ADMIN`; the admin
  cannot withdraw reserves.

## Install parameters

Sixteen parameters (the Xahau maximum). Values are hex. Names are ASCII.

| Param | Type | Meaning |
|---|---|---|
| `CUR` | 20-byte currency | the IOU currency code (`toCurrencyHex`) |
| `ISSUER` | 20-byte account id | the IOU issuer |
| `AMM_LP_CUR` | 20-byte currency | currency code of the LP token the pool will issue |
| `FEEBPS` | u32 | swap fee in basis points (in-hook cap 1000 = 10%) |
| `MINXAH` / `MINIOU` | u64 | minimum XAH drops / IOU micro-units per swap or add |
| `DAO_BPS` | u32 | slice of each fee escrowed for the DAO wallet (0 = none) |
| `DAO_DEST` | 20-byte account id | DAO / treasury wallet |
| `DAO_MIN` | u64 drops | auto-flush threshold for the escrow (0 = manual `DAOCLAIM` only) |
| `ADMIN` | 20-byte account id | may send `CFGUPDATE` / `CFGRESET` / `DBPSUPD` |
| `MAX_RXAH` / `MAX_RIOU` | u64 | per-LP position cap per side (0 = uncapped) |
| `MAX_TOTX` / `MAX_TOTY` | u64 | pool-wide reserve cap per side (0 = uncapped) |
| `CORENS` | 32 bytes | namespace of a DAO core hook the pool may read for governed settings; zeros if you have none |
| `FEECCY` | u32 | `0` = the DAO cut on IOU→XAH sells is booked in the IOU; `1` = converted on the curve and booked in XAH |

`FEECCY` only changes the *currency* the DAO's cut is kept in. The trader's output and the
LPs' fee share are identical in both modes.

## Install

```bash
npm install
# dry run — prints the full plan, checks the binary hash, signs nothing
POOL_SEED=s... CUR=EVR ISSUER=r... LP_CUR=ELP FEEBPS=30 ADMIN=r... DAO_DEST=r... node install-amm.js --network testnet
# apply
POOL_SEED=s... CUR=EVR ISSUER=r... LP_CUR=ELP FEEBPS=30 ADMIN=r... DAO_DEST=r... node install-amm.js --network testnet --apply
```

The pool must be a **fresh, dedicated account** (the installer refuses an account that already
carries a hook). Fund it with enough XAH for the owner reserve plus the offers it posts (a
few XAH). Then:

1. **The issuer must clear NoRipple toward the pool.** The issuer sends a `TrustSet` to the pool
   for the IOU with `tfClearNoRipple`; without it every IOU leg fails `tecPATH_DRY` even though
   the hook accepted it. Same for any LP whose issuer line carries NoRipple.
2. **Bootstrap liquidity** with one dual-leg `Remit` (`CMD=ADD`, both amounts) from the first
   LP. The pool prices from that ratio.

## Operating notes (learned on mainnet)

- **Re-installing the hook must resend the per-account parameters.** A `SetHook` that replaces
  slot 0 without the full parameter set leaves the pool "not initialized" — always pass every
  parameter again (this installer's `--upgrade` does).
- **Hook fee quotes spike.** A `SetHook` quote can jump from ~50 XAH to thousands for a few
  seconds when the open ledger is busy; the installer refuses above its cap — just re-run.
- The DEX offers the pool posts cost owner reserve (~2 XAH per open offer); budget ~25 XAH.
- Stored reserves are the hook's bookkeeping; the account balance can sit slightly above them
  (offer fills, passive inflow) until the next command reconciles. Judge pool health by
  `sqrt(rx·ry) / totalShares` rising, not by raw balance.

## Verify

```bash
node -e "const c=require('crypto'),fs=require('fs');console.log(c.createHash('sha512').update(fs.readFileSync('hook/amm-v2-remitadd.wasm')).digest('hex').slice(0,64).toUpperCase())"
# → B549537D6B7F38F94418C510C625315232DE5F527D8B2585BAED423243CF49A2
# then compare with slot 0 of any of the three live pools (ledger_entry hook / account_objects type=hook)
```

The `.c` reproduces this hash byte-for-byte on the public Xahau buildbox
(`@transia/hooks-toolkit-cli compile-c`).

## Lineage

`07E5CA83` → `858715147E` → `6CF9DFE8` (partial-payment guard) → `F8B02C71` (1-sign dual-Remit ADD)
→ `414ECD6B` / `DF31BED9` (external-audit fixes, callback delivery truth, receivability pre-check)
→ `E8400EF2` → `C71EBD01` (`FEECCY`) → `E000F5F0` (u64-overflow guard on the FEECCY conversion)
→ **`B549537D`** (2026-09-26, live on all three pools). The last step fixes a pricing bug found in
external review: on Xahau the hook sees the pool's XAH balance *including* the transaction's
inbound XAH, but the IOU trust line *not yet* including the inbound IOU. The reconcile prelude
assumed both were included, so it settled the IOU reserve to `actual − in` before pricing and every
IOU→XAH swap paid out about `in / reserve` too much XAH (and ADDs minted against the same
understated reserve). The reconcile no longer treats the inbound IOU as already on the line.
If you fork this: never assume the hook's ledger view includes the current transaction's IOU
delivery; measure it per transaction type on testnet.
The hook has been through an external code audit; the audit tracker is private, the resulting
fixes are all in this source.

## Safety stance

Non-custodial: the pool account holds the reserves and only its hook moves them, in response to
commands from the party whose value is moving. Read the code, run the dry-run, verify the hash
on chain. Not financial advice; use at your own risk.
