# BA-cron — autonomous Balance-Reward auto-claim for Xahau

Xahau pays every account a **Balance Reward** (~4% APY on your XAH), but you have
to **claim it yourself** with a `ClaimReward` transaction, and only once every
~30 days. Miss it and the reward just keeps accruing unclaimed.

**BA-cron installs a tiny hook + a schedule on your own account so it claims the
reward *for* you — forever, hands-off.** No server, no bot, no custody. Once
installed it re-arms itself on every tick.

---

## What it installs

Three transactions, all signed by you, on one account:

| # | Transaction | Purpose |
|---|-------------|---------|
| 1 | `AccountSet` `SetFlag 11` | Sets `lsfTshCollect` so a scheduled Cron tick is allowed to run your hook. |
| 2 | `SetHook` (one slot, `Flags: hsfCOLLECT`) | Installs the BA-cron hook. |
| 3 | `CronSet` (`DelaySeconds ≈ 30d`, `RepeatCount 256`) | Schedules the recurring tick. Self-re-arms each time it fires. |

On each tick the hook emits a `ClaimReward`. **Xahau's reward is two-step:** the
`ClaimReward` resets your reward counter (and pays ~0 in that tx), then a
`GenesisMint` in the **next ledger** actually credits your reward. So after a tick
you'll see the reward land one ledger later.

## Is it safe?

Yes — by design, and it's easy to verify:

- **It cannot move or redirect your funds.** Its only action is a `ClaimReward`
  that credits **your own** balance. There is no path for it to send anywhere else.
- **It never runs on your Payments, swaps, or bridges.** The hook's `HookOn` fires
  on **only** `Cron(92)`, `SetHook(22)`, and `Invoke(99)`. The Payment (tt 0) and
  OfferCreate (tt 7) bits are *off*, so the hook is never even invoked on a normal
  transfer, a DEX trade, or a cross-chain teleport — it can't interfere with them.
- **It writes no hook state** and reads only your own account's reward timer.
- **It coexists** with other hooks on your account (installed at its own slot).
- **You stay in control** — you sign every transaction, and you can remove it
  anytime (see *Uninstall*).

## Install

Requirements: Node.js 18+.

```bash
npm install

# 1) Dry run — shows exactly what will happen, sends nothing:
SEED=sEd...your-account-secret...  node install-ba-cron.js

# 2) Install on mainnet:
SEED=sEd...your-account-secret...  node install-ba-cron.js --apply
```

Your secret is read from the `SEED` env var and used only to **sign locally** —
it is never transmitted. Nothing is submitted without `--apply`.

Flags:
- `--testnet` — run against `xahau-test.net` (NetworkID 21338).
- `--slot N` — force a specific hook slot (`0..9`). Default: the first free slot.
- `--net wss://…` — use a custom node.

The installer auto-detects an empty hook slot, checks fees (caps `SetHook` at 50
XAH so a fee spike can't surprise you), and prints a ✓/✗ summary at the end.

## Verify

After install:

```
lsfTshCollect : ✓
hook slot N   : ✓ installed (hsfCOLLECT)
Cron schedule : ✓ scheduled
```

You can also check on any explorer: your account should show a `Cron` object and
a hook whose hash is `9F2B2E34…`. About every 30 days you'll see a `Cron`
pseudo-transaction, a `ClaimReward`, then a `GenesisMint` crediting your reward.

## Uninstall / pause

- **Pause the schedule:** `CronSet` with `RepeatCount: 0`.
- **Remove the hook:** `SetHook` the slot back to empty (`{ "Hook": {} }`).
- (Optional) clear the flag: `AccountSet` `ClearFlag 11`.

## Hook details

| | |
|---|---|
| Hook hash | `9F2B2E342FF4C65343980B7A9F78200B283D84732C1E80376A80A0E11628F7C6` |
| Namespace | `sha256("cron-claim-reward-poke")` |
| `HookOn` | `FFFF…F7EFFFF…BFFFFF` → fires on Cron(92), SetHook(22), Invoke(99) only |
| Flags | `hsfCOLLECT` (4) — required for a Cron tick to run it |
| Size | 1,345 bytes |
| Source | [`hook/cron-claim-reward-poke.c`](hook/cron-claim-reward-poke.c) |
| Binary | [`hook/cron-claim-reward-poke.wasm`](hook/cron-claim-reward-poke.wasm) |

The included `.wasm` hashes to exactly the hash above; the installer refuses to
run if the binary has been altered.

### The "poke" backup

Because `HookOn` also includes `Invoke(99)`, anyone can *nudge* a claim by sending
your account an `Invoke` — useful if you ever fully blackhole the account and the
Cron stalls. It's spam-proof: an Invoke inside the 30-day cooldown is a no-op, and
it can still only claim to your own balance.

---

## Disclaimer

Provided as-is, MIT-licensed, **not audited**. You install it on your own account,
at your own risk. Verify the source and the on-chain result yourself. This is not
financial advice.

— [Cbot Labs](../../README.md)
