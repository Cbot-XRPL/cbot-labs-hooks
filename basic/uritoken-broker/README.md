# Xahau URIToken Broker Hook

> **Release snapshot.** The development home of this hook is the dedicated repo
> [Cbot-XRPL/xahau-uritoken-broker](https://github.com/Cbot-XRPL/xahau-uritoken-broker)
> (v3.0.0, hook hash `9D39BF3D`). This folder mirrors that repo verbatim — source, prebuilt
> `build/broker.wasm`, and the build / install / fund scripts — so it can be installed from
> here like every other Cbot Labs release. Fixes land there first.

An **ephemeral broker hook** for URIToken (NFT) marketplace sales on [Xahau](https://xahau.network).

A buyer sends a single native-XAH `Payment` to the broker account carrying the token id and their max
acceptable ask. The hook does the rest on-chain — it buys the listed URIToken, delivers it to the buyer, and
routes a broker fee to a configured wallet. No custody, no escrow account, no off-chain keeper: the broker
account only ever holds the token for the moment between buying it and remitting it.

## How it works

Trigger: an incoming **native-XAH `Payment`** to the broker account with these transaction parameters:

| Param  | Type              | Meaning                                    |
|--------|-------------------|--------------------------------------------|
| `NFTID`| 32-byte URITokenID| the token the buyer wants                  |
| `BUY`  | 8-byte uint64     | max live ask (drops) the buyer will accept |

Runtime flow:

1. Read the live URIToken object for `NFTID`.
2. Require a native-XAH open sell offer, and require the payment to equal **live ask + broker fee** exactly.
3. Emit `URITokenBuy` from the broker account.
4. On callback success, emit `Remit` to send the bought token to the buyer.
5. On callback success, emit `Payment` of the net broker fee to the fee wallet.
6. On buy failure, emit a refund `Payment` back to the buyer.

### Known limitation (read this)

Emitted transactions settle on later ledgers, so the hook can fully auto-refund a **failed buy**, but it cannot
guarantee a perfect atomic rollback if a later remit/fee leg fails **after** a successful buy. It preflights the
known receipt blockers aggressively to make remit failure rare, and preserves stuck callback state under the
broker account for operator recovery. Treat the broker as an intermediary you monitor, not a trustless vault.

## Install parameters

Set when the hook is installed (see `scripts/install.js`). **Always send the full set** - the first install of a
given wasm hash stores its parameters on the hook *definition* as defaults, and later installs of the same hash
inherit whatever they leave out.

| Param    | Type          | Meaning                                                                                  |
|----------|---------------|------------------------------------------------------------------------------------------|
| `FEEDEST`| ascii r-addr  | wallet that receives the broker fee (required)                                           |
| `FEEBPS` | uint32        | fee in basis points, `0..10000` (e.g. `250` = 2.5%)                                      |
| `RSVINC` | uint32 drops  | **v2** - the ledger's owner-reserve increment (mainnet + testnet: `200000` = 0.2 XAH). See below. |
| `FEEMIN` | uint64 drops  | **v2** - optional minimum fee per sale; `0` = off. Fee = `max(ask * FEEBPS / 10000, FEEMIN)`. |
| `MEMO`   | 2..64 ascii   | **v3** - optional memo stamped on the emitted `URITokenBuy` and `Remit` (see below). `-` = off. |

## Memo on the brokered legs (v3)

With `MEMO` set, the hook appends a `Memos` field to the two transactions your counterparties actually see: the
emitted `URITokenBuy` (the seller's wallet shows the broker buying their token) and the `Remit` that delivers the
token (the buyer's wallet shows it arriving). Both carry one memo: `MemoData` = your text, `MemoFormat` =
`text/plain`. The fee payout and any refund carry no memo.

```bash
MEMO="NFT brokered by My Marketplace" FEEDEST=r... BROKER_SEED=s... node scripts/install.js --network mainnet --apply
```

Leave `MEMO` unset (the installer sends `-`) for no memo. It is sent explicitly on purpose: the first install of a
given wasm hash on a network stores its parameters as the hook *definition's* defaults, so a later install that
omitted `MEMO` would inherit whatever the first installer chose. The reference deployment uses
`NFT brokered by Xahau Vault`.

## Fee accounting (v2) - why `RSVINC` exists

When the hook `Remit`s the bought token to the buyer, Xahau makes the **sender** (the broker) transfer the
buyer's owner-reserve increment for the new URIToken object - 0.2 XAH on mainnet - along with the token. v1 only
netted the three emitted-transaction fees out of the fee payout, so **every sale silently cost the broker 0.2 XAH**
(a reference deployment lost ~100 XAH over ~500 sales before this was caught).

v2 counts `RSVINC` as a chain cost at the remit step, so:

```
payout to FEEDEST = gross fee - URITokenBuy fee - Remit fee - RSVINC - payout tx fee
```

and the broker ends every sale at **exactly** the balance it started with. If the gross fee is smaller than those
costs (tiny asks), no payout is emitted and the broker absorbs the difference - at 2.5% that happens below an ask
of roughly 12 XAH. Set `FEEMIN` to stop subsidising tiny sales; your buy-tx builder must then use the same floor,
because the hook rejects any payment that is not exactly `ask + fee`.

The installer checks `RSVINC` against the live ledger's `reserve_inc` and refuses a mismatch. If the network ever
changes its reserve, re-install with the new value.

## Topping up the broker

The hook rolls back every incoming `Payment` that lacks `NFTID` + `BUY`, so a plain transfer to the broker
**fails**. It accepts any non-Payment transaction, so fund it with a native-XAH **`Remit`**:

```bash
BROKER=rYourBroker... FUND_SEED=s... AMOUNT=100 node scripts/fund.js --network mainnet          # dry run
BROKER=rYourBroker... FUND_SEED=s... AMOUNT=100 node scripts/fund.js --network mainnet --apply
```

The broker needs working XAH for the emitted `URITokenBuy` / `Remit` / fee legs and the reserve transfer; the
hook rejects a sale up front if the broker cannot cover the ask, all three fees and `RSVINC`.

## Build

The hook compiles on the public Xahau **buildbox** — no local C toolchain, Docker, or `hookapi.h` needed
(the buildbox supplies the header server-side; the source only includes `hookapi.h` + `<stdint.h>`).

```bash
npm install        # pulls @transia/hooks-toolkit-cli
npm run build      # src/broker.c -> build/broker.wasm, prints the HookHash
```

Override the buildbox with `HOOKS_COMPILE_HOST` if you run your own. A prebuilt `build/broker.wasm` is
included so you can install without building.

## Deploy

The broker must be a **fresh, dedicated account** — it briefly holds sold tokens, so don't reuse a funded wallet.

1. Generate a new Xahau account and fund it with ~5 XAH.
2. Provide its seed via `BROKER_SEED` (env) or `config/broker.json` (`{"seed":"s..."}` — gitignored).
3. Set `FEEDEST` (fee wallet) and optionally `FEEBPS` (default 250).

```bash
# dry run — prints the plan, signs nothing
FEEDEST=rYourFeeWallet... BROKER_SEED=s... node scripts/install.js --network mainnet

# apply — signs the SetHook from the broker account and submits
FEEDEST=rYourFeeWallet... BROKER_SEED=s... node scripts/install.js --network mainnet --apply
```

`--network testnet` targets Xahau testnet. The installer refuses to run if the broker already carries a hook
(it expects a clean account) and caps the SetHook fee at 20 XAH. SetHook fee quotes can spike transiently under
load (a 500x quote was seen once, normal a minute later) - the cap catches it; just re-run.

### Upgrading a live broker (e.g. v2 -> v3)

```bash
FEEDEST=r... BROKER_SEED=s... node scripts/install.js --network mainnet --upgrade          # dry run
FEEDEST=r... BROKER_SEED=s... node scripts/install.js --network mainnet --upgrade --apply
```

`--upgrade` replaces the hook in place (same slot, same namespace, `hsfOVERRIDE`, no namespace delete) so any
pending-sale state survives, but it **refuses while a pending sale record exists** in the namespace - wait for the
in-flight sale to finish and re-run. Use the same `NAMESPACE` label as the original install.

### Keep the seed off any server

Run the installer **locally**. A public API/marketplace server never needs the broker seed — the hook signs its
own emitted transactions on-chain; the server only builds the buyer's unsigned `Payment` and reads chain state.
Keep `BROKER_SEED` / `config/broker.json` out of git (already in `.gitignore`).

## Layout

```
src/broker.c        the hook source (C)
build/broker.wasm   prebuilt binary (rebuild with `npm run build`)
scripts/build.js    compile via the Xahau buildbox
scripts/install.js  install on a dedicated broker account (mainnet/testnet); --upgrade replaces a live hook
scripts/fund.js     top up the broker's working XAH by Remit (plain Payments are rejected by the hook)
```

## Versions

| Version | HookHash (sha512half) | Size | Notes |
|---|---|---|---|
| **v3** (current) | `9D39BF3DF8A48960B73D00FA8D08246C6A53866B4C04BD0E3519264158C92CE0` | 15,765 B | + `MEMO` install param: text/plain Memo on the emitted `URITokenBuy` and `Remit` (not on the fee payout). Fee accounting unchanged from v2. |
| v2 | `EF0C87237993204F414122828C308F4C332B158973C1108D99C3C0645E37C917` | 15,042 B | `RSVINC` netted out of the payout (zero balance drift per sale), optional `FEEMIN` floor. Testnet-proven 30/30 (normal sale, sub-cost sale, floor reject + accept, namespace clean). Live on the reference deployment 2026-09-20. |
| v1 | `2E418F951A9202B4E8EB589D605873A14514121455CF7090F697D42E1EE5D8D4` | 14,390 B | Original port. Bleeds 0.2 XAH per sale (remit reserve not recouped). |

The prebuilt `build/broker.wasm` is v3; `npm run build` reproduces the same hash from `src/broker.c` on the
buildbox. Verify: `node -e "const c=require('crypto'),fs=require('fs');console.log(c.createHash('sha512').update(fs.readFileSync('build/broker.wasm')).digest('hex').slice(0,64).toUpperCase())"`.

## Provenance

Derived from the "Ephemeral Broker Hook" reference in the Xahau hooks toolkit example set. A reference
deployment runs on Xahau mainnet as the marketplace broker for the Odin's Eyes raven-license NFT
(`rBkEp8W1yhBGLrvHFKKyrmSvniMFVJbPPg`, v3 `9D39BF3D`).

## License

MIT
