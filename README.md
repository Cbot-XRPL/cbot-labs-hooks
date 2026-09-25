# Cbot Labs Hooks

Public, self-contained hook releases for the **Xahau** network — organized by what
each hook is *for*. Everything here is a Xahau hook; the folders group them by
purpose, not by restating "it's a hook."

Each release is a complete package: hook source, compiled `.wasm`, a one-command
installer, and docs. Install on your own account — non-custodial, you sign
everything.

## Categories

| Folder | For |
|--------|-----|
| [`basic/`](basic/) | General-purpose account hooks — rewards, utilities. |
| [`defi/`](defi/) | DeFi building blocks — pools, staking, DAO/governance. |

## Releases

| Category | Hook | What it does | Status |
|----------|------|--------------|--------|
| basic | [**ba-cron**](basic/ba-cron/) | Auto-claims your Xahau **Balance Reward** (~4% APY) every ~30 days, forever, hands-off. | Live on mainnet |
| basic | [**uritoken-broker**](basic/uritoken-broker/) | Ephemeral **URIToken (NFT) broker**: buyer sends one XAH Payment, the hook buys the listed token, remits it to the buyer, routes the broker fee, auto-refunds a failed buy. Mirror of [xahau-uritoken-broker](https://github.com/Cbot-XRPL/xahau-uritoken-broker). | Live on mainnet |
| defi / pools | [**amm-v2**](defi/pools/amm-v2/) | **Constant-product AMM** (XAH ⇄ one IOU): LP shares as an IOU, swap fee in bps, optional DAO fee escrow, DEX offer mirroring. The exact build on the three onexah.io pools. | Live on mainnet (externally audited) |

More to come — this repo is where we publish them. Each release folder has its own README with the hook hash, what it can and cannot do, and the install walk-through.

## How these work

You run a small Node script from the release folder; it builds and submits the
transactions signed by **your** key (read locally from `SEED`, never transmitted).
Every installer has a dry-run mode that shows exactly what it will do before
anything is sent, and verifies the compiled binary's hash before running.

## Safety stance

- `basic/` hooks only ever act on **your own** account and cannot move your funds
  anywhere you didn't authorize; each release's README states precisely what it
  can and can't do.
- Sources and compiled binaries are both included.
- **Read the code, run the dry-run, verify the on-chain result.** `basic/` hooks are not audited; the AMM has been through an external audit (tracker private, fixes in source).
  Use at your own risk. Nothing here is financial advice.

## License

[MIT](LICENSE) © Cbot Labs
