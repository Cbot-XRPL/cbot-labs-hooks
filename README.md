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
| [`defi/`](defi/) | DeFi building blocks — pools, staking, DAO/governance. *(coming)* |

## Releases

| Category | Hook | What it does | Status |
|----------|------|--------------|--------|
| basic | [**ba-cron**](basic/ba-cron/) | Auto-claims your Xahau **Balance Reward** (~4% APY) every ~30 days, forever, hands-off. | Live on mainnet |

More to come — this repo is where we publish them.

## How these work

You run a small Node script from the release folder; it builds and submits the
transactions signed by **your** key (read locally from `SEED`, never transmitted).
Every installer has a dry-run mode that shows exactly what it will do before
anything is sent, and verifies the compiled binary's hash before running.

## Safety stance

- Hooks here only ever act on **your own** account and cannot move your funds
  anywhere you didn't authorize; each release's README states precisely what it
  can and can't do.
- Sources and compiled binaries are both included.
- **Not audited.** Read the code, run the dry-run, verify the on-chain result.
  Use at your own risk. Nothing here is financial advice.

## License

[MIT](LICENSE) © Cbot Labs
