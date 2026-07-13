# Cbot Labs Hooks

Public, self-contained hook releases for the **Xahau** network. Each folder is a
complete, ready-to-run package: the hook source, the compiled `.wasm`, a
one-command installer, and docs. Install on your own account — non-custodial, you
sign everything.

## Releases

| Hook | What it does | Status |
|------|--------------|--------|
| [**ba-cron**](ba-cron/) | Auto-claims your Xahau **Balance Reward** (~4% APY) every ~30 days, forever, hands-off. | Live on mainnet |

More to come — this repo is where we publish them.

## How these work

Every release does the same three-step thing where relevant:

1. sets any account flag the hook needs (e.g. `lsfTshCollect`),
2. `SetHook`s the hook to one of your account's slots,
3. schedules or wires whatever makes it run.

You run a small Node script; it builds and submits the transactions signed by
**your** key (read locally from `SEED`, never transmitted). Every installer has a
dry-run mode that shows exactly what it will do before anything is sent.

## Safety stance

- Hooks here only ever act on **your own** account and cannot move your funds
  anywhere you didn't authorize; each release's README states precisely what it
  can and can't do.
- Sources and compiled binaries are both included, and installers verify the
  binary hash before running.
- **Not audited.** Read the code, run the dry-run, verify the on-chain result.
  Use at your own risk. Nothing here is financial advice.

## License

[MIT](LICENSE) © Cbot Labs
