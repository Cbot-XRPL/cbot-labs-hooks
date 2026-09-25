# DeFi hooks

DeFi building-block hooks for Xahau, grouped by role:

| Folder | For | Published |
|--------|-----|-----------|
| [`pools/`](pools/) | AMM / liquidity-pool hooks | [**amm-v2**](pools/amm-v2/) — constant-product XAH ⇄ IOU pool, the build live on the onexah.io pools |
| `staking/` | staking + reward-distribution hooks | *(coming)* |
| `dao/` | governance, voting, and treasury hooks | *(coming)* |

DeFi hooks hold **other people's funds** by definition (a pool's reserves are its LPs'),
so read each release's *Security properties* and *Operating notes* before installing one,
and run it on testnet first. The AMM release here has been through an external code
audit; the audit tracker itself is private, the resulting fixes are in the source.
