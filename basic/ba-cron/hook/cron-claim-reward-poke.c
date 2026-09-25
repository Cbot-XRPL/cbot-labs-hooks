#include "hookapi.h"
#include <stdint.h>

/*
 * BA-cron + spam-proof external poke
 * ==================================
 *
 * Reconstruction of our chain-extracted BA-cron (hash 6442A7F7…, which had
 * NO source) PLUS a spam-proof external poke, so an account can be fully
 * blackholed and still never strand its Balance Adjustment (BA) reward.
 *
 * WHAT THE ORIGINAL DID (recovered by disassembling the 1074-byte wasm —
 * imports: hook_account, ledger_seq, etxn_reserve, etxn_details,
 * etxn_fee_base, emit, accept, rollback, _g):
 *   on every fire it reserved one emit, filled a hardcoded ClaimReward
 *   template's Account with hook_account, set the fee + EmitDetails, emitted
 *   the ClaimReward, and accepted. It did NOT check the trigger type or
 *   eligibility — it just emitted and let the chain reject during the 30-day
 *   cooldown. Its HookOn fired only on Cron (tt 92) + SetHook (tt 22), so
 *   there was no way to nudge it from outside.
 *
 * WHAT THIS ADDS:
 *   1. Installed with HookOn ALSO firing on ttINVOKE (tt 99) so ANYONE can
 *      send a zero-value Invoke to nudge a claim — works even when the
 *      account is fully blackholed (incoming txns still fire hooks).
 *   2. A FAIL-OPEN eligibility gate: read the hook account's own RewardTime
 *      from its AccountRoot; if RewardTime is present AND we're still inside
 *      the 30-day cooldown, accept with NO emit (a poke during cooldown is a
 *      cheap no-op, so spamming Invokes can't drain the account via repeated
 *      failed-emit fees). If RewardTime is absent (never primed) or the read
 *      fails for any reason, we FALL THROUGH to emit — so a read bug can
 *      never *block* a legitimate claim; worst case is one wasted emit the
 *      chain rejects (the original's behavior).
 *   3. Value-safety is inherent: ClaimReward credits BA to the account's OWN
 *      balance — a poke can never redirect funds.
 *
 * The ClaimReward template below is the EXACT byte layout extracted from the
 * working mainnet wasm's data section, including the hardcoded reward Issuer
 * (B5F762798A53D543A014CAF8B297CFF8F2F937E8).
 *
 * STATUS: authored from the disassembly + our hook API; NOT yet compiled or
 * testnet-verified. Build via research/hooks/vpra-hooks (`npm run build`),
 * then testnet-prove (prime -> cooldown bounce -> eligible emit -> poke) per
 * the Xahau hook debug playbook BEFORE any mainnet SetHook.
 */

/* RewardTime: UInt32, nth 98 -> field id (type 2 << 16) | 98. Define if the
   SDK header doesn't already expose it. */
#ifndef sfRewardTime
#define sfRewardTime ((2U << 16U) + 98U)
#endif

/* ttHOOK_SET (SetHook = 22) — define defensively if the header set doesn't. */
#ifndef ttHOOK_SET
#define ttHOOK_SET 22
#endif

/* 30-day BA claim cooldown, in seconds (matches server/lib/ba-status.js). */
#define BA_COOLDOWN_SECONDS 2592000ULL

/* ClaimReward emit template (251 bytes) — extracted verbatim from the chain
   wasm. Offsets we fill at runtime:
     [15] FirstLedgerSequence (u32 BE)   [21] LastLedgerSequence (u32 BE)
     [26] Fee (u64 BE, native)           [71] Account (20 bytes)
   Static in the template: TransactionType=98, Flags=0, Issuer (20B @93).
   The 138-byte tail @113 is written by etxn_details (sfEmitDetails). */
#define CR_SIZE      251U
#define CR_FLS_OUT    15U
#define CR_LLS_OUT    21U
#define CR_FEE_OUT    26U
#define CR_ACCT_OUT   71U
#define CR_EMIT_OUT  113U
#define CR_EMIT_LEN  138U

/* ClaimReward emit template at FILE SCOPE (global), mirroring protocol-x-core's
   px_remit_tx. A large aggregate initializer MUST live at module scope: as a
   *local* it lowers to a memcpy() import that Xahau's HookSet rejects ("Hook
   attempted to import a function that does not appear in the hook_api function
   set: memcpy"). As a global it becomes a wasm data segment, re-initialized
   fresh each invocation (hooks are stateless / re-instantiated per call) — so
   it's still "fresh, no shared state"; we just fill Account/FLS/LLS/Fee/
   EmitDetails at runtime. */
static uint8_t txn[CR_SIZE] = {
    0x12,0x00,0x62,                                  /* TransactionType = ClaimReward (98) */
    0x22,0x00,0x00,0x00,0x00,                        /* Flags = 0 */
    0x24,0x00,0x00,0x00,0x00,                        /* Sequence (emit fills) */
    0x20,0x1A,0x00,0x00,0x00,0x00,                   /* FirstLedgerSequence (we fill) */
    0x20,0x1B,0x00,0x00,0x00,0x00,                   /* LastLedgerSequence (we fill) */
    0x68,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    /* Fee (we fill; 0x40.. = native) */
    0x73,0x21,                                       /* SigningPubKey (33B, emit fills) */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,
    0x81,0x14,                                       /* Account (20B, we fill) */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,
    0x84,0x14,                                       /* Issuer (reward issuer, hardcoded) */
    0xB5,0xF7,0x62,0x79,0x8A,0x53,0xD5,0x43,0xA0,0x14,
    0xCA,0xF8,0xB2,0x97,0xCF,0xF8,0xF2,0xF9,0x37,0xE8
    /* [113..250] EmitDetails — written by etxn_details (auto-zero here) */
};

int64_t cbak(uint32_t reserved)
{
    /* Emitted ClaimReward resolved — nothing to reconcile (stateless). */
    accept(SBUF("AutoReward: callback completed."), 0);
    _g(1, 1);
    return 0;
}

int64_t hook(uint32_t reserved)
{
    /* `txn` is the file-scope ClaimReward template (see note above) — fresh per
       invocation because the hook wasm is re-instantiated each call. We fill
       Account / FLS / LLS / Fee / EmitDetails below. */

    /* ---- trigger gate (frz-authz / otxn_type finding) ------------------
       Auto-claim only on the INTENDED triggers — the Cron tick and an external
       Invoke poke. HookOn also admits SetHook (tt22) so a reinstall re-arms the
       cron, but a reinstall must NOT itself stage a ClaimReward: a maintenance
       SetHook shouldn't carry a claim side-effect. Accept early (no emit) on
       SetHook; Cron/Invoke fall through to the eligibility gate + emit. */
    if (otxn_type() == ttHOOK_SET)
        accept(SBUF("AutoReward: no claim on SetHook reinstall."), 0);

    /* Who are we (and the claimer Account on the emitted ClaimReward). */
    uint8_t hook_acc[20];
    if (hook_account(SBUF(hook_acc)) != 20)
        rollback(SBUF("AutoReward: hook_account failed."), 1);
    for (int i = 0; _g(2, 21), i < 20; ++i)
        txn[CR_ACCT_OUT + i] = hook_acc[i];

    /* ---- FAIL-OPEN eligibility gate (spam-proofing) -------------------
       Bounce ONLY when we can prove we're still inside the cooldown:
       RewardTime present AND now < RewardTime + 30d. Any read failure or a
       missing RewardTime (never primed) falls through to emit. */
    {
        uint8_t kl[34];
        if (util_keylet(SBUF(kl), KEYLET_ACCOUNT, hook_acc, 20, 0, 0, 0, 0) == 34 &&
            slot_set(SBUF(kl), 1) == 1 &&
            slot_subfield(1, sfRewardTime, 2) == 2)
        {
            uint8_t rt[4];
            if (slot(SBUF(rt), 2) == 4)
            {
                uint32_t reward_time =
                    ((uint32_t)rt[0] << 24) | ((uint32_t)rt[1] << 16) |
                    ((uint32_t)rt[2] << 8)  |  (uint32_t)rt[3];
                int64_t now = ledger_last_time();
                if (reward_time != 0 && now >= 0 &&
                    (uint64_t)now < (uint64_t)reward_time + BA_COOLDOWN_SECONDS)
                {
                    /* In cooldown — no-op. Spamming pokes costs only the
                       poker's own Invoke fee; we emit nothing. */
                    accept(SBUF("AutoReward: within 30d cooldown, no-op."), 0);
                }
            }
        }
    }

    /* ---- Eligible (or unknown / first claim) -> emit the ClaimReward ---- */
    if (etxn_reserve(1) != 1)
        rollback(SBUF("AutoReward: etxn_reserve failed."), 2);

    uint32_t seq = (uint32_t)ledger_seq();
    uint32_t fls = seq + 1U;
    uint32_t lls = seq + 5U;
    txn[CR_FLS_OUT + 0] = (fls >> 24) & 0xFFU; txn[CR_FLS_OUT + 1] = (fls >> 16) & 0xFFU;
    txn[CR_FLS_OUT + 2] = (fls >> 8)  & 0xFFU; txn[CR_FLS_OUT + 3] =  fls        & 0xFFU;
    txn[CR_LLS_OUT + 0] = (lls >> 24) & 0xFFU; txn[CR_LLS_OUT + 1] = (lls >> 16) & 0xFFU;
    txn[CR_LLS_OUT + 2] = (lls >> 8)  & 0xFFU; txn[CR_LLS_OUT + 3] =  lls        & 0xFFU;

    if (etxn_details(txn + CR_EMIT_OUT, CR_EMIT_LEN) != CR_EMIT_LEN)
        rollback(SBUF("AutoReward: etxn_details failed."), 3);

    int64_t fee = etxn_fee_base(txn, CR_SIZE);
    if (fee < 0)
        rollback(SBUF("AutoReward: etxn_fee_base failed."), 4);
    uint64_t feeval = 0x4000000000000000ULL | (uint64_t)fee;   /* native XAH amount */
    for (int i = 0; _g(3, 9), i < 8; ++i)
        txn[CR_FEE_OUT + i] = (uint8_t)((feeval >> (56 - 8 * i)) & 0xFFU);

    uint8_t emit_hash[32];
    if (emit(SBUF(emit_hash), txn, CR_SIZE) < 0)
        rollback(SBUF("AutoReward: failed to emit claim transaction."), 5);

    accept(SBUF("AutoReward: claim emitted successfully."), 0);
    _g(4, 1);
    return 0;
}
