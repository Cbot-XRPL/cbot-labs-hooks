#include "hookapi.h"
#include <stdint.h>

/*
 * Constant-Product AMM Hook
 *
 * Pool: native XAH <-> a single IOU (currency CUR issued by ISSUER).
 * Invariant: x * y = k (constant product) on swaps, with a configurable
 * swap fee in basis points. LP shares are tracked in hook state; no LP token.
 *
 * All math is done in 64-bit unsigned integers. IOU amounts are scaled into
 * integer micro-units (1e-6) on the way in and converted back to XFL on the
 * way out for the emitted Payment.
 *
 * Install params (hook_param):
 *   CUR     : 20-byte standard currency code for the IOU side
 *   ISSUER  : 20-byte account_id of the IOU issuer
 *   FEEBPS  : uint32 swap fee in basis points (capped in-hook at 1000)
 *   MINXAH  : uint64 minimum XAH drops for swap/add
 *   MINIOU  : uint64 minimum IOU micro-units for swap/add
 *   DAO_BPS : uint32 slice of fee routed to DAO escrow (0 = off)
 *   DAO_DEST: 20-byte account_id of the DAO wallet
 *   DAO_MIN : uint64 auto-emit threshold in drops (0 = manual claim only)
 *
 * Tx params (otxn_param):
 *   CMD    : 3-8 byte ASCII command — "ADD", "REM", "SWAP", "DAOCLAIM",
 *            "TESTDAO"
 *   SHARES : REM, uint64 LP share micro-units to redeem
 *   MINOUT : SWAP, uint64 micro-unit slippage floor
 *
 * State layout (32-byte keys, first byte is namespace tag):
 *   0x01 + 31 zeros                 -> pool config (56 bytes)
 *       u64 reserveXahDrops
 *       u64 reserveIouMicro
 *       u64 totalShares
 *       u64 cumFeesXahDrops
 *       u64 cumFeesIouMicro
 *       u64 cumDaoXahDrops   (optional DAO fee escrow, XAH side)
 *       u64 cumDaoIouMicro   (optional DAO fee escrow, IOU side)
 *   0x02 + 20-byte LP account + 11 zeros -> per-LP shares (u64)
 *   0x03 + 20-byte LP account + 11 zeros -> pending ADD credit
 *       u8 side (1 = XAH pending, 2 = IOU pending)
 *       u64 amount (drops for side=1, micro for side=2)
 *
 * Notes:
 *   - ADD is a 2-step protocol: LP sends one side first, then the other.
 *   - First-LP bootstrap uses shares = xah_in + iou_in (simple, safe). This is
 *     not a true sqrt-based AMM bootstrap; seed the pool with a small balanced
 *     amount before opening liquidity to others.
 *   - REM is triggered by a tiny XAH dust Payment; the dust is added to the
 *     XAH reserve and only the share-math payout is emitted back.
 *   - v5: all four XAH-out emit sites (REM, SWAP out, DAO auto-flush, DAOCLAIM)
 *     use a hand-built 260-byte Payment template with a 138-byte EmitDetails
 *     block instead of PREPARE_PAYMENT_SIMPLE. The macro emits a 116-byte
 *     EmitDetails that the current Xahau mainnet amendment level rejects,
 *     producing "emit XAH failed." rollbacks. Same fix pattern as the v3->v4
 *     Remit migration.
 */

#define AMM_GUARD(n)     _g(__LINE__, (n) + 1)
#define AMM_ACCEPT(msg)  return accept(SBUF(msg), __LINE__)
/* Helper that inlines the offer-emit + accept at the call site. Originally
   tried to hoist these via `goto post_emit;` to free depth budget, but
   forward-goto compiles to a wasm `block { br }` wrapping which costs more
   depth than the inline call. Inline form keeps the original depth
   structure; ladder fits in amm_emit_offers itself via flat AMM_MULDIV. */
#define AMM_ACCEPT_AFTER_EMIT(msg) do {                                 \
    (void)amm_emit_offers(hook_acc, cfg_cur, cfg_issuer,                \
                          reserveXah, reserveIou, totalShares,          \
                          min_xah, min_iou, fee_bps, dao_bps, feeccy);  \
    return accept(SBUF(msg), __LINE__);                                 \
} while (0)
#define AMM_ROLLBACK(msg) return rollback(SBUF(msg), __LINE__)

#define AMM_MAX_FEEBPS   1000U

#define AMM_CFG_LEN      72U
#define AMM_CFG_LEN_V1   56U  /* legacy length; pre-pending-tracker installs */
#define AMM_CFG_RXAH      0U
#define AMM_CFG_RIOU      8U
#define AMM_CFG_SHARES   16U
#define AMM_CFG_FEEXAH   24U
#define AMM_CFG_FEEIOU   32U
#define AMM_CFG_DAOX     40U
#define AMM_CFG_DAOY     48U
/* Global pending-ADD totals across ALL senders. YIELD adds these to
   `tracked` so cross-user stash XAH/IOU isn't treated as untracked yield
   and double-counted into reserveXah/cumFee. Incremented on side-1 stash
   creation, decremented on side-2 completion / pending-clear. Upgrade
   path: when state() returns AMM_CFG_LEN_V1 (56 B), bytes 56-71 are
   zero-padded — a one-shot DAO RESYNC with CPXH/CPIO seeds the values to
   the sum of currently-outstanding stash slot amounts. */
#define AMM_CFG_PENDXAH  56U
#define AMM_CFG_PENDIOU  64U

#define AMM_PEND_LEN      9U
#define AMM_PEND_SIDE_XAH 1U
#define AMM_PEND_SIDE_IOU 2U

#define AMM_ZERO(buf, len) \
    { for (uint32_t _z = 0; AMM_GUARD(len), _z < (uint32_t)(len); ++_z) (buf)[_z] = 0; }

#define AMM_COPY_20(dst, src) \
    { for (int _c = 0; AMM_GUARD(20), _c < 20; ++_c) (dst)[_c] = (src)[_c]; }


/* read the RAW 8-byte sfBalance value word of `who`'s ALP(hook_acc, lpcur)
   trustline; 0 if no line. sA/sB = scratch slot numbers. Cheaper than an XFL
   decode (no float_int) and enough for cbak-verify, which only needs to know
   whether the balance CHANGED (tec => unchanged, delivery => changed). ALP is
   pool-issued so nothing but a mint/burn can move this word. */
#define AMM_READ_ALP_RAW(out_raw, who, hook_acc, lpcur, sA, sB) do {             \
    (out_raw) = 0;                                                               \
    uint8_t _rk[34];                                                             \
    if (util_keylet(SBUF(_rk), KEYLET_LINE, (who),20, (hook_acc),20, (lpcur),20) == 34 \
        && slot_set(SBUF(_rk), (sA)) == (sA)                                     \
        && slot_subfield((sA), sfBalance, (sB)) == (sB)) {                       \
        uint8_t _rb[48]; int64_t _rl = slot(SBUF(_rb), (sB));                    \
        if (_rl == 8 || _rl == 48) (out_raw) = UINT64_FROM_BUF(_rb);            \
    }                                                                           \
} while (0)

#define SBUF_STR(str) (uint32_t)(str), sizeof(str) - 1

/* --------------------------------------------------------------------- */
/* 64-bit safe multiply-divide: (a * b) / c, with overflow guard.        */
/* Returns 0xFFFFFFFFFFFFFFFFULL on overflow.                            */
/* --------------------------------------------------------------------- */
#define AMM_MULDIV_OVF (~(uint64_t)0)
/* Macro (a*b)/c using hook XFL API — avoids clang emitting __multi3 and
   avoids introducing a non-imported helper function in the wasm. Writes the
   result into `out_var`; sets it to AMM_MULDIV_OVF on overflow/error.
   Flattened (early-break) form: each error case `break`s out of the do-while
   so block nesting stays at 2 levels (do-while + the if-then). The original
   nested-if version reached 7 levels which left no headroom for a multi-rung
   offer ladder. Same semantics. */
#define AMM_MULDIV(out_var, a_in, b_in, c_in)                                 \
    do {                                                                       \
        uint64_t _ma = (uint64_t)(a_in);                                       \
        uint64_t _mb = (uint64_t)(b_in);                                       \
        uint64_t _mc = (uint64_t)(c_in);                                       \
        (out_var) = AMM_MULDIV_OVF;                                            \
        if (_mc == 0) break;                                                   \
        if (_ma == 0 || _mb == 0) { (out_var) = 0; break; }                    \
        int64_t _xa = float_set(0, (int64_t)_ma);                              \
        if (_xa < 0) break;                                                    \
        int64_t _xb = float_set(0, (int64_t)_mb);                              \
        if (_xb < 0) break;                                                    \
        int64_t _xc = float_set(0, (int64_t)_mc);                              \
        if (_xc < 0) break;                                                    \
        int64_t _pr = float_multiply(_xa, _xb);                                \
        if (_pr < 0) break;                                                    \
        int64_t _q = float_divide(_pr, _xc);                                   \
        if (_q < 0) break;                                                     \
        int64_t _i = float_int(_q, 0, 0);                                      \
        if (_i < 0) break;                                                     \
        (out_var) = (uint64_t)_i;                                              \
    } while (0)

/* --------------------------------------------------------------------- */
/* AMM v3: Remit-with-sfAmounts template for single IOU payouts.         */
/* Size = 306 bytes. EmitDetails block is 138 bytes (Xahau mainnet       */
/* amendment level). Layout follows the Xahau-ephemeral-broker pattern.  */
/* Using Remit means the receiver does NOT need a pre-existing trustline */
/* — ttREMIT auto-creates one on the destination.                        */
/* --------------------------------------------------------------------- */
#define AMM_REMIT_SIZE       306U
#define AMM_REMIT_EMIT_LEN   138U
#define AMM_REMIT_FLS_OUT     15U
#define AMM_REMIT_LLS_OUT     21U
#define AMM_REMIT_FEE_OUT     26U
#define AMM_REMIT_ACCT_OUT    71U
#define AMM_REMIT_DEST_OUT    93U
#define AMM_REMIT_EMIT_OUT   113U
#define AMM_REMIT_AMT_OUT    255U

/* Global Remit template, statically initialised to the constant-byte
   layout. Every TESTDAO call patches only the variable fields in place
   (FLS, LLS, Account, Destination, Fee, Amount, EmitDetails). Using a
   global + in-place patches avoids the multi-_g-per-line guard-violation
   that macros suffer from. Hooks don't re-enter during an invocation so
   the single shared buffer is safe. */
uint8_t amm_remit_tx[AMM_REMIT_SIZE] = {
    [0]=0x12U, [1]=0x00U, [2]=0x5FU,          /* tt=Remit */
    [3]=0x22U, [4]=0x80U,                      /* Flags */
    [8]=0x24U,                                 /* sfSequence */
    [13]=0x20U, [14]=0x1AU,                    /* sfFirstLedgerSequence */
    [19]=0x20U, [20]=0x1BU,                    /* sfLastLedgerSequence */
    [25]=0x68U, [26]=0x40U,                    /* sfFee header + native-XAH marker bit
                                                  (0x40 = positive native; required for
                                                  etxn_fee_base to parse the txn). */
    [34]=0x73U, [35]=0x21U,                    /* sfSigningPubKey VL, len=33 */
    [69]=0x81U, [70]=0x14U,                    /* sfAccount 20B */
    [91]=0x83U, [92]=0x14U,                    /* sfDestination 20B */
    [251]=0xF0U, [252]=0x5CU,                  /* sfAmounts array open */
    [253]=0xE0U, [254]=0x5BU,                  /* AmountEntry object open */
    [304]=0xE1U, [305]=0xF1U                   /* object close + array close */
};

/* --------------------------------------------------------------------- */
/* AMM v5: native-XAH Payment template for the four XAH-out emit sites.  */
/* Size = 260 bytes with a 138-byte EmitDetails block. Replaces the      */
/* PREPARE_PAYMENT_SIMPLE macro, which emits a 116-byte EmitDetails      */
/* block that the current Xahau mainnet amendment level rejects (emit    */
/* returns < 0, hook sees "amm: emit XAH failed."). Layout mirrors the   */
/* ephemeral-broker reference and the Remit template above.              */
/* --------------------------------------------------------------------- */
#define AMM_PAY_SIZE       260U
#define AMM_PAY_EMIT_LEN   138U
#define AMM_PAY_FLS_OUT     15U
#define AMM_PAY_LLS_OUT     21U
#define AMM_PAY_AMT_OUT     26U
#define AMM_PAY_FEE_OUT     35U
#define AMM_PAY_ACCT_OUT    80U
#define AMM_PAY_DEST_OUT   102U
#define AMM_PAY_EMIT_OUT   122U

uint8_t amm_pay_tx[AMM_PAY_SIZE] = {
    [0]=0x12U, [1]=0x00U, [2]=0x00U,          /* tt=Payment */
    [3]=0x22U, [4]=0x80U,                      /* Flags */
    [8]=0x24U,                                 /* sfSequence */
    [13]=0x20U, [14]=0x1AU,                    /* sfFirstLedgerSequence */
    [19]=0x20U, [20]=0x1BU,                    /* sfLastLedgerSequence */
    [25]=0x61U, [26]=0x40U,                    /* sfAmount native + 0x40 marker */
    [34]=0x68U, [35]=0x40U,                    /* sfFee native + 0x40 marker */
    [43]=0x73U, [44]=0x21U,                    /* sfSigningPubKey VL, len=33 */
    [78]=0x81U, [79]=0x14U,                    /* sfAccount 20B */
    [100]=0x83U, [101]=0x14U                   /* sfDestination 20B */
};

#define AMM_PAY_WRITE_DROPS(buf_ptr, value) do {                                   \
    uint64_t _amm_pd = ((uint64_t)(value) & 0x3FFFFFFFFFFFFFFFULL) | 0x4000000000000000ULL; \
    UINT64_TO_BUF((buf_ptr), _amm_pd);                                             \
} while (0)

/* --------------------------------------------------------------------- */
/* AMM v2 DEX-EXPOSURE: OfferCreate templates so the path-finder can    */
/* route Payments through the pool. Each template patches per-emit.     */
/* Hook does NOT fire on offer consumption (verified on testnet); the   */
/* bidirectional YIELD reconcile catches the deltas on next interaction.*/
/*                                                                       */
/* TEMPLATE A — pool sells IOU for XAH                                   */
/*   TakerPays = XAH (8B native)   <- what pool RECEIVES                 */
/*   TakerGets = IOU (49B w/field) <- what pool GIVES UP                 */
/*                                                                       */
/* Field order (canonical XRPL, sorted by type then field):              */
/*   TransactionType (1,2)   =  3B   [0..2]                              */
/*   Flags (2,2)             =  5B   [3..7]                              */
/*   Sequence (2,4)          =  5B   [8..12]                             */
/*   Expiration (2,10)       =  5B   [13..17]                            */
/*   FirstLedgerSequence (2,26) = 6B [18..23]                            */
/*   LastLedgerSequence (2,27)  = 6B [24..29]                            */
/*   TakerPays (6,4)         =  9B (native XAH) [30..38]                 */
/*   TakerGets (6,5)         = 49B (IOU) [39..87]                        */
/*   Fee (6,8)               =  9B (native XAH) [88..96]                 */
/*   SigningPubKey (7,3)     = 35B (VL=33 + 33 zeros) [97..131]          */
/*   Account (8,1)           = 22B (VL=20 + 20B) [132..153]              */
/*   EmitDetails (14,13)     = 138B [154..291]                           */
/*   ----                                                                */
/*   Total                   = 292 bytes                                 */
/* --------------------------------------------------------------------- */
#define AMM_OFFA_SIZE          292U
#define AMM_OFFA_EMIT_LEN      138U
#define AMM_OFFA_EXP_OUT        14U   /* u32 ripple-time after 0x2A */
#define AMM_OFFA_FLS_OUT        20U
#define AMM_OFFA_LLS_OUT        26U
#define AMM_OFFA_PAYS_OUT       31U   /* 8 bytes XAH (after 0x64) */
#define AMM_OFFA_GETS_XFL_OUT   40U   /* 8 bytes XFL (after 0x65) */
#define AMM_OFFA_GETS_CUR_OUT   48U   /* 20 bytes currency */
#define AMM_OFFA_GETS_ISS_OUT   68U   /* 20 bytes issuer */
#define AMM_OFFA_FEE_OUT        89U   /* 8 bytes XAH (after 0x68) */
#define AMM_OFFA_ACCT_OUT      134U   /* 20 bytes (after 0x81 0x14) */
#define AMM_OFFA_EMIT_OUT      154U   /* 138 bytes filled by etxn_details */

uint8_t amm_offa_tx[AMM_OFFA_SIZE] = {
    [0]=0x12U, [1]=0x00U, [2]=0x07U,           /* tt=OfferCreate */
    [3]=0x22U, [4]=0x80U,                       /* sfFlags = 0x80000000 (tfFullyCanonicalSig) */
    [8]=0x24U,                                  /* sfSequence (emit fills) */
    [13]=0x2AU,                                 /* sfExpiration (patch) */
    [18]=0x20U, [19]=0x1AU,                     /* sfFirstLedgerSequence */
    [24]=0x20U, [25]=0x1BU,                     /* sfLastLedgerSequence */
    [30]=0x64U, [31]=0x40U,                     /* sfTakerPays native + 0x40 marker */
    [39]=0x65U,                                 /* sfTakerGets (IOU follows: 8 XFL + 20 cur + 20 iss) */
    [88]=0x68U, [89]=0x40U,                     /* sfFee native + 0x40 marker */
    [97]=0x73U, [98]=0x21U,                     /* sfSigningPubKey VL=33 (33 zeros follow) */
    [132]=0x81U, [133]=0x14U                    /* sfAccount 20B */
};

/* --------------------------------------------------------------------- */
/* TEMPLATE B — pool sells XAH for IOU                                   */
/*   TakerPays = IOU (49B w/field) <- what pool RECEIVES                 */
/*   TakerGets = XAH (8B native)   <- what pool GIVES UP                 */
/* Same total size (292B) — only the amount field positions differ.     */
/* --------------------------------------------------------------------- */
#define AMM_OFFB_SIZE          292U
#define AMM_OFFB_EMIT_LEN      138U
#define AMM_OFFB_EXP_OUT        14U
#define AMM_OFFB_FLS_OUT        20U
#define AMM_OFFB_LLS_OUT        26U
#define AMM_OFFB_PAYS_XFL_OUT   31U   /* 8 bytes XFL (after 0x64) */
#define AMM_OFFB_PAYS_CUR_OUT   39U   /* 20 bytes currency */
#define AMM_OFFB_PAYS_ISS_OUT   59U   /* 20 bytes issuer */
#define AMM_OFFB_GETS_OUT       80U   /* 8 bytes XAH (after 0x65) */
#define AMM_OFFB_FEE_OUT        89U
#define AMM_OFFB_ACCT_OUT      134U
#define AMM_OFFB_EMIT_OUT      154U

uint8_t amm_offb_tx[AMM_OFFB_SIZE] = {
    [0]=0x12U, [1]=0x00U, [2]=0x07U,
    [3]=0x22U, [4]=0x80U,
    [8]=0x24U,
    [13]=0x2AU,
    [18]=0x20U, [19]=0x1AU,
    [24]=0x20U, [25]=0x1BU,
    [30]=0x64U,                                 /* sfTakerPays IOU (no 0x40 marker — XFL bytes follow) */
    [79]=0x65U, [80]=0x40U,                     /* sfTakerGets native + 0x40 marker */
    [88]=0x68U, [89]=0x40U,
    [97]=0x73U, [98]=0x21U,
    [132]=0x81U, [133]=0x14U
};

#define AMM_FEE_WRITE(buf_ptr, value) do {                                          \
    (buf_ptr)[0] = 0x40U | (uint8_t)(((uint64_t)(value) >> 56) & 0x3FU);             \
    (buf_ptr)[1] = (uint8_t)(((uint64_t)(value) >> 48) & 0xFFU);                     \
    (buf_ptr)[2] = (uint8_t)(((uint64_t)(value) >> 40) & 0xFFU);                     \
    (buf_ptr)[3] = (uint8_t)(((uint64_t)(value) >> 32) & 0xFFU);                     \
    (buf_ptr)[4] = (uint8_t)(((uint64_t)(value) >> 24) & 0xFFU);                     \
    (buf_ptr)[5] = (uint8_t)(((uint64_t)(value) >> 16) & 0xFFU);                     \
    (buf_ptr)[6] = (uint8_t)(((uint64_t)(value) >>  8) & 0xFFU);                     \
    (buf_ptr)[7] = (uint8_t)( (uint64_t)(value)        & 0xFFU);                     \
} while (0)

/* ---------------------------------------------------------------------- */
/* Pending state schema (v2 cbak protection):                              */
/*   Key   : 32-byte emit hash from a state-affecting emit (LP IOU mint).  */
/*   Value : 1 byte op_tag + 8 bytes shares_delta = 9 bytes                */
/*           op_tag = AMM_PEND_TAG_ADD (0x01) — totalShares was incremented*/
/*                    by shares_delta when this emit was scheduled.        */
/* On cbak success: pending entry cleared (totalShares stays).             */
/* On cbak failure: totalShares -= shares_delta, pending entry cleared.    */
/* Why only ADD: REM's LP IOU is INBOUND (atomic burn), reserves are       */
/* auto-healed by XAH-YIELD + IOU-YIELD on next interaction. SWAP/DAOCLAIM */
/* don't touch totalShares. So ADD's outbound LP IOU mint is the only      */
/* state-affecting emit that can desync if it fails post-commit.           */
/* ---------------------------------------------------------------------- */
/* cbak-verify (2026-08): the pending carries the depositor + their pre-mint ALP
   balance so cbak decides on DELIVERY TRUTH (re-read the depositor's ALP line),
   NOT on ctx (which is 0 for a tec too — testnet-proven, see
   reviews/cbak-verify-delivery-truth-2026-08-09). Layout:
     [0]      op_tag (0x01 = ADD)
     [1..8]   minted (u64) — added to totalShares by this ADD
     [9..28]  depositor accountID (20B) — needed on the EmitFailure (ctx!=0) path,
              where the emitted txn's sfDestination is not readable
     [29..36] pre-mint depositor ALP sfBalance RAW value word (u64; 0 if no line) */
#define AMM_PEND_LEN_CBAK   37U
#define AMM_PEND_TAG_ADD    0x01U
#define AMM_PC_MINTED        1U
#define AMM_PC_USER          9U
#define AMM_PC_PRERAW       29U

int64_t cbak(uint32_t ctx)
{
    _g(1, 1);

    /* Recover the emit hash that this callback corresponds to. ctx==0 means
       the emitted txn was applied successfully (otxn_id is the emit hash
       on this hook invocation); ctx!=0 means it was rejected (the emit
       hash lives in sfEmittedTxnID instead). */
    uint8_t cb_key[32];
    int64_t cb_len = -1;
    if (ctx == 0U)
        cb_len = otxn_id(SBUF(cb_key), 0);
    else
        cb_len = otxn_field(SBUF(cb_key), sfEmittedTxnID);
    if (cb_len != 32)
        cb_len = otxn_id(SBUF(cb_key), 0);
    if (cb_len != 32)
        return accept(0, 0, __LINE__);

    /* Look up pending entry by emit hash. Most emits (offer posts, REM XAH/
       IOU emits, DAOCLAIM, MIGRATE) won't have a pending entry — that's
       expected; cbak is a no-op for them. */
    uint8_t pend[AMM_PEND_LEN_CBAK];
    if (state(SBUF(pend), SBUF(cb_key)) != AMM_PEND_LEN_CBAK)
        return accept(0, 0, __LINE__);

    uint8_t tag = pend[0];
    uint64_t delta = UINT64_FROM_BUF(pend + AMM_PC_MINTED);

    /* cbak-verify: decide on DELIVERY TRUTH, not ctx. A tec emit reaches cbak
       with ctx==0 (looks like success) — but the depositor's ALP balance only
       moves if the mint actually delivered. Re-read it here (post-apply) and
       revert totalShares whenever it did NOT increase. One check covers BOTH the
       tec path (ctx==0) and the EmitFailure path (ctx!=0), with no TOCTOU (real
       state, after the emit applied) and no manipulation vector (ALP is issued
       only by this pool). Testnet-proven premise: reviews/cbak-verify-delivery-
       truth-2026-08-09 + sandbox/tests/probe/. */
    if (tag == AMM_PEND_TAG_ADD) {
        uint8_t depositor[20];
        AMM_COPY_20(depositor, pend + AMM_PC_USER);
        uint64_t pre_raw = UINT64_FROM_BUF(pend + AMM_PC_PRERAW);

        uint8_t hook_acc[20];
        if (hook_account(SBUF(hook_acc)) != 20) {
            state_set(0, 0, SBUF(cb_key));
            return accept(0, 0, __LINE__);
        }

        /* re-read + normalize the pool's ALP currency (install param) */
        uint8_t amm_lp_cur[20];
        AMM_ZERO(amm_lp_cur, 20);
        int lp_tok = 0;
        {
            int64_t lpcl = hook_param(SBUF(amm_lp_cur), SBUF_STR("AMM_LP_CUR"));
            if (lpcl == 20) {
                for (int _i = 0; AMM_GUARD(20), _i < 20; ++_i)
                    if (amm_lp_cur[_i] != 0) { lp_tok = 1; break; }
            } else if (lpcl == 3) {
                uint8_t s0 = amm_lp_cur[0], s1 = amm_lp_cur[1], s2 = amm_lp_cur[2];
                AMM_ZERO(amm_lp_cur, 20);
                amm_lp_cur[12] = s0; amm_lp_cur[13] = s1; amm_lp_cur[14] = s2;
                lp_tok = 1;
            }
        }

        /* #157: decide on the emitted txn's provisional-meta TER, not the absolute
           ALP-balance delta — unrelated ALP activity in the callback window could
           make post != pre and wrongly read a failed mint as delivered. Only
           tesSUCCESS(0) is a real delivery. If meta can't be read (ter stays 0xFF)
           fall back to the balance-delta (tokenized) or ctx (legacy) — still no
           worse than before. */
        int delivered;
        {
            uint8_t ter = 0xFFU;
            int64_t ms = (ctx == 0U) ? meta_slot(0) : (int64_t)-1;
            if (ms >= 0 && slot_subfield((uint32_t)ms, sfTransactionResult, (uint32_t)ms) >= 0)
                slot(&ter, 1, (uint32_t)ms);
            if (ter != 0xFFU) {
                delivered = (ctx == 0U && ter == 0U) ? 1 : 0;   /* authoritative TER */
            } else if (lp_tok) {
                uint64_t post_raw = 0;
                AMM_READ_ALP_RAW(post_raw, depositor, hook_acc, amm_lp_cur, 20, 22);
                delivered = (post_raw != pre_raw) ? 1 : 0;      /* fallback: balance delta */
            } else {
                delivered = (ctx == 0U) ? 1 : 0;                /* legacy state-only */
            }
        }

        if (!delivered) {
            uint8_t cfg_k[32];
            for (int _i = 0; _i < 32; ++_i) cfg_k[_i] = 0;
            cfg_k[0] = 0x01U;
            uint8_t cfg_v[AMM_CFG_LEN];
            if (state(cfg_v, AMM_CFG_LEN, SBUF(cfg_k)) == AMM_CFG_LEN) {
                uint64_t ts = UINT64_FROM_BUF(cfg_v + AMM_CFG_SHARES);
                /* underflow guard: never floor to 0 (zombie pool) — see #12 notes */
                if (ts >= delta) {
                    ts -= delta;
                    UINT64_TO_BUF(cfg_v + AMM_CFG_SHARES, ts);
                    state_set(cfg_v, AMM_CFG_LEN, SBUF(cfg_k));
                }
            }
        }
    }
    state_set(0, 0, SBUF(cb_key));
    return accept(0, 0, __LINE__);
}

/* --------------------------------------------------------------------- */
/* AMM v3 update: post bid + ask offers on the DEX so the path-finder    */
/* can route Payments through the pool. Sized 1% of reserves, priced via */
/* constant-product curve + fee_bps spread, 600s Expiration (was 90s).   */
/*                                                                       */
/* Why 600s instead of 90s: with 90s the pool went dark inside any 2-min */
/* lull in interactions, and an external keeper would have been needed   */
/* to keep liquidity live. 600s lets normal organic activity keep the    */
/* pool visible. Reserve cost: each open offer holds ~2 XAH owner-       */
/* reserve; 2 offers/emit × ~6 emits/hour worst case ≈ 12 active offers  */
/* at any moment ≈ 24 XAH locked. Acceptable for the visibility gain.    */
/*                                                                       */
/* Why not a multi-rung ladder yet: the AMM_MULDIV chain + per-rung      */
/* control flow stacked too deep against the wasm guard checker's 16-    */
/* level block-nesting cap. Tried 2- and 3-rung variants with various    */
/* flatten attempts; none compiled. A real curve-style ladder needs a    */
/* heavier refactor (split emit into a separate hook account, or wait    */
/* for guard relaxation). For now: single rung at 1% + 600s expiration   */
/* gets the visibility win without a depth fight. Direct CMD=SWAP still  */
/* unlocks the FULL curve for any trader who knows our pool address.    */
/*                                                                       */
/* Returns 0 on success or any skip; never aborts the parent hook.       */
/* etxn_reserve must be called by the caller BEFORE this function (it   */
/* needs at least 2 reserved slots).                                    */
/* --------------------------------------------------------------------- */
static inline __attribute__((always_inline)) int64_t amm_emit_offers(
    uint8_t* hook_acc20, uint8_t* cfg_cur20, uint8_t* cfg_iss20,
    uint64_t reserveXah, uint64_t reserveIou, uint64_t totalShares,
    uint64_t min_xah, uint64_t min_iou, uint32_t fee_bps,
    uint32_t dao_bps, uint32_t feeccy)
{
    _g(2, 1);

    /* FEECCY=1 offer-ladder reprice (DAO fee-currency = XAH).
       Offer A (pool sells IOU, over-collects XAH) already accrues its margin
       in XAH — left unchanged. Offer B (pool sells XAH, over-collects IOU)
       normally books its whole fee margin in IOU. Under mode 1 we split the
       margin so the DAO-cut portion is retained in XAH (under-deliver XAH)
       while the LP portion stays over-collected in IOU:
         fee_lp_bps  = fee_bps * (10000 - dao_bps) / 10000   (LP keeps IOU)
         dao_fee_bps = fee_bps - fee_lp_bps                  (DAO keeps XAH)
       These are small u32 (fee_bps<=1000, dao_bps<=10000) so the products fit
       in u64 with no __multi3 and no AMM_MULDIV. When feeccy==0 or dao_bps==0
       both collapse to the mode-0 values (fee_lp_bps==fee_bps, dao_fee_bps==0),
       so offer B stays byte-for-byte the mode-0 ladder. */
    int off_b_xah = (feeccy == 1U && dao_bps > 0U) ? 1 : 0;
    uint32_t fee_lp_bps = fee_bps;
    uint32_t dao_fee_bps = 0U;
    if (off_b_xah) {
        fee_lp_bps  = (uint32_t)(((uint64_t)fee_bps * (uint64_t)(10000U - dao_bps)) / 10000ULL);
        dao_fee_bps = fee_bps - fee_lp_bps;
        if (dao_fee_bps >= 10000U) dao_fee_bps = 9999U; /* paranoia: keep 10000-x > 0 */
    }
    /* Divisor the IOU over-collect markup uses: LP-only fee under mode 1,
       full fee under mode 0. Guaranteed < 10000 (fee_bps<=1000). */
    uint32_t off_b_div = 10000U - fee_lp_bps;

    if (totalShares == 0) return 0;
    if (reserveXah < min_xah * 10ULL) return 0;
    if (reserveIou < min_iou * 10ULL) return 0;

    uint64_t off_iou = reserveIou / 100ULL; if (off_iou == 0) off_iou = 1;
    uint64_t off_xah = reserveXah / 100ULL; if (off_xah == 0) off_xah = 1;
    if (off_iou >= reserveIou) return 0;
    if (off_xah >= reserveXah) return 0;

    /* Direction A pricing: pays_xah_a = off_iou × reserveXah × 10000
                                       / ((reserveIou - off_iou) × (10000 - fee_bps))
       Direction B pricing: pays_iou_b = off_xah × reserveIou × 10000
                                       / ((reserveXah - off_xah) × (10000 - fee_bps))

       BUGFIX (2026-05-19): the prior implementation pre-multiplied
       `off_iou × reserveXah` (and `off_xah × reserveIou`) via a u32-halves
       split-multiply to avoid emitting __multi3 (128-bit helper not in
       the Hook API whitelist). That trick capped each operand at
       0xFFFFFFFF = 4.29B drops / micro. Once mainnet pool reserves
       crossed that line (≈ 4,295 XAH), the guard `if (reserveXah >
       0xFFFFFFFFULL) return 0;` silently aborted every offer-emit call
       — the AMM stopped posting passive DEX offers around 2026-05-10.
       The fix: stop pre-multiplying. AMM_MULDIV already does the
       multiplication via float_multiply (XFL math) which has effectively
       unbounded intermediate range. Restructure the formula so the
       intermediate quotient (a × b / divisor) is small enough to fit in
       int64 after the divide, then apply the fee-bps adjustment as a
       second AMM_MULDIV. Identical mathematical result, no __multi3,
       no u32 ceiling. Safe up to MAX_TOTX / MAX_TOTY = 100k XAH / IOU. */
    uint64_t pays_xah_a = 0, pays_iou_b = 0;
    {
        uint64_t step1_a;
        AMM_MULDIV(step1_a, off_iou, reserveXah, reserveIou - off_iou);
        if (step1_a == AMM_MULDIV_OVF || step1_a == 0) return 0;
        AMM_MULDIV(pays_xah_a, step1_a, 10000ULL, (uint64_t)(10000U - fee_bps));
        if (pays_xah_a == AMM_MULDIV_OVF || pays_xah_a == 0) return 0;
    }
    {
        uint64_t step1_b;
        AMM_MULDIV(step1_b, off_xah, reserveIou, reserveXah - off_xah);
        if (step1_b == AMM_MULDIV_OVF || step1_b == 0) return 0;
        /* off_b_div = 10000-fee_bps in mode 0, 10000-fee_lp_bps in mode 1
           (over-collect only the LP portion of the fee in IOU). */
        AMM_MULDIV(pays_iou_b, step1_b, 10000ULL, (uint64_t)off_b_div);
        if (pays_iou_b == AMM_MULDIV_OVF || pays_iou_b == 0) return 0;
    }
    /* Mode 1: under-deliver XAH by the DAO-cut portion so the pool keeps that
       portion of the margin in XAH. deliver_xah_b == off_xah in mode 0.
       Plain u64 math (no XFL/AMM_MULDIV — keeps worst-case instruction count
       under the 65535 ceiling): off_xah*(10000-dao_fee_bps) <= off_xah*10000,
       guarded so the product cannot overflow u64. */
    uint64_t deliver_xah_b = off_xah;
    if (off_b_xah && off_xah <= ((~(uint64_t)0) / 10000ULL)) {
        uint64_t dxb = off_xah * (uint64_t)(10000U - dao_fee_bps) / 10000ULL;
        if (dxb > 0) deliver_xah_b = dxb;
    }

    int64_t lt = ledger_last_time();
    if (lt < 0) return 0;
    /* Offer TTL = 62 min. Slightly longer than the keeper's 60-min idle
       interval so emitted offers stay live until the next refresh, even
       if the keeper skips an idle poke (skipped when there's been pool
       activity in the past hour, since user txs already repost offers).
       Reserve cost: each open offer holds ~0.2 XAH owner reserve; 4
       offers/emit = 0.8 XAH locked, freed on the next emit's overwrite
       or on expiry. Worst-case ~3-4 emit batches × 4 offers = 12-16
       active offers ≈ 2.4-3.2 XAH locked at any moment. Acceptable. */
    uint32_t exp_at = (uint32_t)(lt + 3700LL);
    uint32_t fls = (uint32_t)ledger_seq() + 1U;

    /* Copy the 20-byte currency / issuer / hook-account fields into BOTH offer
       templates up front, one merged loop per field (3 loops, not 6). Halving
       the number of guarded ~21x copy loops on this hot path reclaims the
       worst-case instruction budget the FEECCY reprice needs, at ~zero byte
       cost — cheaper than unrolling (which balloons bytes because this whole
       function is always_inline at ~6 call sites). Both templates are separate
       persistent globals, so writing both before either emit is safe. */
    for (int _i = 0; _g(__LINE__, 21), _i < 20; ++_i) {
        amm_offa_tx[AMM_OFFA_GETS_CUR_OUT + _i] = cfg_cur20[_i];
        amm_offb_tx[AMM_OFFB_PAYS_CUR_OUT + _i] = cfg_cur20[_i];
    }
    for (int _i = 0; _g(__LINE__, 21), _i < 20; ++_i) {
        amm_offa_tx[AMM_OFFA_GETS_ISS_OUT + _i] = cfg_iss20[_i];
        amm_offb_tx[AMM_OFFB_PAYS_ISS_OUT + _i] = cfg_iss20[_i];
    }
    for (int _i = 0; _g(__LINE__, 21), _i < 20; ++_i) {
        amm_offa_tx[AMM_OFFA_ACCT_OUT + _i] = hook_acc20[_i];
        amm_offb_tx[AMM_OFFB_ACCT_OUT + _i] = hook_acc20[_i];
    }

    /* ---- emit offer A: TakerPays=pays_xah_a XAH, TakerGets=off_iou IOU ---- */
    UINT32_TO_BUF(amm_offa_tx + AMM_OFFA_EXP_OUT, exp_at);
    UINT32_TO_BUF(amm_offa_tx + AMM_OFFA_FLS_OUT, fls);
    UINT32_TO_BUF(amm_offa_tx + AMM_OFFA_LLS_OUT, fls + 4U);
    AMM_PAY_WRITE_DROPS(amm_offa_tx + AMM_OFFA_PAYS_OUT, pays_xah_a);
    int64_t xfl_a = float_set(-6, (int64_t)off_iou);
    if (xfl_a < 0) return 0;
    {
        uint64_t xfl_u = ((uint64_t)xfl_a) ^ 0x8000000000000000ULL;
        UINT64_TO_BUF(amm_offa_tx + AMM_OFFA_GETS_XFL_OUT, xfl_u);
        /* currency/issuer copied up-front in the merged loops above */
    }
    if (etxn_details(amm_offa_tx + AMM_OFFA_EMIT_OUT, AMM_OFFA_EMIT_LEN) != AMM_OFFA_EMIT_LEN)
        return 0;
    int64_t fee_a = etxn_fee_base(amm_offa_tx, AMM_OFFA_SIZE);
    if (fee_a < 0) return 0;
    AMM_FEE_WRITE(amm_offa_tx + AMM_OFFA_FEE_OUT, (uint64_t)fee_a);
    uint8_t eha[32];
    int64_t er_a = emit(SBUF(eha), amm_offa_tx, AMM_OFFA_SIZE);
    if (er_a < 0) { TRACEVAR(er_a); TRACESTR("AMM: offer A emit failed"); return 0; }

    /* ---- emit offer B: TakerPays=pays_iou_b IOU, TakerGets=off_xah XAH ---- */
    UINT32_TO_BUF(amm_offb_tx + AMM_OFFB_EXP_OUT, exp_at);
    UINT32_TO_BUF(amm_offb_tx + AMM_OFFB_FLS_OUT, fls);
    UINT32_TO_BUF(amm_offb_tx + AMM_OFFB_LLS_OUT, fls + 4U);
    int64_t xfl_b = float_set(-6, (int64_t)pays_iou_b);
    if (xfl_b < 0) return 0;
    {
        uint64_t xfl_u = ((uint64_t)xfl_b) ^ 0x8000000000000000ULL;
        UINT64_TO_BUF(amm_offb_tx + AMM_OFFB_PAYS_XFL_OUT, xfl_u);
        /* currency/issuer copied up-front in the merged loops above */
    }
    AMM_PAY_WRITE_DROPS(amm_offb_tx + AMM_OFFB_GETS_OUT, deliver_xah_b);
    if (etxn_details(amm_offb_tx + AMM_OFFB_EMIT_OUT, AMM_OFFB_EMIT_LEN) != AMM_OFFB_EMIT_LEN)
        return 0;
    int64_t fee_b = etxn_fee_base(amm_offb_tx, AMM_OFFB_SIZE);
    if (fee_b < 0) return 0;
    AMM_FEE_WRITE(amm_offb_tx + AMM_OFFB_FEE_OUT, (uint64_t)fee_b);
    uint8_t ehb[32];
    int64_t er_b = emit(SBUF(ehb), amm_offb_tx, AMM_OFFB_SIZE);
    if (er_b < 0) { TRACEVAR(er_b); TRACESTR("AMM: offer B emit failed"); return 0; }

    /* ============== RUNG 2 — 5% of reserves, deeper into the curve.
       Captures mid-size trades that would step past the 1% rung. Each
       offer's price reflects the slippage that size trade would incur on
       the AMM, so walking the ladder == walking the curve. Best-effort:
       any failure inside the do-while just exits the rung and leaves
       rung 1 in place. The do-while + early-break flat structure keeps
       wasm block-nesting at the minimum (1 outer block + AMM_MULDIV's
       2 levels). Reuses the rung-1 template buffers — by this point
       rung 1's emits have completed and the wasm txn images are
       immutable, so overwriting the template is safe. */
    do {
        uint64_t off_iou_2 = reserveIou / 20ULL; if (off_iou_2 == 0) break;
        uint64_t off_xah_2 = reserveXah / 20ULL; if (off_xah_2 == 0) break;
        if (off_iou_2 >= reserveIou) break;
        if (off_xah_2 >= reserveXah) break;

        /* Same XFL-pipeline restructure as rung 1 — no u32 narrowing,
           no __multi3, safe at full MAX_TOTX / MAX_TOTY pool sizes. */
        uint64_t pays_xah_a2 = 0, step1_a2;
        AMM_MULDIV(step1_a2, off_iou_2, reserveXah, reserveIou - off_iou_2);
        if (step1_a2 == AMM_MULDIV_OVF || step1_a2 == 0) break;
        AMM_MULDIV(pays_xah_a2, step1_a2, 10000ULL, (uint64_t)(10000U - fee_bps));
        if (pays_xah_a2 == AMM_MULDIV_OVF || pays_xah_a2 == 0) break;

        uint64_t pays_iou_b2 = 0, step1_b2;
        AMM_MULDIV(step1_b2, off_xah_2, reserveIou, reserveXah - off_xah_2);
        if (step1_b2 == AMM_MULDIV_OVF || step1_b2 == 0) break;
        AMM_MULDIV(pays_iou_b2, step1_b2, 10000ULL, (uint64_t)off_b_div);
        if (pays_iou_b2 == AMM_MULDIV_OVF || pays_iou_b2 == 0) break;
        /* Mode 1: under-deliver XAH by the DAO portion (== off_xah_2 in mode 0).
           Plain guarded u64 math (see rung-1 note) to stay under the 65535
           worst-case instruction ceiling. */
        uint64_t deliver_xah_b2 = off_xah_2;
        if (off_b_xah && off_xah_2 <= ((~(uint64_t)0) / 10000ULL)) {
            uint64_t dxb2 = off_xah_2 * (uint64_t)(10000U - dao_fee_bps) / 10000ULL;
            if (dxb2 > 0) deliver_xah_b2 = dxb2;
        }

        /* RUNG 2 offer A (5% IOU side) — overwrite rung-1 template */
        AMM_PAY_WRITE_DROPS(amm_offa_tx + AMM_OFFA_PAYS_OUT, pays_xah_a2);
        int64_t xfl_a2 = float_set(-6, (int64_t)off_iou_2);
        if (xfl_a2 < 0) break;
        uint64_t xfl_au2 = ((uint64_t)xfl_a2) ^ 0x8000000000000000ULL;
        UINT64_TO_BUF(amm_offa_tx + AMM_OFFA_GETS_XFL_OUT, xfl_au2);
        if (etxn_details(amm_offa_tx + AMM_OFFA_EMIT_OUT, AMM_OFFA_EMIT_LEN) != AMM_OFFA_EMIT_LEN) break;
        int64_t fee_a2 = etxn_fee_base(amm_offa_tx, AMM_OFFA_SIZE);
        if (fee_a2 < 0) break;
        AMM_FEE_WRITE(amm_offa_tx + AMM_OFFA_FEE_OUT, (uint64_t)fee_a2);
        uint8_t eha2[32];
        (void)emit(SBUF(eha2), amm_offa_tx, AMM_OFFA_SIZE);

        /* RUNG 2 offer B (5% XAH side) */
        int64_t xfl_b2 = float_set(-6, (int64_t)pays_iou_b2);
        if (xfl_b2 < 0) break;
        uint64_t xfl_bu2 = ((uint64_t)xfl_b2) ^ 0x8000000000000000ULL;
        UINT64_TO_BUF(amm_offb_tx + AMM_OFFB_PAYS_XFL_OUT, xfl_bu2);
        AMM_PAY_WRITE_DROPS(amm_offb_tx + AMM_OFFB_GETS_OUT, deliver_xah_b2);
        if (etxn_details(amm_offb_tx + AMM_OFFB_EMIT_OUT, AMM_OFFB_EMIT_LEN) != AMM_OFFB_EMIT_LEN) break;
        int64_t fee_b2 = etxn_fee_base(amm_offb_tx, AMM_OFFB_SIZE);
        if (fee_b2 < 0) break;
        AMM_FEE_WRITE(amm_offb_tx + AMM_OFFB_FEE_OUT, (uint64_t)fee_b2);
        uint8_t ehb2[32];
        (void)emit(SBUF(ehb2), amm_offb_tx, AMM_OFFB_SIZE);
    } while (0);

    TRACESTR("AMM: ladder posted (rung1 + rung2)");
    return 0;
}

int64_t hook(uint32_t reserved)
{
    _g(1, 1);
    (void)reserved;

    /* v7-exp: Payment, Invoke, or Remit. Invoke is canonical for
       signal-only ops (REM legacy SHARES path / DAOCLAIM / MIGRATE).
       Payment carries single-sided value CMDs (SWAP, ADD legs).
       Remit (XLS-43) carries the NEW dual-currency single-tx ADD:
       both legs in one signed tx via sfAmounts. Every other tt
       (GenesisMint, ClaimReward/BA, Import, …) falls through exactly
       as before — BA income keeps landing silently and gets absorbed
       by the YIELD preludes on the next op. */
    int64_t _ttype = otxn_type();
    if (((uint32_t)(_ttype != ttPAYMENT) & (uint32_t)(_ttype != ttINVOKE) & (uint32_t)(_ttype != ttREMIT)) != 0)
        AMM_ACCEPT("amm: non-payment/invoke ignored.");
    int is_invoke = (_ttype == ttINVOKE) ? 1 : 0;
    int is_remit  = (_ttype == ttREMIT)  ? 1 : 0;

    uint8_t hook_acc[20];
    if (hook_account(SBUF(hook_acc)) != 20)
        AMM_ROLLBACK("amm: hook_account failed.");

    uint8_t sender[20];
    if (otxn_field(SBUF(sender), sfAccount) != 20)
        AMM_ROLLBACK("amm: missing sender.");

    /* Self-emitted payments (ours) must pass through without recursion. */
    if (BUFFER_EQUAL_20(hook_acc, sender))
        AMM_ACCEPT("amm: self-emit pass-through.");

    /* v7-exp Remit policy is enforced AFTER the shared CMD classify below
       (reusing its otxn_param read instead of a redundant one): CMD=ADD →
       dual-currency single-tx ADD; no CMD → legacy blanket-accept
       (XAH_DIS funding / donations, absorbed by YIELD on the next op, the
       same path BA income uses); any other CMD → rollback. */

    /* v3: reserve emit budget upfront — etxn_reserve can only be called
       once per hook execution. Max emits across any branch (with 2-rung
       ladder = 4 offers/emit):
         SWAP:     1 XAH-out + 2 DAO emits + 4 ladder offers = 7
         REM:      1 XAH + 1 IOU + 4 ladder = 6
         DAOCLAIM: 1 XAH + 1 IOU + 4 ladder = 6
         no-CMD / ADD / TESTDAO: 4 ladder
       Reserving 8 covers every path with slack; unused slots are free.
       Ladder fits because we flattened AMM_MULDIV (early-break form,
       was 7-deep nested-if, now 2-deep) freeing wasm guard depth budget. */
    if (etxn_reserve(8) < 0)
        AMM_ROLLBACK("amm: etxn_reserve(8) failed.");

    /* -------- install params -------- */
    uint8_t cfg_cur[20];
    {
        uint8_t cur_raw[20];
        AMM_ZERO(cur_raw, 20);
        int64_t clen = hook_param(SBUF(cur_raw), SBUF_STR("CUR"));
        if (clen <= 0)
            AMM_ROLLBACK("amm: missing CUR param.");
        AMM_ZERO(cfg_cur, 20);
        if (clen == 20)
        {
            AMM_COPY_20(cfg_cur, cur_raw);
        }
        else if (clen == 3)
        {
            /* standard 3-ascii -> 20-byte layout: bytes 12..14 = ASCII */
            cfg_cur[12] = cur_raw[0];
            cfg_cur[13] = cur_raw[1];
            cfg_cur[14] = cur_raw[2];
        }
        else
        {
            AMM_ROLLBACK("amm: CUR must be 3 ascii or 20 bytes.");
        }
    }

    uint8_t cfg_issuer[20];
    {
        int64_t ilen = hook_param(SBUF(cfg_issuer), SBUF_STR("ISSUER"));
        if (ilen != 20)
            AMM_ROLLBACK("amm: ISSUER must be 20-byte account.");
    }

    uint32_t fee_bps = 0;
    {
        uint8_t fb[4];
        if (hook_param(SBUF(fb), SBUF_STR("FEEBPS")) != 4)
            AMM_ROLLBACK("amm: missing FEEBPS.");
        fee_bps = UINT32_FROM_BUF(fb);
        if (fee_bps > AMM_MAX_FEEBPS) fee_bps = AMM_MAX_FEEBPS;
    }

    uint64_t min_xah = 0;
    {
        uint8_t b[8];
        if (hook_param(SBUF(b), SBUF_STR("MINXAH")) != 8)
            AMM_ROLLBACK("amm: missing MINXAH.");
        min_xah = UINT64_FROM_BUF(b);
    }

    uint64_t min_iou = 0;
    {
        uint8_t b[8];
        if (hook_param(SBUF(b), SBUF_STR("MINIOU")) != 8)
            AMM_ROLLBACK("amm: missing MINIOU.");
        min_iou = UINT64_FROM_BUF(b);
    }

    /* -------- optional DAO fee-routing params -------- */
    /* DAO_BPS: u32, slice of swap fee routed to DAO escrow (bps). 0 = off.
       DAO_DEST: 20-byte account_id of the DAO wallet. Absent/invalid = off.
       When both are set, a configurable cut of each swap fee is diverted
       into a separate escrow (cumDaoXahDrops / cumDaoIouMicro) that is not
       included in reserves. Only DAO_DEST can claim via CMD=DAOCLAIM. */
    uint32_t dao_bps = 0;
    uint8_t  dao_dest[20];
    AMM_ZERO(dao_dest, 20);
    int dao_enabled = 0;
    {
        uint8_t db[4];
        int64_t drl = hook_param(SBUF(db), SBUF_STR("DAO_BPS"));
        if (drl == 4) dao_bps = UINT32_FROM_BUF(db);
        if (dao_bps > 10000U) dao_bps = 10000U;
    }
    {
        int64_t drl = hook_param(SBUF(dao_dest), SBUF_STR("DAO_DEST"));
        if (drl == 20 && dao_bps > 0) dao_enabled = 1;
    }
    uint64_t dao_min = 0; /* auto-emit threshold in drops (0 = manual claim only) */
    {
        uint8_t db[8];
        int64_t drl = hook_param(SBUF(db), SBUF_STR("DAO_MIN"));
        if (drl == 8) dao_min = UINT64_FROM_BUF(db);
    }

    /* -------- FEECCY: DAO fee-currency mode (u32, optional, default 0) --------
       FEECCY = 0 (absent = 0): today's exact behavior — the DAO cut is booked
                 in whichever leg it naturally lands (XAH for a XAH-in buy,
                 IOU for an IOU-in sell). Byte/behavior parity with E8400EF2.
       FEECCY = 1: book the DAO cut in XAH ONLY ("keep extra XAH in the books,
                 not IOUs"). On an IOU->XAH sell, where the cut would naturally
                 escrow into cumDaoIou, the SWAP handler instead converts that
                 cut to XAH along the constant-product curve (k preserved) and
                 escrows it into cumDaoXah, leaving cumDaoIou untouched. XAH-in
                 buys already book XAH and are unchanged. The offer ladder
                 reprices Offer B (see amm_emit_offers) so its DAO-portion
                 margin is denominated in XAH rather than over-collected IOU.
                 Only the DAO cut changes currency; the LP fee share is
                 value-neutral (constant k, same per-share value).
       Any value other than 1 is treated as 0 (mode 0) — forward-safe. */
    uint32_t feeccy = 0;
    {
        uint8_t fc[4];
        if (hook_param(SBUF(fc), SBUF_STR("FEECCY")) == 4) feeccy = UINT32_FROM_BUF(fc);
        if (feeccy != 1U) feeccy = 0U;
    }

    /* v3: pool deposit caps. When MAX_RXAH > 0, ADDs that would push
       reserveXah above the cap are rejected. Same for MAX_RIOU on the
       IOU side. 0 = uncapped (production default once hook is battle-
       tested). Admins can set these as a safety throttle during early
       deployment by reinstalling the hook with new params. */
    uint64_t max_rxah = 0;     /* per-user XAH cap */
    uint64_t max_riou = 0;     /* per-user IOU cap */
    uint64_t max_tot_x = 0;    /* total pool XAH cap */
    uint64_t max_tot_y = 0;    /* total pool IOU cap */
    { uint8_t b[8]; if (hook_param(SBUF(b), SBUF_STR("MAX_RXAH"))==8) max_rxah = UINT64_FROM_BUF(b); }
    { uint8_t b[8]; if (hook_param(SBUF(b), SBUF_STR("MAX_RIOU"))==8) max_riou = UINT64_FROM_BUF(b); }
    { uint8_t b[8]; if (hook_param(SBUF(b), SBUF_STR("MAX_TOTX"))==8) max_tot_x = UINT64_FROM_BUF(b); }
    { uint8_t b[8]; if (hook_param(SBUF(b), SBUF_STR("MAX_TOTY"))==8) max_tot_y = UINT64_FROM_BUF(b); }

    /* v4 CFGUPDATE tunable overrides — single state slot at key
       0xC1 + 31 zeros holds runtime overrides for tunable params. Layout
       (64 bytes, big-endian):
         [ 0..3 ] u32 fee_bps         (0 = use install param FEEBPS)
         [ 4..7 ] u32 dao_bps         (0 = use install param DAO_BPS)
         [ 8..15] u64 dao_min_drops   (0 = use install param DAO_MIN)
         [16..23] u64 max_rxah_drops  (0 = use install param MAX_RXAH)
         [24..31] u64 max_riou_micro  (0 = use install param MAX_RIOU)
         [32..39] u64 max_tot_x_drops (0 = use install param MAX_TOTX)
         [40..47] u64 max_tot_y_micro (0 = use install param MAX_TOTY)
         [48..55] u64 min_xah_drops   (0 = use install param MINXAH)
         [56..63] u64 min_iou_micro   (0 = use install param MINIOU)
       Lets admin tune fees/caps/mins without a SetHook reinstall. Written
       by CMD=CFGUPDATE handler; cleared by CMD=CFGRESET. Both gated by
       sender == ADMIN install param. Reinstall continues to work in
       parallel — install params are the fallback when override is 0. */
    uint8_t tcfg_key[32]; AMM_ZERO(tcfg_key, 32); tcfg_key[0] = 0xC1U;
    uint8_t tcfg[64]; AMM_ZERO(tcfg, 64);
    int have_tcfg = (state(tcfg, 64, SBUF(tcfg_key)) == 64);
    if (have_tcfg) {
        uint32_t ov_fee = UINT32_FROM_BUF(tcfg + 0);
        if (ov_fee > 0) { fee_bps = ov_fee; if (fee_bps > AMM_MAX_FEEBPS) fee_bps = AMM_MAX_FEEBPS; }
        uint32_t ov_dao_bps = UINT32_FROM_BUF(tcfg + 4);
        if (ov_dao_bps > 0) { dao_bps = ov_dao_bps; if (dao_bps > 10000U) dao_bps = 10000U; }
        /* Re-derive dao_enabled — dao_bps may have just changed. Original
           install-time logic: enabled iff dao_dest was 20 bytes AND dao_bps > 0.
           The dao_dest install param is loaded above into dao_dest[20]; if
           absent it's still all zero (init'd via AMM_ZERO). */
        int dest_set = 0;
        for (int _i = 0; AMM_GUARD(20), _i < 20; ++_i) { if (dao_dest[_i] != 0) { dest_set = 1; break; } }
        dao_enabled = (dest_set && dao_bps > 0) ? 1 : 0;
        uint64_t ov_dao_min = UINT64_FROM_BUF(tcfg + 8);
        if (ov_dao_min > 0) dao_min = ov_dao_min;
        uint64_t ov_max_rxah = UINT64_FROM_BUF(tcfg + 16);
        if (ov_max_rxah > 0) max_rxah = ov_max_rxah;
        uint64_t ov_max_riou = UINT64_FROM_BUF(tcfg + 24);
        if (ov_max_riou > 0) max_riou = ov_max_riou;
        uint64_t ov_max_tot_x = UINT64_FROM_BUF(tcfg + 32);
        if (ov_max_tot_x > 0) max_tot_x = ov_max_tot_x;
        uint64_t ov_max_tot_y = UINT64_FROM_BUF(tcfg + 40);
        if (ov_max_tot_y > 0) max_tot_y = ov_max_tot_y;
        uint64_t ov_min_xah = UINT64_FROM_BUF(tcfg + 48);
        if (ov_min_xah > 0) min_xah = ov_min_xah;
        uint64_t ov_min_iou = UINT64_FROM_BUF(tcfg + 56);
        if (ov_min_iou > 0) min_iou = ov_min_iou;
    }

    /* v3: LP shares as IOU (tokenization).
       AMM_LP_CUR install param is the 20-byte currency code for the LP
       token. The AMM hook account itself is the issuer. When set + non-
       zero, ADD emits ALP via Remit (instead of writing per-LP state)
       and inbound ALP IOU triggers REM (using inbound amount as burn
       quantity, no SHARES param needed).
       When AMM_LP_CUR is all-zeros (legacy install), tokenization is OFF
       and behavior matches v2 (state-based per-LP shares).
       Permissionless MIGRATE handler converts existing state-based
       shares to ALP IOU on demand for any account — no admin required.
       Pre-blackhole prerequisite: hook account must have asfDefaultRipple
       set so ALP can be freely traded. Once set + master key blackholed,
       the flag is permanent. */
    uint8_t amm_lp_cur[20];
    AMM_ZERO(amm_lp_cur, 20);
    int lp_tokenized = 0;
    {
        int64_t lpcl = hook_param(SBUF(amm_lp_cur), SBUF_STR("AMM_LP_CUR"));
        if (lpcl == 20) {
            /* Detect if non-zero (legitimate currency code set). */
            for (int _i = 0; AMM_GUARD(20), _i < 20; ++_i)
                if (amm_lp_cur[_i] != 0) { lp_tokenized = 1; break; }
        } else if (lpcl == 3) {
            /* 3-ASCII shorthand → bytes 12-14 of canonical 20B layout */
            uint8_t s0 = amm_lp_cur[0], s1 = amm_lp_cur[1], s2 = amm_lp_cur[2];
            AMM_ZERO(amm_lp_cur, 20);
            amm_lp_cur[12] = s0; amm_lp_cur[13] = s1; amm_lp_cur[14] = s2;
            lp_tokenized = 1;
        }
    }

    /* -------- decode incoming Amount: native XAH or IOU? --------
       Invoke txns carry no Amount; leave is_xah_in / in_*_micro at 0 and
       skip parsing. CMD branches reject Invoke for value-bearing ops.
       Remits carry sfAmounts (array) instead of sfAmount — parsed in the
       dedicated block below; is_dual_in marks both legs present. */
    int is_xah_in = 0;
    uint64_t in_xah_drops = 0;
    uint64_t in_iou_micro = 0;
    int is_lp_iou_in = 0;
    int is_dual_in = 0;
    if (!is_invoke && !is_remit)
    {
    /* SECURITY (partial-payment guard — restored byte-for-byte from the live
       6CF9DFE8). Every Payment value path below credits / swaps / burns against
       the STATED sfAmount; a tfPartialPayment (Amount=big, SendMax=tiny) would
       deliver less — SWAP emits output for value never received, ADD inflates
       reserveIou, tokenized REM burns shares for LP never returned. Rejecting
       the flag makes delivered == sfAmount for every accepted Payment. This
       guards ONLY the Payment path: Remits carry sfAmounts (no sfAmount, no
       partial-delivery mechanism) and are handled in the dual-Remit ADD block
       below, so they correctly skip this. tfPartialPayment = 0x00020000.
       fl_buf is NOT pre-zeroed — otxn_field overwrites exactly the 4 bytes that
       are read, and only when it returned 4 (the short-circuit &&). */
    uint8_t fl_buf[4];
    if (otxn_field(SBUF(fl_buf), sfFlags) == 4 &&
        (UINT32_FROM_BUF(fl_buf) & 0x00020000U))
        AMM_ROLLBACK("amm: partial payments not allowed.");

    /* v7-exp: no AMM_ZERO on amt_buf — otxn_field overwrites exactly amt_len
       bytes, and amt_buf[8..47] is read ONLY on the amt_len==48 (IOU) branch,
       i.e. only after otxn_field wrote them. */
    uint8_t amt_buf[48];
    int64_t amt_len = otxn_field(SBUF(amt_buf), sfAmount);
    if (((uint32_t)(amt_len != 8) & (uint32_t)(amt_len != 48)) != 0)
        AMM_ROLLBACK("amm: bad Amount length.");

    is_xah_in = (amt_len == 8) ? 1 : 0;

    if (is_xah_in)
    {
        int64_t d = AMOUNT_TO_DROPS(amt_buf);
        if (d < 0)
            AMM_ROLLBACK("amm: negative drops.");
        in_xah_drops = (uint64_t)d;
    }
    else
    {
        /* IOU amount encoding (48 bytes):
             bytes  0..7  : XFL value
             bytes  8..27 : currency (20)
             bytes 28..47 : issuer  (20)
           Validate as one of two acceptable IOUs:
             (a) trade IOU (currency=cfg_cur, issuer=cfg_issuer)
             (b) LP IOU (currency=amm_lp_cur, issuer=hook_acc) — only
                 when lp_tokenized; routes to REM as burn input.
           Anything else is rejected. */
        int cur_match_trade = 1, iss_match_trade = 1;
        int cur_match_lp = lp_tokenized ? 1 : 0;
        int iss_match_lp = lp_tokenized ? 1 : 0;
        /* v7-exp: BRANCHLESS match loop — was 4× `if (x!=y) flag=0` plus a
           nested `if (lp_tokenized)` branch evaluated on every one of the 20
           iterations. The LP compares are always evaluated now: when not
           tokenized, cur_match_lp/iss_match_lp start at 0 and `0 & anything`
           stays 0, so the result is identical. Removing 20 iterations of
           branching is a sizeable common-path budget reclaim. */
        for (int i = 0; AMM_GUARD(20), i < 20; ++i) {
            cur_match_trade &= (amt_buf[8 + i]  == cfg_cur[i]);
            iss_match_trade &= (amt_buf[28 + i] == cfg_issuer[i]);
            cur_match_lp    &= (amt_buf[8 + i]  == amm_lp_cur[i]);
            iss_match_lp    &= (amt_buf[28 + i] == hook_acc[i]);
        }
        int is_trade_iou = (int)((uint32_t)cur_match_trade & (uint32_t)iss_match_trade);
        int is_lp_iou = (int)((uint32_t)lp_tokenized & (uint32_t)cur_match_lp & (uint32_t)iss_match_lp);
        if (((uint32_t)is_trade_iou | (uint32_t)is_lp_iou) == 0)
            AMM_ROLLBACK("amm: unrecognized IOU.");
        is_lp_iou_in = is_lp_iou;

        /* The on-wire serialized Amount has bit 63 inverted vs the
           canonical XFL that hooks float_* APIs expect.  Wire: bit63=1
           means positive.  Hooks XFL: bit63=0 means positive.  Flip it. */
        uint64_t raw = UINT64_FROM_BUF(amt_buf);
        if ((raw & 0x8000000000000000ULL) == 0)
            AMM_ROLLBACK("amm: xfl decode failed."); /* negative on wire */
        int64_t xfl = (int64_t)(raw ^ 0x8000000000000000ULL);
        if (xfl == 0)
            AMM_ROLLBACK("amm: zero IOU amount.");
        /* Convert XFL -> integer micro-units (scale 1e-6). */
        int64_t micro_i = float_int(xfl, 6, 0);
        if (micro_i < 0)
            AMM_ROLLBACK("amm: IOU value underflow.");
        in_iou_micro = (uint64_t)micro_i;
    }
    } /* end if (!is_invoke && !is_remit) Amount-parsing block */

    /* v7-exp: the dual-currency Remit ADD's sfAmounts are parsed AFTER the
       CMD classify below (so it can reuse that otxn_param read and the
       is_add flag) but still BEFORE the YIELD preludes that need
       in_xah_drops / in_iou_micro for their double-count exclusion. */

    /* -------- read CMD (v2: classify but don't reject yet — reconciles
       run first so no-CMD inbound (offer fill, donation, BA) can absorb
       delta into reserves). -------- */
    uint8_t cmd[8];
    AMM_ZERO(cmd, 8);
    int64_t cmd_len = otxn_param(SBUF(cmd), SBUF_STR("CMD"));

    /* v7-exp: BRANCHLESS CMD classify. Each operand is already 0/1, so the
       short-circuit `&&`/`||` (which the guard checker counts as branches +
       wasm blocks) is replaced with bitwise `&`/`|`. Identical booleans,
       zero branches — this reclaims enough common-path budget to fit the
       dual-Remit ADD without making the hook heavier than the original.
       `cl3/cl4/cl6/cl7/cl8` are the length predicates as 0/1. */
    uint32_t cl3 = (uint32_t)(cmd_len >= 3);
    uint32_t cl4 = (uint32_t)(cmd_len >= 4);
    uint32_t cl6 = (uint32_t)(cmd_len == 6);
    uint32_t cl7 = (uint32_t)(cmd_len == 7);
    uint32_t cl8 = (uint32_t)(cmd_len == 8);
    int is_add  = (int)(cl3 & (uint32_t)(cmd[0]=='A') & (uint32_t)(cmd[1]=='D') & (uint32_t)(cmd[2]=='D'));
    int is_rem  = (int)(cl3 & (uint32_t)(cmd[0]=='R') & (uint32_t)(cmd[1]=='E') & (uint32_t)(cmd[2]=='M'));
    int is_swap = (int)(cl4 & (uint32_t)(cmd[0]=='S') & (uint32_t)(cmd[1]=='W') & (uint32_t)(cmd[2]=='A') & (uint32_t)(cmd[3]=='P'));
    int is_migrate = (int)(cl7 & (uint32_t)(cmd[0]=='M') & (uint32_t)(cmd[1]=='I') & (uint32_t)(cmd[2]=='G') & (uint32_t)(cmd[3]=='R') & (uint32_t)(cmd[4]=='A') & (uint32_t)(cmd[5]=='T') & (uint32_t)(cmd[6]=='E'));
    /* RESYNC — admin (DAO_DEST) one-shot reserve reconcile (manual override
       for drift the bidirectional yield reconcile can't catch). */
    int is_resync = (int)(cl6 & (uint32_t)(cmd[0]=='R') & (uint32_t)(cmd[1]=='E') & (uint32_t)(cmd[2]=='S') & (uint32_t)(cmd[3]=='Y') & (uint32_t)(cmd[4]=='N') & (uint32_t)(cmd[5]=='C'));
    /* inbound ALP IOU auto-routes to REM (branchless: is_rem |= is_lp_iou_in). */
    is_rem = (int)((uint32_t)is_rem | (uint32_t)is_lp_iou_in);
    int is_daoclaim = (int)(cl8 & (uint32_t)(cmd[0]=='D') & (uint32_t)(cmd[1]=='A') & (uint32_t)(cmd[2]=='O') & (uint32_t)(cmd[3]=='C') & (uint32_t)(cmd[4]=='L') & (uint32_t)(cmd[5]=='A') & (uint32_t)(cmd[6]=='I') & (uint32_t)(cmd[7]=='M'));
    /* CFGSET / CFGRESET — admin runtime config (6/8 chars). */
    int is_cfg = (int)(cl6 & (uint32_t)(cmd[0]=='C') & (uint32_t)(cmd[1]=='F') & (uint32_t)(cmd[2]=='G') & (uint32_t)(cmd[3]=='S') & (uint32_t)(cmd[4]=='E') & (uint32_t)(cmd[5]=='T'));
    int is_cfgreset = (int)(cl8 & (uint32_t)(cmd[0]=='C') & (uint32_t)(cmd[1]=='F') & (uint32_t)(cmd[2]=='G') & (uint32_t)(cmd[3]=='R') & (uint32_t)(cmd[4]=='E') & (uint32_t)(cmd[5]=='S') & (uint32_t)(cmd[6]=='E') & (uint32_t)(cmd[7]=='T'));
    /* DBPSUPD — admin-only DAO_BPS update (Gov ptype-11 EXEC pushes it). */
    int is_dbpsupd = (int)(cl7 & (uint32_t)(cmd[0]=='D') & (uint32_t)(cmd[1]=='B') & (uint32_t)(cmd[2]=='P') & (uint32_t)(cmd[3]=='S') & (uint32_t)(cmd[4]=='U') & (uint32_t)(cmd[5]=='P') & (uint32_t)(cmd[6]=='D'));
    /* EXEC — permissionless dispatch after a passing ptype-15 vote. */
    int is_exec = (int)((uint32_t)(cmd_len == 4) & (uint32_t)(cmd[0]=='E') & (uint32_t)(cmd[1]=='X') & (uint32_t)(cmd[2]=='E') & (uint32_t)(cmd[3]=='C'));

    int has_known_cmd = (int)((uint32_t)is_add | (uint32_t)is_rem | (uint32_t)is_swap | (uint32_t)is_daoclaim | (uint32_t)is_migrate | (uint32_t)is_resync | (uint32_t)is_cfg | (uint32_t)is_cfgreset | (uint32_t)is_dbpsupd | (uint32_t)is_exec);

    /* ===== v7-exp: dual-currency Remit ADD =====
       Runs after the shared CMD classify, before the YIELD preludes.
       Policy by CMD on a Remit:
         CMD=ADD  → parse the two-leg sfAmounts and mark is_dual_in
         no CMD   → legacy blanket-accept (XAH_DIS funding / donation,
                    absorbed by YIELD on the next op — the BA-income path)
         any other CMD → rollback (value returns to sender via tx unwind)
       FIXED LEG ORDER (budget): entry[0] = native XAH, entry[1] = the
       trade IOU, EXACTLY two entries. The Remit is built server-side so
       order is guaranteed; enforcing it removes the slot_size classify +
       leg-picking that blew the 65535 worst-case-instruction ceiling.
       slot_count==2 closes the junk-3rd-leg trustline-spam vector; any
       wrong leg rolls back, unwinding the Remit (so it can never plant a
       junk trustline on the pool account). */
    if (is_remit && !is_add && has_known_cmd)
        AMM_ROLLBACK("amm: remit supports CMD=ADD only.");
    if (is_remit && is_add)
    {
        uint8_t xbuf[8];
        uint8_t ibuf[48];
        if (otxn_slot(10) <= 0)
            AMM_ROLLBACK("amm: remit ADD otxn_slot.");
        if (slot_subfield(10, sfAmounts, 11) != 11)
            AMM_ROLLBACK("amm: remit ADD needs Amounts.");
        if (slot_count(11) != 2)
            AMM_ROLLBACK("amm: remit ADD needs exactly 2 amounts.");
        if (slot_subarray(11, 0U, 12) != 12)
            AMM_ROLLBACK("amm: remit ADD bad entry 0.");
        if (slot_subfield(12, sfAmount, 13) <= 0)
            AMM_ROLLBACK("amm: remit ADD entry 0 amount.");
        if (slot(SBUF(xbuf), 13) != 8)
            AMM_ROLLBACK("amm: remit ADD entry 0 must be XAH.");
        if (slot_subarray(11, 1U, 14) != 14)
            AMM_ROLLBACK("amm: remit ADD bad entry 1.");
        if (slot_subfield(14, sfAmount, 15) <= 0)
            AMM_ROLLBACK("amm: remit ADD entry 1 amount.");
        if (slot(SBUF(ibuf), 15) != 48)
            AMM_ROLLBACK("amm: remit ADD entry 1 must be IOU.");

        int64_t rd = AMOUNT_TO_DROPS(xbuf);
        if (rd <= 0)
            AMM_ROLLBACK("amm: remit ADD bad drops.");
        in_xah_drops = (uint64_t)rd;

        if (!BUFFER_EQUAL_20(ibuf + 8, cfg_cur))
            AMM_ROLLBACK("amm: remit ADD unrecognized IOU.");
        if (!BUFFER_EQUAL_20(ibuf + 28, cfg_issuer))
            AMM_ROLLBACK("amm: remit ADD unrecognized IOU issuer.");
        uint64_t rraw = UINT64_FROM_BUF(ibuf);
        if ((rraw & 0x8000000000000000ULL) == 0)
            AMM_ROLLBACK("amm: remit ADD xfl decode.");
        int64_t rxfl = (int64_t)(rraw ^ 0x8000000000000000ULL);
        if (rxfl == 0)
            AMM_ROLLBACK("amm: remit ADD zero IOU.");
        int64_t rmicro = float_int(rxfl, 6, 0);
        if (rmicro <= 0)
            AMM_ROLLBACK("amm: remit ADD IOU underflow.");
        in_iou_micro = (uint64_t)rmicro;
        is_dual_in = 1;
    }

    /* -------- load pool config -------- */
    uint8_t cfg_key[32];
    AMM_ZERO(cfg_key, 32);
    cfg_key[0] = 0x01U;
    uint8_t cfg_val[AMM_CFG_LEN];
    AMM_ZERO(cfg_val, AMM_CFG_LEN);
    /* state() may return a short buffer on old installs:
       - 40 B: pre-DAO-escrow layout (no cumDao fields)
       - 56 B: pre-pending-tracker layout (no cumPending fields)
       - 72 B: current full layout
       We pre-zeroed cfg_val so any missing trailing fields default to 0
       and the first subsequent state_set writes a fresh 72-byte config,
       upgrading the layout cleanly. After install of this version on an
       existing pool with outstanding stashes, run RESYNC with CPXH/CPIO
       (DAO-only) to seed the pending-tracker fields to the sum of live
       stash slot amounts — without that, YIELD would treat the existing
       stash XAH/IOU as untracked yield on the next non-stashed tx. */
    int64_t cfg_r = state(cfg_val, AMM_CFG_LEN, SBUF(cfg_key));
    (void)cfg_r;

    uint64_t reserveXah = UINT64_FROM_BUF(cfg_val + AMM_CFG_RXAH);
    uint64_t reserveIou = UINT64_FROM_BUF(cfg_val + AMM_CFG_RIOU);
    uint64_t totalShares = UINT64_FROM_BUF(cfg_val + AMM_CFG_SHARES);
    uint64_t cumFeeXah = UINT64_FROM_BUF(cfg_val + AMM_CFG_FEEXAH);
    uint64_t cumFeeIou = UINT64_FROM_BUF(cfg_val + AMM_CFG_FEEIOU);
    uint64_t cumDaoXah = UINT64_FROM_BUF(cfg_val + AMM_CFG_DAOX);
    uint64_t cumDaoIou = UINT64_FROM_BUF(cfg_val + AMM_CFG_DAOY);
    uint64_t cumPendXah = UINT64_FROM_BUF(cfg_val + AMM_CFG_PENDXAH);
    uint64_t cumPendIou = UINT64_FROM_BUF(cfg_val + AMM_CFG_PENDIOU);

    TRACEVAR(reserveXah);
    TRACEVAR(reserveIou);
    TRACEVAR(totalShares);

    /* pending-ADD key + load — must be available to the YIELD preludes
       below so they can exclude any prior-txn pending-ADD stash from the
       tracked-vs-ledger delta. Without this, leg-2 of a two-leg ADD would
       re-absorb leg-1's stash as "yield" and inflate cumFee + corrupt the
       share-math denominator. */
    uint8_t pend_key[32];
    AMM_ZERO(pend_key, 32);
    pend_key[0] = 0x03U;
    AMM_COPY_20(pend_key + 1, sender);
    uint8_t pre_pend_val[AMM_PEND_LEN];
    AMM_ZERO(pre_pend_val, AMM_PEND_LEN);
    int64_t pre_pend_r = state(pre_pend_val, AMM_PEND_LEN, SBUF(pend_key));
    uint8_t pre_pend_side = (pre_pend_r == AMM_PEND_LEN) ? pre_pend_val[0] : 0;
    uint64_t pre_pend_amt = (pre_pend_r == AMM_PEND_LEN)
        ? UINT64_FROM_BUF(pre_pend_val + 1) : 0;

    /* XAH-YIELD: reconcile on-chain hook account XAH balance into state.
       Xahau Balance Adjustment (GenesisMint tt=96) credits land on the
       AccountRoot directly and never invoke the hook. We absorb the delta
       here on every command entry so LPs passively receive the yield
       proportional to their shares on the next interaction. Only written
       back if state is actually stale (avoids a redundant state_set on the
       common no-op path). Mirrors Richard's amm.c L401-412 idiom:
       util_keylet(KEYLET_ACCOUNT, HOOKACC) -> slot_set -> slot_subfield
       (sfBalance) but reads raw 8-byte drops via slot()+AMOUNT_TO_DROPS
       instead of slot_float, since our state stores drops as u64. */
    do {
        /* XAH-YIELD: skip reconciliation on a freshly-installed hook so
           the bootstrap ADD sees a clean zero reserve and the first LP
           controls the initial XAH side explicitly. Once the pool has any
           LP shares, reconciliation runs on every subsequent command. */
        if (totalShares == 0)
        { TRACESTR("AMM: yield skipped (pre-bootstrap)"); break; }
        uint8_t _yk[34];
        if (util_keylet(SBUF(_yk), KEYLET_ACCOUNT, hook_acc, 20, 0,0,0,0) != 34)
        { TRACESTR("AMM: yield keylet failed"); break; }
        if (slot_set(SBUF(_yk), 9) != 9)
        { TRACESTR("AMM: yield slot_set failed"); break; }
        if (slot_subfield(9, sfBalance, 9) != 9)
        { TRACESTR("AMM: yield slot_subfield failed"); break; }
        uint8_t _yb[8];
        if (slot(SBUF(_yb), 9) != 8)
        { TRACESTR("AMM: yield slot read wrong len"); break; }
        int64_t _yd = AMOUNT_TO_DROPS(_yb);
        if (_yd < 0)
        { TRACESTR("AMM: yield not native XAH"); break; }
        uint64_t raw_balance_drops = (uint64_t)_yd;

        /* v6 learning: subtract Xahau base+owner reserve (1 XAH +
           0.2 XAH × OwnerCount) so reserveXah tracker reflects what's
           actually safely emittable. Without this, REM math sized to
           the raw balance can fail tecUNFUNDED_PAYMENT when the post-
           emit balance would dip below the reserve floor — burning
           the LP's IOU but never delivering the XAH leg. */
        uint8_t _ok_buf[8]; AMM_ZERO(_ok_buf, 8);
        uint32_t owner_count = 0;
        if (slot_subfield(9, sfOwnerCount, 10) == 10) {
            if (slot(_ok_buf, 4, 10) == 4) {
                owner_count = ((uint32_t)_ok_buf[0] << 24)
                            | ((uint32_t)_ok_buf[1] << 16)
                            | ((uint32_t)_ok_buf[2] << 8)
                            |  (uint32_t)_ok_buf[3];
            }
        }
        uint64_t reserve_floor_drops = 1000000U + (uint64_t)owner_count * 200000U;
        uint64_t ledger_balance_drops = (raw_balance_drops > reserve_floor_drops)
            ? (raw_balance_drops - reserve_floor_drops)
            : 0;
        TRACEVAR(raw_balance_drops);
        TRACEVAR(reserve_floor_drops);
        TRACEVAR(ledger_balance_drops);
        /* XAH-YIELD: the ledger balance includes reserveXah, the DAO
           escrow (cumDaoXah), any XAH the rippled engine already
           credited from THIS txn's inbound Payment (rippled applies
           Payment before invoking the hook), AND any XAH still parked
           from a prior-txn leg-1 pending ADD by this sender. Only the
           delta above all four is genuine untracked yield (BA mint, DEX
           offer fill, donation, ignored Payment by other senders).
           Without these exclusions, SWAP/ADD deposits and stashed
           leg-1 amounts would be double-attributed — inflating cumFeeXah
           by ~333x and momentarily corrupting reserveXah. Same fix also
           covers DAOCLAIM legacy-dust path (dust would otherwise be
           absorbed here AND added explicitly by the DAOCLAIM body). */
        uint64_t tracked = reserveXah;
        if (cumDaoXah > (~(uint64_t)0) - tracked) tracked = ~(uint64_t)0;
        else tracked += cumDaoXah;
        /* v7-exp: amount-keyed (was `if (is_xah_in)`). Identical for every
           Payment/Invoke shape (XAH-in ⇒ drops>0, IOU-in ⇒ drops==0) but
           also excludes the XAH leg of a dual-currency Remit ADD — without
           this the leg would be absorbed as yield here AND added again by
           the ADD body: the double-count class the cumFee bug taught us. */
        if (in_xah_drops > 0) {
            if (tracked > (~(uint64_t)0) - in_xah_drops) tracked = ~(uint64_t)0;
            else tracked += in_xah_drops;
        }
        /* Global pending-stash credit. cumPendXah covers ALL outstanding
           XAH stashes including this sender's own. Without it, another
           user's prior-txn stash gets absorbed as "untracked yield" into
           reserveXah, draining their value to existing LPs. Fallback:
           if cumPendXah hasn't been seeded yet (post-upgrade, before the
           DAO RESYNC-CPXH heal), use this sender's own pre_pend_amt as a
           floor so leg-2 same-user is still protected. */
        uint64_t pend_x_track = cumPendXah;
        if (((uint32_t)(pre_pend_side == AMM_PEND_SIDE_XAH) & (uint32_t)(pend_x_track < pre_pend_amt)) != 0)
            pend_x_track = pre_pend_amt;
        if (tracked > (~(uint64_t)0) - pend_x_track) tracked = ~(uint64_t)0;
        else tracked += pend_x_track;
        if (ledger_balance_drops > tracked)
        {
            uint64_t delta = ledger_balance_drops - tracked;
            TRACEVAR(delta);
            TRACESTR("AMM: balance adjustment credit absorbed");
            reserveXah += delta;
            /* Track absorbed delta as lifetime LP yield. Source: any XAH that
               landed without going through a SWAP/ADD command (BA mint, REM
               rounding dust, inbound payments the hook ignored, on-ledger
               DEX revenue against this account's offers). It compounds into
               reserveXah which grows existing LP share value pro-rata, so
               it's effectively a fee — surfacing it in cumFeeXah keeps the
               lifetime-fees stat truthful instead of under-reporting LP
               gain. Downsyncs (ledger < tracked) are skipped — those are
               withdrawals, not revenue. */
            if (cumFeeXah > (~(uint64_t)0) - delta) cumFeeXah = ~(uint64_t)0;
            else cumFeeXah += delta;
            UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
            if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
                AMM_ROLLBACK("amm: yield cfg write failed.");
        }
        else if (ledger_balance_drops < tracked)
        {
            /* v2: bidirectional reconcile — absorb decrements too. Pool
               XAH can DROP below tracked when:
                 (a) our posted offer was filled in the XAH-out direction
                 (b) emit fees burnt drops out of pool over time
               The decrement is bounded by ledger_balance_drops (we never
               drive below 0, since ledger can't be < 0). Only the
               reserveXah portion absorbs the decrement; cumDaoXah is
               untouched (DAO escrow is virtual, just decrement reserveXah
               down to where ledger_balance - cumDaoXah lands). */
            uint64_t target_reserve = (ledger_balance_drops > cumDaoXah)
                                      ? (ledger_balance_drops - cumDaoXah) : 0;
            uint64_t delta_dn = reserveXah - target_reserve;
            TRACEVAR(delta_dn);
            TRACESTR("AMM: xah-yield decrement absorbed");
            reserveXah = target_reserve;
            UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
            if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
                AMM_ROLLBACK("amm: yield-dn cfg write failed.");
        }
    } while (0);
    /* XAH-YIELD: end */

    /* IOU-YIELD (v2): mirror of XAH-YIELD for the IOU side. Reads the
       pool's IOU trustline balance via KEYLET_LINE and absorbs any
       untracked positive delta into reserveIou. Captures IOU credits
       that arrive without invoking the hook — the most important being
       OUR OWN posted offers being filled by external Payments routed
       through the DEX path-finder. Hook does NOT fire on offer
       consumption (verified on testnet); without this reconcile, IOU
       received from offer fills would silently accumulate as untracked
       balance and the next CMD=SWAP would price using stale reserves. */
    do {
        if (totalShares == 0)
        { TRACESTR("AMM: iou-yield skipped (pre-bootstrap)"); break; }
        /* AUDIT #7 — REVIEW + TESTNET BEFORE MAINNET.
           ledger_iou defaults to 0 so the two empty/missing-trustline
           paths below (slot_set fail = the trustline object does not
           exist; xfl == 0 = balance is exactly zero) fall through to the
           reconcile with a ledger reading of 0 and DRIVE reserveIou DOWN
           toward 0, instead of `break`ing and leaving a phantom-high
           reserveIou that a later XAH->IOU swap would price against and be
           unable to pay. Both paths are deterministic ledger-state reads:
           they can only fire when the pool genuinely holds 0 of the trade
           IOU, so zeroing reserveIou matches on-chain reality — it is the
           exact same reconcile the existing `ledger_iou < tracked_iou`
           decrement branch already performs. The internal-error paths
           (keylet build, slot_subfield, wrong len) are NOT ledger signals
           and still `break` unchanged. */
        uint64_t ledger_iou = 0;
        uint8_t _lk[34];
        if (util_keylet(SBUF(_lk), KEYLET_LINE,
                        hook_acc, 20, cfg_issuer, 20, cfg_cur, 20) != 34)
        { TRACESTR("AMM: iou-yield keylet failed"); break; }
        if (slot_set(SBUF(_lk), 11) != 11)   /* AUDIT #7: no trustline object -> pool holds 0 IOU, reconcile reserveIou down */
        { TRACESTR("AMM: iou-yield slot_set failed (no trustline?)"); goto iou_reconcile; }
        if (slot_subfield(11, sfBalance, 11) != 11)
        { TRACESTR("AMM: iou-yield slot_subfield failed"); break; }
        /* TrustLine.Balance via slot() returns the STAmount-IOU
           serialization: 48 bytes = 8B XFL value + 20B currency
           + 20B issuer-null. */
        uint8_t _lb[48];
        int64_t _lb_len = slot(SBUF(_lb), 11);
        if (((uint32_t)(_lb_len != 8) & (uint32_t)(_lb_len != 48)) != 0)
        { TRACESTR("AMM: iou-yield slot read wrong len"); break; }
        /* XFL wire-format inverts bit 63 vs hook-native (wire bit 63
           = 1 → positive). XOR-flip to hook-native; pass absolute=1
           to float_int because the pool may be on either side of the
           lex-cmp ordering and we always want magnitude. */
        uint64_t raw = UINT64_FROM_BUF(_lb);
        int64_t xfl = (int64_t)(raw ^ 0x8000000000000000ULL);
        if (xfl == 0) { TRACESTR("AMM: iou-yield zero balance"); goto iou_reconcile; }  /* AUDIT #7: zero balance -> reconcile reserveIou down */
        int64_t iou_micro = float_int(xfl, 6, 1);
        if (iou_micro < 0)
        { TRACESTR("AMM: iou-yield xfl conv failed"); break; }
        /* AUDIT #9 — respect the SIGN. The raw RippleState.Balance sign is
           expressed in the LOW-node frame, so abs() (float_int absolute=1) would
           book a pool that OWES the trade IOU as positive reserve + LP profit.
           Normalize to the pool's own frame: the pool is the low node iff its
           20-byte account id sorts before the issuer's. If the pool's true
           holding is negative (it owes), reconcile reserveIou DOWN to 0 rather
           than crediting debt as reserve. Magnitude (iou_micro) is unchanged. */
        int _raw_pos = (raw & 0x4000000000000000ULL) != 0;   /* AUDIT #9 v2: in an STAmount value bit63 is the always-1 "is-IOU" TYPE flag; bit62 is the SIGN (positive 0xD.., negative 0x9..). Read bit62 for the low-node-frame sign. */
        int _pool_low = 0;
        for (int _ci = 0; _ci < 20; _ci++)
        { if (hook_acc[_ci] != cfg_issuer[_ci]) { _pool_low = hook_acc[_ci] < cfg_issuer[_ci]; break; } }
        int _pool_pos = _pool_low ? _raw_pos : (!_raw_pos);
        if (!_pool_pos)
        { TRACESTR("AMM: iou-yield pool owes trade IOU -> reserve 0"); ledger_iou = 0; goto iou_reconcile; }
        ledger_iou = (uint64_t)iou_micro;
    iou_reconcile: ;   /* AUDIT #7 reconcile entry; ledger_iou == 0 on the empty/missing-line paths above */
        uint64_t tracked_iou = reserveIou;
        if (cumDaoIou > (~(uint64_t)0) - tracked_iou) tracked_iou = ~(uint64_t)0;
        else tracked_iou += cumDaoIou;
        /* Mirror the XAH-YIELD exclusions: subtract this txn's own
           inbound trade-IOU before computing delta, and subtract any
           prior-txn IOU-side pending-ADD stash. LP-IOU inbound (REM)
           lands on a different trustline and never contributes to the
           trade-IOU ledger reading, so skip it. */
        /* v7-exp: amount-keyed (was `!is_xah_in && !is_lp_iou_in`) — same
           result for all Payment shapes, plus excludes the IOU leg of a
           dual-currency Remit ADD. */
        if (in_iou_micro > 0 && !is_lp_iou_in) {
            if (tracked_iou > (~(uint64_t)0) - in_iou_micro) tracked_iou = ~(uint64_t)0;
            else tracked_iou += in_iou_micro;
        }
        /* Cross-user pending-stash credit. See XAH-YIELD block for rationale. */
        uint64_t pend_y_track = cumPendIou;
        if (((uint32_t)(pre_pend_side == AMM_PEND_SIDE_IOU) & (uint32_t)(pend_y_track < pre_pend_amt)) != 0)
            pend_y_track = pre_pend_amt;
        if (tracked_iou > (~(uint64_t)0) - pend_y_track) tracked_iou = ~(uint64_t)0;
        else tracked_iou += pend_y_track;
        if (ledger_iou > tracked_iou)
        {
            uint64_t delta = ledger_iou - tracked_iou;
            TRACEVAR(delta);
            TRACESTR("AMM: iou-yield credit absorbed");
            reserveIou += delta;
            /* Mirror the XAH-YIELD fee tracking. IOU credits absorbed here
               are typically our own posted offers being filled — pool
               received IOU at our quoted rate (which embeds the spread).
               That gain belongs to LPs and should appear in cumFeeIou. */
            if (cumFeeIou > (~(uint64_t)0) - delta) cumFeeIou = ~(uint64_t)0;
            else cumFeeIou += delta;
            UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
            if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
                AMM_ROLLBACK("amm: iou-yield cfg write failed.");
        }
        else if (ledger_iou < tracked_iou)
        {
            /* v2: bidirectional — absorb IOU decrement too. Pool IOU
               drops when our posted offer was filled in the IOU-out
               direction, or when an external Payment routed through. */
            /* AUDIT #8 + #155 — the decrement target must exclude the SAME amounts
               tracked_iou excluded (this txn's inbound trade-IOU + the pending
               stash), or the target (ledger - cumDaoIou) settles reserveIou too
               HIGH — absorbing those just-arrived amounts into reserve when they
               belong to the SWAP/ADD path. #8 only stopped an outright RAISE via the
               clamp; #155 stops the too-high settle WITHIN the decrement. The plain
               reconcile (no inbound, no pending) is unchanged (excl == cumDaoIou). */
            uint64_t excl_iou = cumDaoIou;
            if (in_iou_micro > 0 && !is_lp_iou_in) {
                if (excl_iou > (~(uint64_t)0) - in_iou_micro) excl_iou = ~(uint64_t)0;
                else excl_iou += in_iou_micro;
            }
            if (excl_iou > (~(uint64_t)0) - pend_y_track) excl_iou = ~(uint64_t)0;
            else excl_iou += pend_y_track;
            uint64_t target_iou = (ledger_iou > excl_iou) ? (ledger_iou - excl_iou) : 0;
            /* Belt-and-suspenders: the decrement branch must never RAISE reserveIou. */
            if (target_iou > reserveIou) target_iou = reserveIou;
            uint64_t delta_dn = reserveIou - target_iou;
            TRACEVAR(delta_dn);
            TRACESTR("AMM: iou-yield decrement absorbed");
            reserveIou = target_iou;
            UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
            UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
            if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
                AMM_ROLLBACK("amm: iou-yield-dn cfg write failed.");
        }
    } while (0);
    /* IOU-YIELD: end */

    /* v2: now that XAH-YIELD + IOU-YIELD have run and any silent inbound
       (offer fill, donation, BA credit) has been absorbed into reserves,
       reject unknown CMDs softly via ACCEPT — but FIRST repost AMM
       offers on the DEX so the path-finder has fresh quotes. The same
       offer-repost runs at the end of every successful CMD branch
       below; doing it here too means even no-CMD pokes refresh the
       book. ROLLBACK here would discard reconcile + offers. */
    if (!has_known_cmd) {
        if (is_invoke)
            AMM_ACCEPT_AFTER_EMIT("amm: unknown CMD.");
        AMM_ACCEPT_AFTER_EMIT("amm: passive deposit reconciled.");
    }

    TRACEHEX(cmd);

    /* per-LP shares key */
    uint8_t lp_key[32];
    AMM_ZERO(lp_key, 32);
    lp_key[0] = 0x02U;
    AMM_COPY_20(lp_key + 1, sender);
    /* pend_key already derived above, before the YIELD preludes. */

    /* ================================================================ */
    /*  CFGUPDATE — admin-only tunable param overrides                   */
    /* ================================================================ */
    /* Admin sends Invoke (or Payment dust carrier) with CMD=CFGUPDATE +
       any subset of named params (FEEBPS, DAO_BPS, DAO_MIN, MAX_RXAH,
       MAX_RIOU, MAX_TOTX, MAX_TOTY, MINXAH, MINIOU). Hook merges into
       the tcfg state slot (each named param overwrites its slot offset;
       absent params keep prior value). On the next action, the override
       block above applies the new tcfg values. Reinstall continues to
       work — install params remain the fallback when override is 0.

       For DAO ops post-blackhole: when ADMIN install param is set to the
       DAO account, the DAO's own emit-from-Core path can fire CFGUPDATE
       Invokes via a future ptype handler. Same auth model as perps. */
    if (is_cfg) {
        uint8_t admin[20]; AMM_ZERO(admin, 20);
        if (hook_param(SBUF(admin), SBUF_STR("ADMIN")) != 20) AMM_ROLLBACK("amm: CFGUPDATE no ADMIN param.");
        if (!BUFFER_EQUAL_20(sender, admin)) AMM_ROLLBACK("amm: CFGUPDATE admin only.");
        /* tcfg buffer was loaded above (or zero-init if absent). Merge new
           values from named otxn_params into the corresponding offsets,
           then write the full slot back. */
          /* AUDIT #10 + #156: distinguish absent (DOESNT_EXIST -> keep prior value)
             from present-but-wrong-width (reject). The 16B read buffer reports the
             true length for widths <= 16; #156: a param LARGER than 16B returns
             TOO_SMALL (negative) and must ALSO be rejected, not mistaken for absence
             — so the guard is `_pl != EXPECTED && _pl != DOESNT_EXIST` (any non-exact
             present width, in- or over-buffer, rolls back). Absent/correct unchanged. */
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("FEEBPS"));   if (_pl != 4 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==4) { for (int _i=0; AMM_GUARD(4), _i<4; ++_i) tcfg[0+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("DAO_BPS"));  if (_pl != 4 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==4) { for (int _i=0; AMM_GUARD(4), _i<4; ++_i) tcfg[4+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("DAO_MIN"));  if (_pl != 8 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==8) { for (int _i=0; AMM_GUARD(8), _i<8; ++_i) tcfg[8+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("MAX_RXAH")); if (_pl != 8 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==8) { for (int _i=0; AMM_GUARD(8), _i<8; ++_i) tcfg[16+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("MAX_RIOU")); if (_pl != 8 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==8) { for (int _i=0; AMM_GUARD(8), _i<8; ++_i) tcfg[24+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("MAX_TOTX")); if (_pl != 8 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==8) { for (int _i=0; AMM_GUARD(8), _i<8; ++_i) tcfg[32+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("MAX_TOTY")); if (_pl != 8 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==8) { for (int _i=0; AMM_GUARD(8), _i<8; ++_i) tcfg[40+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("MINXAH"));   if (_pl != 8 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==8) { for (int _i=0; AMM_GUARD(8), _i<8; ++_i) tcfg[48+_i] = b[_i]; } }
          { uint8_t b[16]; int64_t _pl = otxn_param(SBUF(b), SBUF_STR("MINIOU"));   if (_pl != 8 && _pl != DOESNT_EXIST) AMM_ROLLBACK("amm: CFG malformed param."); if (_pl==8) { for (int _i=0; AMM_GUARD(8), _i<8; ++_i) tcfg[56+_i] = b[_i]; } }
        if (state_set(tcfg, 64, SBUF(tcfg_key)) != 64) AMM_ROLLBACK("amm: CFG write.");
        AMM_ACCEPT("amm: CFG updated.");
    }

    /* ================================================================ */
    /*  CFGRESET — clear all tunable overrides; fall back to install     */
    /* ================================================================ */
    if (is_cfgreset) {
        uint8_t admin[20]; AMM_ZERO(admin, 20);
        if (hook_param(SBUF(admin), SBUF_STR("ADMIN")) != 20) AMM_ROLLBACK("amm: CFGRESET no ADMIN param.");
        if (!BUFFER_EQUAL_20(sender, admin)) AMM_ROLLBACK("amm: CFGRESET admin only.");
        (void)state_set(0, 0, SBUF(tcfg_key));
        AMM_ACCEPT("amm: CFG reset.");
    }

    /* ================================================================ */
    /*  DBPSUPD — admin-only DAO_BPS update (single-field CFGSET).        */
    /*  Unified vocabulary across products; written by Gov ptype 11.      */
    /* ================================================================ */
    if (is_dbpsupd) {
        uint8_t admin[20]; AMM_ZERO(admin, 20);
        if (hook_param(SBUF(admin), SBUF_STR("ADMIN")) != 20) AMM_ROLLBACK("amm: DBPSUPD no ADMIN param.");
        if (!BUFFER_EQUAL_20(sender, admin)) AMM_ROLLBACK("amm: DBPSUPD admin only.");
        uint8_t b4[4];
        if (otxn_param(SBUF(b4), SBUF_STR("DAO_BPS")) != 4) AMM_ROLLBACK("amm: DBPSUPD no DAO_BPS.");
        uint32_t new_bps = UINT32_FROM_BUF(b4);
        if (new_bps > 10000U) new_bps = 10000U;
        /* tcfg+4 = DAO_BPS slot (AMM CFGSET layout). */
        UINT32_TO_BUF(tcfg + 4, new_bps);
        if (state_set(tcfg, 64, SBUF(tcfg_key)) != 64) AMM_ROLLBACK("amm: DBPSUPD write.");
        AMM_ACCEPT("amm: DAO_BPS updated.");
    }

    /* ================================================================ */
    /*  EXEC — apply ptype 15 (AMM CFG via vote).                         */
    /*  Permissionless after Core's quorum/council verdict (gv[53]==3).   */
    /*  Closes pre-blackhole hole: FEEBPS + caps/mins were admin-only.    */
    /*  PDAT: 1B field + 8B value. Field map (mirrors CFGSET keys):        */
    /*    1 = FEEBPS, 2 = DAO_MIN, 3 = MAX_RXAH, 4 = MAX_RIOU,             */
    /*    5 = MAX_TOTX, 6 = MAX_TOTY, 7 = MINXAH, 8 = MINIOU              */
    /*  DAO_BPS (tcfg+4) intentionally omitted — already covered by ptype */
    /*  11 (DBPSUPD). No per-PID applied flag: re-EXEC writes same value  */
    /*  idempotently; saves ~120 worst-case-guard inst to stay under the  */
    /*  65535 ceiling. Senders pay their own fee, so spam is self-priced. */
    /* ================================================================ */
    if (is_exec) {
        uint8_t corens_e[32];
        if (hook_param(SBUF(corens_e), SBUF_STR("CORENS")) != 32) AMM_ACCEPT("amm: EXEC no CORENS.");
        uint8_t dao_dest_e[20];
        if (hook_param(SBUF(dao_dest_e), SBUF_STR("DAO_DEST")) != 20) AMM_ACCEPT("amm: EXEC no DAO_DEST.");
        uint8_t pb[8];
        if (otxn_param(SBUF(pb), SBUF_STR("PID")) != 8) AMM_ACCEPT("amm: EXEC no PID.");

        uint8_t gk[32]; AMM_ZERO(gk, 32); gk[0] = 0x14U;
        for (int _i = 0; AMM_GUARD(8), _i < 8; ++_i) gk[1 + _i] = pb[_i];
        /* gv must fit the FULL 80B Core gov record — state_foreign returns
           negative if out_len < actual state size. ZERO skipped (state_foreign
           populates the entire 80B on success; on failure we early-accept and
           never read gv) to stay under the 65535 worst-case guard ceiling. */
        uint8_t gv[80];
        if (state_foreign(gv, 80, SBUF(gk), SBUF(corens_e), SBUF(dao_dest_e)) < 0)
            AMM_ACCEPT("amm: EXEC no prop.");

        if (gv[0] != 15) AMM_ACCEPT("amm: EXEC ptype not for AMM.");
        if (gv[53] != 3) AMM_ACCEPT("amm: EXEC not approved (or already final).");

        uint8_t fld = gv[1];
        uint64_t val = UINT64_FROM_BUF(gv + 2);
        if (fld == 1) {
            if (val > 1000ULL) val = 1000ULL;
            UINT32_TO_BUF(tcfg + 0, (uint32_t)val);
        } else if (fld >= 2 && fld <= 8) {
            UINT64_TO_BUF(tcfg + ((uint32_t)(fld - 1U) * 8U), val);
        } else AMM_ROLLBACK("amm: ptype15 field.");

        if (state_set(tcfg, 64, SBUF(tcfg_key)) != 64) AMM_ROLLBACK("amm: ptype15 w.");
        AMM_ACCEPT("amm: EXEC ptype15 CFG set.");
    }

    /* ================================================================ */
    /*  ADD — two-step pair liquidity                                    */
    /* ================================================================ */
    if (is_add)
    {
        if (is_invoke) AMM_ROLLBACK("amm: ADD needs XAH or IOU payment.");
        /* anti-dust — BITWISE flat conditions (no && nesting, depth budget):
           the dual-Remit path checks BOTH legs; Payment paths check their
           single leg as before (dual ⇒ is_xah_in==0, so the IOU check
           already covers dual). */
        if ((uint32_t)(is_xah_in | is_dual_in) & (uint32_t)(in_xah_drops < min_xah))
            AMM_ROLLBACK("amm: ADD XAH below MINXAH.");
        if ((uint32_t)(is_xah_in == 0) & (uint32_t)(in_iou_micro < min_iou))
            AMM_ROLLBACK("amm: ADD IOU below MINIOU.");
        /* v7-exp: a parked half-fill must be resolved on the Payment path
           first — mixing it with a single-Remit dual ADD would misroute
           the pairing/counter bookkeeping. */
        if ((uint32_t)is_dual_in & (uint32_t)(pre_pend_r == AMM_PEND_LEN))
            AMM_ROLLBACK("amm: pending half-fill exists, finish it first.");

        /* Reuse the pending state loaded up-front for the YIELD preludes.
           v7-exp: dual-Remit ADDs never stash — both legs are in THIS tx. */
        if (!is_dual_in && pre_pend_r != AMM_PEND_LEN)
        {
            /* No pending — stash this side and wait for the pair. */
            uint8_t pend_val[AMM_PEND_LEN];
            AMM_ZERO(pend_val, AMM_PEND_LEN);
            pend_val[0] = is_xah_in ? AMM_PEND_SIDE_XAH : AMM_PEND_SIDE_IOU;
            UINT64_TO_BUF(pend_val + 1, is_xah_in ? in_xah_drops : in_iou_micro);
            if (state_set(pend_val, AMM_PEND_LEN, SBUF(pend_key)) != AMM_PEND_LEN)
                AMM_ROLLBACK("amm: pending write failed.");
            /* Bump global pending counter on the stashed side. YIELD reads
               cumPendXah/cumPendIou to know stash totals so a different
               sender's future tx won't absorb them as "untracked yield".
               cfg_val already holds current reserves/fees/dao (loaded at
               hook entry, refreshed by YIELD if it ran), so we only write
               the field that changed. */
            if (is_xah_in){
                if (cumPendXah > (~(uint64_t)0) - in_xah_drops)
                    AMM_ROLLBACK("amm: pending counter overflow X.");
                cumPendXah += in_xah_drops;
                UINT64_TO_BUF(cfg_val + AMM_CFG_PENDXAH, cumPendXah);
            } else {
                if (cumPendIou > (~(uint64_t)0) - in_iou_micro)
                    AMM_ROLLBACK("amm: pending counter overflow Y.");
                cumPendIou += in_iou_micro;
                UINT64_TO_BUF(cfg_val + AMM_CFG_PENDIOU, cumPendIou);
            }
            if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
                AMM_ROLLBACK("amm: cfg write failed (stash).");
            AMM_ACCEPT("amm: ADD first side stashed.");
        }

        uint8_t pend_side = pre_pend_side;
        uint64_t pend_amt = pre_pend_amt;

        /* v7-exp: BRANCHLESS leg routing (replaces the if/else-if chain —
           each else-if nests one block deeper in wasm and the hook sits at
           the 16-level ceiling; this form is flatter than the original).
           Exactly one of the three match flags is 1:
             is_dual_in  — single-Remit dual ADD (both legs in THIS tx)
             m_xah_pend  — stashed XAH leg + inbound IOU leg
             m_iou_pend  — stashed IOU leg + inbound XAH leg
           A2 fix preserved: same-side resend (no flag set) ROLLS BACK so
           the second amount returns to the sender via tx unwind. */
        uint32_t m_xah_pend = (uint32_t)((pend_side == AMM_PEND_SIDE_XAH) & (is_xah_in == 0) & (is_dual_in == 0));
        uint32_t m_iou_pend = (uint32_t)((pend_side == AMM_PEND_SIDE_IOU) & (is_xah_in != 0) & (is_dual_in == 0));
        if (((uint32_t)is_dual_in | m_xah_pend | m_iou_pend) == 0)
            AMM_ROLLBACK("amm: pending side already set, send the other side.");
        uint64_t xah_in = (uint64_t)(is_dual_in | m_iou_pend) * in_xah_drops
                        + (uint64_t)m_xah_pend * pend_amt;
        uint64_t iou_in = (uint64_t)(is_dual_in | m_xah_pend) * in_iou_micro
                        + (uint64_t)m_iou_pend * pend_amt;

        /* Clear pending + decrement the global pending counter — FLAT,
           guarded on !is_dual_in (dual ADDs never had a stash). The stash
           side is becoming part of reserveXah/reserveIou via the ADD body
           below. Clamp at 0 so an under-seeded counter (post-upgrade,
           before the DAO RESYNC-CPXH heal) can't underflow into u64-max. */
        if (is_dual_in == 0)
            state_set(0, 0, SBUF(pend_key));
        if ((uint32_t)(is_dual_in == 0) & (uint32_t)(pend_side == AMM_PEND_SIDE_XAH))
            cumPendXah = (cumPendXah >= pend_amt) ? (cumPendXah - pend_amt) : 0;
        if ((uint32_t)(is_dual_in == 0) & (uint32_t)(pend_side != AMM_PEND_SIDE_XAH))
            cumPendIou = (cumPendIou >= pend_amt) ? (cumPendIou - pend_amt) : 0;

        /* Compute minted shares. */
        uint64_t minted = 0;
        uint64_t donated_xah = 0;
        uint64_t donated_iou = 0;
        /* Snapshot pre-mint totalShares: needed below to decide whether
           YIELD already absorbed the deposit. YIELD-XAH/IOU only run when
           totalShares > 0; on bootstrap they skip and we must add the
           deposit ourselves at the "Update reserves" step. */
        uint64_t totalShares_pre_mint = totalShares;

        if (totalShares == 0 || reserveXah == 0 || reserveIou == 0)
        {
            /* Bootstrap: safe-but-unfair rule. TRACE a warning. */
            TRACESTR("amm: bootstrap LP using xah_in+iou_in rule (non-sqrt).");
            if (xah_in > (~(uint64_t)0) - iou_in)
                AMM_ROLLBACK("amm: bootstrap overflow.");
            minted = xah_in + iou_in;
        }
        else
        {
            /* Post-cumFee-fix: the YIELD preludes now exclude both this
               txn's inbound (in_xah_drops / in_iou_micro) AND any prior-
               txn pending-ADD stash (pre_pend_amt on the matching side)
               from their tracked totals before comparing to ledger. So
               YIELD does NOT pre-absorb either side of the deposit;
               reserveXah/reserveIou in locals already equal R_x_old /
               R_y_old. Use them directly as denominators. The "Update
               reserves" step below now adds xah_in / iou_in
               unconditionally (guard removed) so reserves land at
               R_x_old + xah_in / R_y_old + iou_in exactly once. */
            uint64_t pre_rx = reserveXah;
            uint64_t pre_ry = reserveIou;
            /* AUDIT #6 — removed the unreachable zombie fallback that lived here.
               This else branch is only entered when the outer guard
               `if (totalShares==0 || reserveXah==0 || reserveIou==0)` was FALSE,
               i.e. reserveXah!=0 && reserveIou!=0 — so pre_rx/pre_ry are already
               proven non-zero and the old `if (pre_rx==0 || pre_ry==0)` body
               could never execute. The zombie state (shares>0, reserves 0 after
               a RESYNC) is handled by that outer bootstrap branch. Dead code
               removed; also frees wasm nesting depth. */
            uint64_t sx = 0, sy = 0;
            AMM_MULDIV(sx, xah_in, totalShares, pre_rx);
            AMM_MULDIV(sy, iou_in, totalShares, pre_ry);
            if (sx == AMM_MULDIV_OVF || sy == AMM_MULDIV_OVF)
                AMM_ROLLBACK("amm: shares math overflow.");
            if (sx <= sy)
            {
                minted = sx;
                uint64_t used_iou = 0;
                AMM_MULDIV(used_iou, minted, pre_ry, totalShares);
                if (used_iou != AMM_MULDIV_OVF && used_iou < iou_in)
                    donated_iou = iou_in - used_iou;
            }
            else
            {
                minted = sy;
                uint64_t used_xah = 0;
                AMM_MULDIV(used_xah, minted, pre_rx, totalShares);
                if (used_xah != AMM_MULDIV_OVF && used_xah < xah_in)
                    donated_xah = xah_in - used_xah;
            }
            if (donated_xah > 0) TRACEVAR(donated_xah);
            if (donated_iou > 0) TRACEVAR(donated_iou);
        }

        /* AUDIT #6 — `add_post_math:` label removed with the dead zombie goto. */
        if (minted == 0)
            AMM_ROLLBACK("amm: zero shares minted.");

        /* Update reserves + total shares. */
        if (reserveXah > (~(uint64_t)0) - xah_in)
            AMM_ROLLBACK("amm: reserve overflow X.");
        if (reserveIou > (~(uint64_t)0) - iou_in)
            AMM_ROLLBACK("amm: reserve overflow Y.");
        /* Total pool cap. 0 = uncapped. Caps the protocol's total reserve
           growth from new ADDs. Useful as a hard ceiling on protocol-wide
           exposure during early deployment. */
        /* v7-exp: branchless (operands side-effect-free) — common ADD path. */
        if (((uint32_t)(max_tot_x > 0) & (uint32_t)((reserveXah + xah_in) > max_tot_x)) != 0)
            AMM_ROLLBACK("amm: ADD over total MAX_TOTX cap.");
        if (((uint32_t)(max_tot_y > 0) & (uint32_t)((reserveIou + iou_in) > max_tot_y)) != 0)
            AMM_ROLLBACK("amm: ADD over total MAX_TOTY cap.");

        /* Per-user deposit cap. 0 = uncapped. Caps the XAH/IOU equivalent
           value of THIS user's LP position. Resolves user's current LP
           share count from:
             (a) tokenized: read sender's ALP trustline balance via
                 KEYLET_LINE(sender, hook_acc, amm_lp_cur). Convert XFL
                 to micro-units. Then convert to XAH/IOU equivalent via
                 share × reserve / totalShares.
             (b) legacy: state lookup at lp_key.
           Safety throttle for early deployment. Set 0 once battle-tested. */
        if (max_rxah > 0 || max_riou > 0) {
            uint64_t user_lp = 0;
            if (lp_tokenized) {
                /* Read sender's ALP trustline balance. */
                uint8_t _alpk[34];
                if (util_keylet(SBUF(_alpk), KEYLET_LINE,
                                sender, 20, hook_acc, 20, amm_lp_cur, 20) == 34
                    && slot_set(SBUF(_alpk), 13) == 13
                    && slot_subfield(13, sfBalance, 13) == 13) {
                    uint8_t _alpb[48];
                    int64_t _alen = slot(SBUF(_alpb), 13);
                    if (_alen == 8 || _alen == 48) {
                        uint64_t _alp_raw = UINT64_FROM_BUF(_alpb);
                        int64_t _alp_xfl = (int64_t)(_alp_raw ^ 0x8000000000000000ULL);
                        if (_alp_xfl != 0) {
                            int64_t _alp_micro = float_int(_alp_xfl, 6, 1);
                            if (_alp_micro > 0) user_lp = (uint64_t)_alp_micro;
                        }
                    }
                }
                /* No trustline (slot_set fails) -> first-time depositor,
                   user_lp stays 0. */
            } else {
                uint8_t lpv_chk[8]; AMM_ZERO(lpv_chk, 8);
                if (state(lpv_chk, 8, SBUF(lp_key)) == 8) user_lp = UINT64_FROM_BUF(lpv_chk);
            }
            if (user_lp > 0 && totalShares > 0) {
                if (max_rxah > 0) {
                    uint64_t userXah;
                    AMM_MULDIV(userXah, user_lp, reserveXah, totalShares);
                    /* MULDIV overflow MUST rollback, not fall back to 0.
                       Falling back to 0 makes (0 + xah_in > max_rxah) the
                       only test, silently letting an arithmetically-
                       overflowing user past the per-user cap. */
                    if (userXah == AMM_MULDIV_OVF)
                        AMM_ROLLBACK("amm: per-user cap math overflow (XAH).");
                    if (userXah + xah_in > max_rxah) AMM_ROLLBACK("amm: ADD over per-user MAX_RXAH cap.");
                }
                if (max_riou > 0) {
                    uint64_t userIou;
                    AMM_MULDIV(userIou, user_lp, reserveIou, totalShares);
                    if (userIou == AMM_MULDIV_OVF)
                        AMM_ROLLBACK("amm: per-user cap math overflow (IOU).");
                    if (userIou + iou_in > max_riou) AMM_ROLLBACK("amm: ADD over per-user MAX_RIOU cap.");
                }
            } else {
                /* First deposit by this user: just check the deposit itself. */
                if (max_rxah > 0 && xah_in > max_rxah) AMM_ROLLBACK("amm: ADD over per-user MAX_RXAH cap.");
                if (max_riou > 0 && iou_in > max_riou) AMM_ROLLBACK("amm: ADD over per-user MAX_RIOU cap.");
            }
        }
        /* Update reserves unconditionally. Post-cumFee-fix the YIELD
           preludes no longer absorb the deposit (current-txn inbound and
           any prior-txn pending stash are excluded from their tracked
           totals), so reserveXah/reserveIou in locals are still at
           R_x_old/R_y_old here regardless of whether we're on the
           bootstrap branch or the non-bootstrap branch. Adding xah_in /
           iou_in here lands them at R_x_old + xah_in / R_y_old + iou_in
           exactly once and keeps the post-commit state consistent so
           anyone reading cfg between this commit and the next YIELD
           sees correct reserves. */
        reserveXah += xah_in;
        reserveIou += iou_in;
        /* ---- receivability PRE-CHECK (#12 fix — fail-closed, ATOMIC rollback) ----
           The tokenized ADD bumps totalShares and then mints ALP to `sender` via
           Remit. If that emit applies with a `tec` (recipient has DepositAuth, or
           a FROZEN ALP trustline), cbak is invoked with ctx==0 — indistinguishable
           from success — so it never reverts the bump, leaving totalShares inflated
           against an LP that was never delivered (issue #12). Catch the two
           predictable blockers HERE, before the bump/emit, and roll the whole ADD
           back atomically. A MISSING ALP line is NOT blocked — the payout is a
           Remit that auto-creates it (the pool pays the reserve). Non-tokenized ADD
           writes state only (no emit), so it needs no pre-check. Rollback-only:
           this block never writes state and never emits. Slots 20/22 are free
           (ADD uses 9/11/13). */
        /* AMM_TEST_NO_PRECHECK: compile-time switch to DISABLE the up-front
           pre-check so the cbak-verify backstop can be exercised directly on
           testnet (a DepositAuth depositor then reaches the emit → tec → cbak).
           NEVER define for production — the pre-check protects the depositor's
           deposit (atomic rollback), while cbak-verify only protects the pool's
           share accounting. Default (undefined) keeps both. */
#ifndef AMM_TEST_NO_PRECHECK
        if (lp_tokenized) {
            uint32_t _padf = 0;
            uint8_t _pakl[34];
            if (util_keylet(SBUF(_pakl), KEYLET_ACCOUNT, sender, 20, 0, 0, 0, 0) == 34
                && slot_set(SBUF(_pakl), 20) == 20
                && slot_subfield(20, sfFlags, 20) == 20) {
                uint8_t _pfb[4];
                if (slot(SBUF(_pfb), 20) == 4) _padf = UINT32_FROM_BUF(_pfb);
            }
            if (_padf & 0x01000000U)   /* lsfDepositAuth */
                AMM_ROLLBACK("amm: recipient has DepositAuth — remove it to add liquidity.");
            uint8_t _plk[34];
            if (util_keylet(SBUF(_plk), KEYLET_LINE, sender, 20, hook_acc, 20, amm_lp_cur, 20) == 34
                && slot_set(SBUF(_plk), 22) == 22
                && slot_subfield(22, sfFlags, 22) == 22) {
                uint8_t _plf[4];
                if (slot(SBUF(_plf), 22) == 4
                    && (UINT32_FROM_BUF(_plf) & 0x00C00000U))   /* lsfLowFreeze | lsfHighFreeze */
                    AMM_ROLLBACK("amm: your ALP trustline is frozen.");
            }
        }
#endif

        if (totalShares > (~(uint64_t)0) - minted)
            AMM_ROLLBACK("amm: totalShares overflow.");
        totalShares += minted;

        /* Credit per-LP shares. When AMM_LP_CUR is set, emit ALP IOU
           to sender via Remit (combining any existing state-based
           shares = auto-migrate). When tokenization is OFF, keep
           state-based path. Caps are now compatible with tokenization
           because the per-user cap check above resolves the user's LP
           balance from the trustline via KEYLET_LINE. */
        uint8_t lp_val[8];
        AMM_ZERO(lp_val, 8);
        uint64_t cur_lp = 0;
        if (state(lp_val, 8, SBUF(lp_key)) == 8)
            cur_lp = UINT64_FROM_BUF(lp_val);
        if (cur_lp > (~(uint64_t)0) - minted)
            AMM_ROLLBACK("amm: lp share overflow.");
        cur_lp += minted;
        if (lp_tokenized) {
            /* Emit ALP IOU = (existing state shares + newly minted) and
               clear any legacy state. Auto-migration. */
            int64_t lp_xfl = float_set(-6, (int64_t)cur_lp);
            if (lp_xfl < 0) AMM_ROLLBACK("amm: ALP xfl.");
            uint32_t fls_lp = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_FLS_OUT, fls_lp);
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_LLS_OUT, fls_lp + 4U);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_ACCT_OUT, hook_acc);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_DEST_OUT, sender);
            if (etxn_details(amm_remit_tx + AMM_REMIT_EMIT_OUT, AMM_REMIT_EMIT_LEN) != AMM_REMIT_EMIT_LEN)
                AMM_ROLLBACK("amm: ALP details.");
            if (float_sto(amm_remit_tx + AMM_REMIT_AMT_OUT, 49, amm_lp_cur, 20, hook_acc, 20, lp_xfl, sfAmount) != 49)
                AMM_ROLLBACK("amm: ALP sto.");
            int64_t fee_lp = etxn_fee_base(amm_remit_tx, AMM_REMIT_SIZE);
            if (fee_lp < 0) AMM_ROLLBACK("amm: ALP fee.");
            amm_remit_tx[AMM_REMIT_FEE_OUT + 0] = 0x40U | ((uint8_t)((fee_lp >> 56) & 0x3FU));
            amm_remit_tx[AMM_REMIT_FEE_OUT + 1] = (uint8_t)((fee_lp >> 48) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 2] = (uint8_t)((fee_lp >> 40) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 3] = (uint8_t)((fee_lp >> 32) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 4] = (uint8_t)((fee_lp >> 24) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 5] = (uint8_t)((fee_lp >> 16) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 6] = (uint8_t)((fee_lp >>  8) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 7] = (uint8_t)( fee_lp        & 0xFFU);
            uint8_t eh_lp[32];
            if (emit(SBUF(eh_lp), SBUF(amm_remit_tx)) < 0)
                AMM_ROLLBACK("amm: ALP emit.");
            /* cbak protection: write pending entry keyed by emit hash so
               that if the emitted Remit fails post-commit, cbak() can
               revert the totalShares increment. ADD is the only state-
               affecting emit path (REM's burn is atomic on inbound). */
            /* cbak-verify pending: minted + depositor + pre-mint ALP balance, so
               cbak can revert totalShares on non-delivery (tec) by re-reading the
               depositor's ALP line. pre-read is the depositor's balance NOW (the
               mint applies in a later ledger), slots 20/22 free post pre-check. */
            uint64_t pre_alp_raw = 0;
            AMM_READ_ALP_RAW(pre_alp_raw, sender, hook_acc, amm_lp_cur, 20, 22);
            uint8_t pend_v[AMM_PEND_LEN_CBAK];
            pend_v[0] = AMM_PEND_TAG_ADD;
            UINT64_TO_BUF(pend_v + AMM_PC_MINTED, minted);
            AMM_COPY_20(pend_v + AMM_PC_USER, sender);
            UINT64_TO_BUF(pend_v + AMM_PC_PRERAW, pre_alp_raw);
            if (state_set(pend_v, AMM_PEND_LEN_CBAK, SBUF(eh_lp)) != AMM_PEND_LEN_CBAK)
                AMM_ROLLBACK("amm: ADD pending write failed.");
            /* Clear legacy state if it had any */
            if (cur_lp - minted > 0) state_set(0, 0, SBUF(lp_key));
        } else {
            UINT64_TO_BUF(lp_val, cur_lp);
            if (state_set(lp_val, 8, SBUF(lp_key)) != 8)
                AMM_ROLLBACK("amm: lp write failed.");
        }

        /* Persist config. Includes cumPendXah/Iou because the stash that
           was just consumed at L1441 decremented them in locals. */
        UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_PENDXAH, cumPendXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_PENDIOU, cumPendIou);
        if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
            AMM_ROLLBACK("amm: cfg write failed.");

        TRACEVAR(minted);
        AMM_ACCEPT_AFTER_EMIT("amm: ADD liquidity minted shares.");
    }

    /* ================================================================ */
    /*  REM — burn shares, emit XAH + IOU back                           */
    /* ================================================================ */
    if (is_rem)
    {
        /* RH-REF: mirror is_swap init guard; refuse REM against an
           uninitialized or emptied pool instead of relying on the
           AMM_MULDIV denom==0 sentinel to catch it downstream. */
        if (reserveXah == 0 || reserveIou == 0 || totalShares == 0)
            AMM_ROLLBACK("amm: REM pool not initialized.");

        /* v3: two REM paths — tokenized (inbound ALP IOU = burn quantity)
           or legacy (XAH dust + SHARES param + state-based shares). */
        uint64_t burn = 0;
        uint64_t cur_lp = 0;
        int legacy_path = 0;
        if (is_lp_iou_in) {
            /* Tokenized REM: inbound ALP IOU is the burn quantity. The
               hook receiving its own IOU = automatic burn (issuer's
               liability cancels). No state lookup needed. */
            burn = in_iou_micro;
            if (burn == 0) AMM_ROLLBACK("amm: REM zero ALP.");
            cur_lp = burn; /* logically "had at least burn"; no state to check */
        } else {
            /* Legacy REM: Invoke (canonical) OR XAH dust + SHARES param.
               Both feed the state-based shares path. */
            if (!is_invoke && !is_xah_in) AMM_ROLLBACK("amm: REM requires ALP IOU, Invoke, or XAH dust.");
            uint8_t sh_b[8];
            if (otxn_param(SBUF(sh_b), SBUF_STR("SHARES")) != 8)
                AMM_ROLLBACK("amm: REM missing SHARES.");
            burn = UINT64_FROM_BUF(sh_b);
            if (burn == 0) AMM_ROLLBACK("amm: REM zero SHARES.");
            uint8_t lp_val[8]; AMM_ZERO(lp_val, 8);
            if (state(lp_val, 8, SBUF(lp_key)) != 8)
                AMM_ROLLBACK("amm: no LP shares.");
            cur_lp = UINT64_FROM_BUF(lp_val);
            if (burn > cur_lp) AMM_ROLLBACK("amm: REM shares exceeds balance.");
            legacy_path = 1;
            /* Add the dust back to the XAH reserve first. */
            if (reserveXah > (~(uint64_t)0) - in_xah_drops)
                AMM_ROLLBACK("amm: reserve overflow dust.");
            reserveXah += in_xah_drops;
        }
        if (totalShares == 0) AMM_ROLLBACK("amm: pool empty.");
        /* Explicit burn-vs-totalShares guard. The downstream `xah_out >
           reserveXah` check at line ~1696 catches this indirectly, but
           relying on multiplication+division to surface a malformed burn
           is fragile across future reserve-formula changes. Make the
           precondition explicit so a stray write that lets cur_lp >
           totalShares can never propagate to a 100%+ withdrawal. */
        if (burn > totalShares) AMM_ROLLBACK("amm: REM burn exceeds totalShares.");

        uint64_t xah_out = 0, iou_out = 0;
        AMM_MULDIV(xah_out, burn, reserveXah, totalShares);
        AMM_MULDIV(iou_out, burn, reserveIou, totalShares);
        if (xah_out == AMM_MULDIV_OVF || iou_out == AMM_MULDIV_OVF)
            AMM_ROLLBACK("amm: REM math overflow.");
        /* Dust-burn donation guard. If burn is tiny relative to reserves,
           integer-floored AMM_MULDIV can yield xah_out=iou_out=0. Without
           this guard the LP loses their shares (totalShares decremented)
           but receives nothing — silent donation to remaining LPs. Reject
           cleanly so dust-burners aren't unintentionally robbed. */
        if (xah_out == 0 && iou_out == 0)
            AMM_ROLLBACK("amm: REM dust burn — no proportional output.");
        if (xah_out > reserveXah || iou_out > reserveIou)
            AMM_ROLLBACK("amm: REM underflow.");

        /* Don't double-pay the dust the LP just sent (legacy only —
           tokenized REM has no dust). */
        uint64_t xah_emit;
        if (legacy_path) {
            xah_emit = (xah_out > in_xah_drops) ? (xah_out - in_xah_drops) : 0;
        } else {
            xah_emit = xah_out;
        }

        /* AUDIT #5 (net-payout guard): the gross guard above rejects
           xah_out==0 && iou_out==0, but on the legacy (XAH-dust) path the
           XAH actually paid is xah_emit = xah_out - in_xah_drops. A dust-
           sized withdraw can pass the gross guard (xah_out>0) yet net to
           xah_emit==0, and with iou_out==0 the LP burns shares while nothing
           is emitted. Reject BEFORE any reserve/share burn or emit so the
           rollback undoes everything. */
        if (xah_emit == 0 && iou_out == 0)
            AMM_ROLLBACK("amm: REM net payout zero.");

        reserveXah -= xah_out;
        reserveIou -= iou_out;
        totalShares -= burn;
        cur_lp -= burn;

        TRACEVAR(xah_out);
        TRACEVAR(iou_out);
        TRACEVAR(xah_emit);

        /* etxn_reserve(5) called once at top of hook — covers REM's 2
           emits + 2 offer-emits with slack. */

        /* ---- emit native XAH Payment ---- */
        if (xah_emit > 0)
        {
            uint32_t fls_p = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(amm_pay_tx + AMM_PAY_FLS_OUT, fls_p);
            UINT32_TO_BUF(amm_pay_tx + AMM_PAY_LLS_OUT, fls_p + 4U);
            AMM_COPY_20(amm_pay_tx + AMM_PAY_ACCT_OUT, hook_acc);
            AMM_COPY_20(amm_pay_tx + AMM_PAY_DEST_OUT, sender);
            AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_AMT_OUT, xah_emit);
            if (etxn_details(amm_pay_tx + AMM_PAY_EMIT_OUT, AMM_PAY_EMIT_LEN) != AMM_PAY_EMIT_LEN)
                AMM_ROLLBACK("amm: REM pay details.");
            int64_t fee_p = etxn_fee_base(amm_pay_tx, AMM_PAY_SIZE);
            if (fee_p < 0) AMM_ROLLBACK("amm: REM pay fee.");
            AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_FEE_OUT, (uint64_t)fee_p);
            uint8_t eh[32];
            if (emit(SBUF(eh), amm_pay_tx, AMM_PAY_SIZE) < 0)
                AMM_ROLLBACK("amm: emit XAH failed.");
        }

        /* ---- emit IOU via Remit (auto-creates trustline on LP) ---- */
        if (iou_out > 0)
        {
            int64_t xfl_r = float_set(-6, (int64_t)iou_out);
            if (xfl_r < 0) AMM_ROLLBACK("amm: REM xfl.");
            uint32_t fls_r = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_FLS_OUT, fls_r);
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_LLS_OUT, fls_r + 4U);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_ACCT_OUT, hook_acc);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_DEST_OUT, sender);
            if (etxn_details(amm_remit_tx + AMM_REMIT_EMIT_OUT, AMM_REMIT_EMIT_LEN) != AMM_REMIT_EMIT_LEN)
                AMM_ROLLBACK("amm: REM remit details.");
            if (float_sto(amm_remit_tx + AMM_REMIT_AMT_OUT, 49, cfg_cur, 20, cfg_issuer, 20, xfl_r, sfAmount) != 49)
                AMM_ROLLBACK("amm: REM remit sto.");
            int64_t fee_r = etxn_fee_base(amm_remit_tx, AMM_REMIT_SIZE);
            if (fee_r < 0) AMM_ROLLBACK("amm: REM remit fee.");
            amm_remit_tx[AMM_REMIT_FEE_OUT + 0] = 0x40U | ((uint8_t)((fee_r >> 56) & 0x3FU));
            amm_remit_tx[AMM_REMIT_FEE_OUT + 1] = (uint8_t)((fee_r >> 48) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 2] = (uint8_t)((fee_r >> 40) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 3] = (uint8_t)((fee_r >> 32) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 4] = (uint8_t)((fee_r >> 24) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 5] = (uint8_t)((fee_r >> 16) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 6] = (uint8_t)((fee_r >>  8) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 7] = (uint8_t)( fee_r        & 0xFFU);
            uint8_t eh2[32];
            if (emit(SBUF(eh2), SBUF(amm_remit_tx)) < 0)
                AMM_ROLLBACK("amm: REM remit emit.");
        }

        /* Persist LP state — only for legacy path. Tokenized REM had no
           state to update (the burn was the inbound IOU). */
        if (legacy_path) {
            uint8_t lp_persist[8]; AMM_ZERO(lp_persist, 8);
            if (cur_lp == 0) state_set(0, 0, SBUF(lp_key));
            else {
                UINT64_TO_BUF(lp_persist, cur_lp);
                state_set(lp_persist, 8, SBUF(lp_key));
            }
        }

        UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
        if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
            AMM_ROLLBACK("amm: cfg write failed (REM).");

        AMM_ACCEPT_AFTER_EMIT("amm: REM queued emits.");
    }

    /* ================================================================ */
    /*  MIGRATE — convert legacy state-based LP shares to ALP IOU       */
    /*  Permissionless: anyone can migrate any account's shares. Useful */
    /*  for cleanup after the protocol switches to tokenized LP.         */
    /*  Tx params:                                                       */
    /*    CMD : "MIGRATE"                                                */
    /*    ACCT: 20-byte account to migrate                               */
    /*  Reads ACCT's lp_key state, emits ALP IOU equal to the share     */
    /*  count to ACCT, clears the state. Idempotent (re-MIGRATE on a    */
    /*  cleared account no-ops).                                         */
    /* ================================================================ */
    if (is_migrate)
    {
        if (!lp_tokenized) AMM_ROLLBACK("amm: MIGRATE needs AMM_LP_CUR.");
        /* A1 fix: MIGRATE moves state-shares into ALP IOU, hiding them
           from the per-user cap. When caps are set, block MIGRATE so the
           cap remains enforceable. */
        if (max_rxah > 0 || max_riou > 0)
            AMM_ROLLBACK("amm: MIGRATE blocked while caps set.");
        uint8_t macct[20];
        if (otxn_param(SBUF(macct), SBUF_STR("ACCT")) != 20)
            AMM_ROLLBACK("amm: MIGRATE missing ACCT.");
        uint8_t mlp_key[32]; AMM_ZERO(mlp_key, 32); mlp_key[0] = 0x02U;
        AMM_COPY_20(mlp_key + 1, macct);
        uint8_t mlp_val[8]; AMM_ZERO(mlp_val, 8);
        if (state(mlp_val, 8, SBUF(mlp_key)) != 8)
            AMM_ACCEPT("amm: MIGRATE no-op (no state).");
        uint64_t shares = UINT64_FROM_BUF(mlp_val);
        if (shares == 0) {
            state_set(0, 0, SBUF(mlp_key));
            AMM_ACCEPT("amm: MIGRATE no-op (zero shares).");
        }
        /* Emit ALP IOU = shares to ACCT */
        int64_t mlp_xfl = float_set(-6, (int64_t)shares);
        if (mlp_xfl < 0) AMM_ROLLBACK("amm: MIGRATE xfl.");
        uint32_t mfls = (uint32_t)ledger_seq() + 1U;
        UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_FLS_OUT, mfls);
        UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_LLS_OUT, mfls + 4U);
        AMM_COPY_20(amm_remit_tx + AMM_REMIT_ACCT_OUT, hook_acc);
        AMM_COPY_20(amm_remit_tx + AMM_REMIT_DEST_OUT, macct);
        if (etxn_details(amm_remit_tx + AMM_REMIT_EMIT_OUT, AMM_REMIT_EMIT_LEN) != AMM_REMIT_EMIT_LEN)
            AMM_ROLLBACK("amm: MIGRATE details.");
        if (float_sto(amm_remit_tx + AMM_REMIT_AMT_OUT, 49, amm_lp_cur, 20, hook_acc, 20, mlp_xfl, sfAmount) != 49)
            AMM_ROLLBACK("amm: MIGRATE sto.");
        int64_t mfee = etxn_fee_base(amm_remit_tx, AMM_REMIT_SIZE);
        if (mfee < 0) AMM_ROLLBACK("amm: MIGRATE fee.");
        amm_remit_tx[AMM_REMIT_FEE_OUT + 0] = 0x40U | ((uint8_t)((mfee >> 56) & 0x3FU));
        amm_remit_tx[AMM_REMIT_FEE_OUT + 1] = (uint8_t)((mfee >> 48) & 0xFFU);
        amm_remit_tx[AMM_REMIT_FEE_OUT + 2] = (uint8_t)((mfee >> 40) & 0xFFU);
        amm_remit_tx[AMM_REMIT_FEE_OUT + 3] = (uint8_t)((mfee >> 32) & 0xFFU);
        amm_remit_tx[AMM_REMIT_FEE_OUT + 4] = (uint8_t)((mfee >> 24) & 0xFFU);
        amm_remit_tx[AMM_REMIT_FEE_OUT + 5] = (uint8_t)((mfee >> 16) & 0xFFU);
        amm_remit_tx[AMM_REMIT_FEE_OUT + 6] = (uint8_t)((mfee >>  8) & 0xFFU);
        amm_remit_tx[AMM_REMIT_FEE_OUT + 7] = (uint8_t)( mfee        & 0xFFU);
        uint8_t meh[32];
        if (emit(SBUF(meh), SBUF(amm_remit_tx)) < 0)
            AMM_ROLLBACK("amm: MIGRATE emit.");
        state_set(0, 0, SBUF(mlp_key));
        AMM_ACCEPT("amm: MIGRATE done.");
    }

    /* ================================================================ */
    /*  SWAP — constant product                                          */
    /* ================================================================ */
    if (is_swap)
    {
        if (is_invoke) AMM_ROLLBACK("amm: SWAP needs XAH or IOU payment.");
        if (reserveXah == 0 || reserveIou == 0 || totalShares == 0)
            AMM_ROLLBACK("amm: pool not initialized.");

        if (is_xah_in && in_xah_drops < min_xah)
            AMM_ROLLBACK("amm: SWAP XAH below MINXAH.");
        if (!is_xah_in && in_iou_micro < min_iou)
            AMM_ROLLBACK("amm: SWAP IOU below MINIOU.");

        uint8_t mo_b[8];
        uint64_t min_out = 0;
        if (otxn_param(SBUF(mo_b), SBUF_STR("MINOUT")) == 8)
            min_out = UINT64_FROM_BUF(mo_b);

        uint64_t in_amt = is_xah_in ? in_xah_drops : in_iou_micro;

        /* fee split — zero-fee path for the registered DAO account
           (DAO_DEST). When DAO routing is enabled and the swap sender is
           the DAO wallet, the swap executes at 0 bps. This is the
           "mean-reversion profit" path: the DAO rebalances through its
           own AMMs at no fee, capturing the full spread between current
           pool price and target weights. External traders still pay the
           configured FEEBPS. */
        int is_dao_sender = dao_enabled && BUFFER_EQUAL_20(sender, dao_dest);
        uint64_t fee_amt = 0;
        if (!is_dao_sender) {
            AMM_MULDIV(fee_amt, in_amt, (uint64_t)fee_bps, 10000ULL);
            if (fee_amt == AMM_MULDIV_OVF) AMM_ROLLBACK("amm: fee math overflow.");
            if (fee_amt > in_amt) fee_amt = in_amt;
        }
        uint64_t in_after = in_amt - fee_amt;

        /* Optional DAO fee routing. When dao_enabled, a configurable slice
           of fee_amt is diverted to the DAO escrow (not reserves); LPs
           receive pool_fee = fee_amt - dao_cut. Trader's in_after is
           unchanged — trader still pays the full fee. */
        uint64_t dao_cut = 0;
        uint64_t pool_fee = fee_amt;
        if (dao_enabled && fee_amt > 0)
        {
            AMM_MULDIV(dao_cut, fee_amt, (uint64_t)dao_bps, 10000ULL);
            if (dao_cut == AMM_MULDIV_OVF) AMM_ROLLBACK("amm: dao math overflow.");
            if (dao_cut > fee_amt) dao_cut = fee_amt;
            pool_fee = fee_amt - dao_cut;
        }

        uint64_t out_amt = 0;
        if (is_xah_in)
        {
            /* y_out = Ry - (Rx * Ry) / (Rx + in_after) */
            uint64_t denom = reserveXah + in_after;
            if (denom < reserveXah) AMM_ROLLBACK("amm: denom overflow.");
            uint64_t ry_new = 0;
            AMM_MULDIV(ry_new, reserveXah, reserveIou, denom);
            if (ry_new == AMM_MULDIV_OVF) AMM_ROLLBACK("amm: swap math overflow.");
            if (ry_new >= reserveIou) AMM_ROLLBACK("amm: swap non-positive.");
            out_amt = reserveIou - ry_new;
        }
        else
        {
            uint64_t denom = reserveIou + in_after;
            if (denom < reserveIou) AMM_ROLLBACK("amm: denom overflow.");
            uint64_t rx_new = 0;
            AMM_MULDIV(rx_new, reserveIou, reserveXah, denom);
            if (rx_new == AMM_MULDIV_OVF) AMM_ROLLBACK("amm: swap math overflow.");
            if (rx_new >= reserveXah) AMM_ROLLBACK("amm: swap non-positive.");
            out_amt = reserveXah - rx_new;
        }

        TRACEVAR(in_amt);
        TRACEVAR(fee_amt);
        TRACEVAR(out_amt);

        if (out_amt < min_out)
            AMM_ROLLBACK("amm: SWAP slippage.");

        /* update reserves — LP share of the fee stays in the pool, DAO
           share escrows separately (if enabled). reserveIn grows by
           (in_amt - dao_cut); dao_cut is 0 unless DAO routing is on. */
        uint64_t pool_in = in_amt - dao_cut;

        /* FEECCY=1 (IOU->XAH sell only): the DAO cut would naturally escrow in
           IOU (cumDaoIou). Instead book it in XAH into cumDaoXah, leaving
           cumDaoIou untouched, by charging the cut against the swap OUTPUT:
                 dcx = out_amt * fee_bps/10000 * dao_bps/10000
           This is the XAH value of the IOU cut (dao_cut) priced at the trade's
           own execution rate (out_amt per in_after) — i.e. dcx ~= dao_cut *
           (reserveXah-out_amt)/(reserveIou+in_amt), the constant-product-
           preserving conversion, to within the in_amt/in_after ratio (~fee_bps,
           sub-drop for realistic trades). review#5: this is exact only in the
           small-trade limit — dcx/dcx_ideal = (1-fee)*(1 + in_amt/reserveIou), so
           for a sell larger than ~the fee fraction of the IOU reserve it slightly
           OVER-books the DAO (a bounded, self-limiting order-of-slippage amount of
           XAH moves LP->DAO rather than staying with LPs). It is physically conserved
           (goes to the protocol DAO, never the trader) and the escrow stays exactly
           backed, so it is a small value drift, not a leak. LP per-share value is preserved to first order: mode 1
           puts the full input in the IOU reserve and removes dcx extra XAH from
           the XAH reserve, sliding along the same curve. The trader's XAH out
           (out_amt) is NOT touched. dcx==0 => fall back to mode-0 IOU booking.
           XAH-in buys already book XAH and are excluded. Constant divisors keep
           this plain u64 (no XFL, no __multi3), so the hook stays under the
           65535 worst-case instruction ceiling. Overflow-safe for the 100k
           XAH/IOU pool cap: out_amt<=1e11 => *fee_bps<=1e14 => *dao_bps<=1e14. */
        uint64_t dcx = 0;
        int dao_cut_xah = 0;
        if (feeccy == 1U && dao_cut > 0 && !is_xah_in) {
            /* review#7: guard both multiplies against u64 overflow (mirrors the
               offer-ladder deliver_xah_b guard at L578). fee_bps,dao_bps<=10000, so
               out_amt<=~0/10000 makes out_amt*fee_bps safe, and t1<=~0/10000 makes
               t1*dao_bps safe. Under the 100k-XAH pool cap both always pass (identical
               behavior); an uncapped pool with absurd reserves fails safe to dcx=0 ->
               the existing IOU-booking fallback below. */
            uint64_t t1 = 0;
            if (out_amt <= ((~(uint64_t)0) / 10000ULL))
                t1 = out_amt * (uint64_t)fee_bps / 10000ULL;       /* * fee_bps/10000 */
            if (t1 <= ((~(uint64_t)0) / 10000ULL))
                dcx = t1 * (uint64_t)dao_bps / 10000ULL;           /* * dao_bps/10000 */
            uint64_t rx_new = reserveXah - out_amt;                /* > 0 (curve guard) */
            if (dcx == 0 || dcx >= rx_new) dcx = 0;                /* fail-safe -> IOU booking */
            else dao_cut_xah = 1;
        }

        if (is_xah_in)
        {
            if (reserveXah > (~(uint64_t)0) - pool_in)
                AMM_ROLLBACK("amm: rX overflow.");
            reserveXah += pool_in;
            if (out_amt > reserveIou)
                AMM_ROLLBACK("amm: rY underflow.");
            reserveIou -= out_amt;
            if (cumFeeXah > (~(uint64_t)0) - pool_fee)
                cumFeeXah = ~(uint64_t)0;
            else
                cumFeeXah += pool_fee;
            if (dao_cut > 0)
            {
                if (cumDaoXah > (~(uint64_t)0) - dao_cut)
                    cumDaoXah = ~(uint64_t)0;
                else
                    cumDaoXah += dao_cut;
            }
        }
        else
        {
            /* mode 1 (dao_cut_xah): full input stays in IOU reserve, and the
               DAO cut is removed from the XAH side (out_amt + dcx) and escrowed
               as dcx into cumDaoXah. mode 0: pool_in into IOU reserve, out_amt
               out of XAH, dao_cut into cumDaoIou. */
            uint64_t iou_add = dao_cut_xah ? in_amt : pool_in;
            if (reserveIou > (~(uint64_t)0) - iou_add)
                AMM_ROLLBACK("amm: rY overflow.");
            reserveIou += iou_add;
            uint64_t xah_sub = dao_cut_xah ? (out_amt + dcx) : out_amt;
            if (xah_sub > reserveXah)
                AMM_ROLLBACK("amm: rX underflow.");
            reserveXah -= xah_sub;
            /* review#6 (telemetry, not a fund path): in mode 1 (dao_cut_xah) the
               DAO cut is taken from the XAH side (dcx), so the FULL fee_amt IOU
               actually stays with the LPs in reserveIou — yet cumFeeIou is credited
               only pool_fee (fee_amt - dao_cut), understating the lifetime LP IOU-fee
               stat by dao_cut. Left as-is on purpose: this counter feeds LP value/APR
               displays and changing its basis mid-life would create a discontinuity.
               To make it exact, credit fee_amt instead of pool_fee in the dao_cut_xah
               case (no fund impact either way). */
            if (cumFeeIou > (~(uint64_t)0) - pool_fee)
                cumFeeIou = ~(uint64_t)0;
            else
                cumFeeIou += pool_fee;
            if (dao_cut_xah)
            {
                /* FEECCY=1: DAO cut booked in XAH; cumDaoIou untouched. */
                if (cumDaoXah > (~(uint64_t)0) - dcx)
                    cumDaoXah = ~(uint64_t)0;
                else
                    cumDaoXah += dcx;
            }
            else if (dao_cut > 0)
            {
                if (cumDaoIou > (~(uint64_t)0) - dao_cut)
                    cumDaoIou = ~(uint64_t)0;
                else
                    cumDaoIou += dao_cut;
            }
        }

        /* Auto-emit DAO fees if threshold is met. */
        int dao_flush = (dao_enabled && dao_min > 0 && cumDaoXah >= dao_min) ? 1 : 0;
        /* etxn_reserve(5) at top of hook covers SWAP's 1 (XAH/IOU out)
           + up to 2 (DAO flush) + 2 (offers) = 5. */

        /* Emit swap output to sender. XAH-out = native Payment. IOU-out
           = Remit (auto-creates trustline on the trader). */
        if (is_xah_in)
        {
            /* output is IOU: emit via Remit */
            int64_t xfl_s = float_set(-6, (int64_t)out_amt);
            if (xfl_s < 0) AMM_ROLLBACK("amm: SWAP xfl.");
            uint32_t fls_s = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_FLS_OUT, fls_s);
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_LLS_OUT, fls_s + 4U);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_ACCT_OUT, hook_acc);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_DEST_OUT, sender);
            if (etxn_details(amm_remit_tx + AMM_REMIT_EMIT_OUT, AMM_REMIT_EMIT_LEN) != AMM_REMIT_EMIT_LEN)
                AMM_ROLLBACK("amm: SWAP remit details.");
            if (float_sto(amm_remit_tx + AMM_REMIT_AMT_OUT, 49, cfg_cur, 20, cfg_issuer, 20, xfl_s, sfAmount) != 49)
                AMM_ROLLBACK("amm: SWAP remit sto.");
            int64_t fee_s = etxn_fee_base(amm_remit_tx, AMM_REMIT_SIZE);
            if (fee_s < 0) AMM_ROLLBACK("amm: SWAP remit fee.");
            amm_remit_tx[AMM_REMIT_FEE_OUT + 0] = 0x40U | ((uint8_t)((fee_s >> 56) & 0x3FU));
            amm_remit_tx[AMM_REMIT_FEE_OUT + 1] = (uint8_t)((fee_s >> 48) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 2] = (uint8_t)((fee_s >> 40) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 3] = (uint8_t)((fee_s >> 32) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 4] = (uint8_t)((fee_s >> 24) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 5] = (uint8_t)((fee_s >> 16) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 6] = (uint8_t)((fee_s >>  8) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 7] = (uint8_t)( fee_s        & 0xFFU);
            uint8_t eh[32];
            if (emit(SBUF(eh), SBUF(amm_remit_tx)) < 0)
                AMM_ROLLBACK("amm: SWAP remit emit.");
        }
        else
        {
            /* output is XAH: native Payment (no trustline concern) */
            uint32_t fls_sp = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(amm_pay_tx + AMM_PAY_FLS_OUT, fls_sp);
            UINT32_TO_BUF(amm_pay_tx + AMM_PAY_LLS_OUT, fls_sp + 4U);
            AMM_COPY_20(amm_pay_tx + AMM_PAY_ACCT_OUT, hook_acc);
            AMM_COPY_20(amm_pay_tx + AMM_PAY_DEST_OUT, sender);
            AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_AMT_OUT, out_amt);
            if (etxn_details(amm_pay_tx + AMM_PAY_EMIT_OUT, AMM_PAY_EMIT_LEN) != AMM_PAY_EMIT_LEN)
                AMM_ROLLBACK("amm: SWAP pay details.");
            int64_t fee_sp = etxn_fee_base(amm_pay_tx, AMM_PAY_SIZE);
            if (fee_sp < 0) AMM_ROLLBACK("amm: SWAP pay fee.");
            AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_FEE_OUT, (uint64_t)fee_sp);
            uint8_t eh[32];
            if (emit(SBUF(eh), amm_pay_tx, AMM_PAY_SIZE) < 0)
                AMM_ROLLBACK("amm: emit swap XAH failed.");
        }

        /* DAO auto-flush: emit accumulated fees to dao_dest when XAH
           threshold is crossed. Both sides emitted together. */
        if (dao_flush)
        {
            if (cumDaoXah > 0)
            {
                uint32_t fls_da = (uint32_t)ledger_seq() + 1U;
                UINT32_TO_BUF(amm_pay_tx + AMM_PAY_FLS_OUT, fls_da);
                UINT32_TO_BUF(amm_pay_tx + AMM_PAY_LLS_OUT, fls_da + 4U);
                AMM_COPY_20(amm_pay_tx + AMM_PAY_ACCT_OUT, hook_acc);
                AMM_COPY_20(amm_pay_tx + AMM_PAY_DEST_OUT, dao_dest);
                AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_AMT_OUT, cumDaoXah);
                if (etxn_details(amm_pay_tx + AMM_PAY_EMIT_OUT, AMM_PAY_EMIT_LEN) != AMM_PAY_EMIT_LEN)
                    AMM_ROLLBACK("amm: dao auto pay details.");
                int64_t fee_da = etxn_fee_base(amm_pay_tx, AMM_PAY_SIZE);
                if (fee_da < 0) AMM_ROLLBACK("amm: dao auto pay fee.");
                AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_FEE_OUT, (uint64_t)fee_da);
                uint8_t deh[32];
                if (emit(SBUF(deh), amm_pay_tx, AMM_PAY_SIZE) < 0)
                    AMM_ROLLBACK("amm: dao auto-emit XAH failed.");
                cumDaoXah = 0;
            }
            if (cumDaoIou > 0)
            {
                int64_t dxfl = float_set(-6, (int64_t)cumDaoIou);
                if (dxfl >= 0)
                {
                    uint32_t fls_af = (uint32_t)ledger_seq() + 1U;
                    UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_FLS_OUT, fls_af);
                    UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_LLS_OUT, fls_af + 4U);
                    AMM_COPY_20(amm_remit_tx + AMM_REMIT_ACCT_OUT, hook_acc);
                    AMM_COPY_20(amm_remit_tx + AMM_REMIT_DEST_OUT, dao_dest);
                    int ok_af = 1;
                    if (etxn_details(amm_remit_tx + AMM_REMIT_EMIT_OUT, AMM_REMIT_EMIT_LEN) != AMM_REMIT_EMIT_LEN) ok_af = 0;
                    if (ok_af && float_sto(amm_remit_tx + AMM_REMIT_AMT_OUT, 49, cfg_cur, 20, cfg_issuer, 20, dxfl, sfAmount) != 49) ok_af = 0;
                    int64_t fee_af = ok_af ? etxn_fee_base(amm_remit_tx, AMM_REMIT_SIZE) : -1;
                    if (fee_af < 0) ok_af = 0;
                    if (ok_af) {
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 0] = 0x40U | ((uint8_t)((fee_af >> 56) & 0x3FU));
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 1] = (uint8_t)((fee_af >> 48) & 0xFFU);
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 2] = (uint8_t)((fee_af >> 40) & 0xFFU);
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 3] = (uint8_t)((fee_af >> 32) & 0xFFU);
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 4] = (uint8_t)((fee_af >> 24) & 0xFFU);
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 5] = (uint8_t)((fee_af >> 16) & 0xFFU);
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 6] = (uint8_t)((fee_af >>  8) & 0xFFU);
                        amm_remit_tx[AMM_REMIT_FEE_OUT + 7] = (uint8_t)( fee_af        & 0xFFU);
                        uint8_t deh2[32];
                        if (emit(SBUF(deh2), SBUF(amm_remit_tx)) >= 0)
                            cumDaoIou = 0;
                    }
                }
                /* IOU emit failure is non-fatal — XAH already sent,
                   IOU stays in escrow for next flush or manual claim. */
            }
            TRACESTR("amm: DAO auto-flush emitted.");
        }

        UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
        if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
            AMM_ROLLBACK("amm: cfg write failed (SWAP).");

        AMM_ACCEPT_AFTER_EMIT("amm: SWAP executed.");
    }

    /* ================================================================ */
    /*  DAOCLAIM — DAO wallet sweeps accumulated fee escrow              */
    /* ================================================================ */
    if (is_daoclaim)
    {
        if (!dao_enabled)
            AMM_ROLLBACK("amm: dao claim: feature disabled.");
        /* Authorization: sender must equal configured DAO_DEST. */
        if (!BUFFER_EQUAL_20(sender, dao_dest))
            AMM_ROLLBACK("amm: dao claim: not authorized.");

        /* v6: Invoke is canonical; legacy XAH-dust Payment still accepted. */
        if (!is_invoke && !is_xah_in)
            AMM_ROLLBACK("amm: dao claim: requires Invoke or XAH dust.");
        if (!is_invoke && in_xah_drops < min_xah)
            AMM_ROLLBACK("amm: dao claim: dust below MINXAH.");

        uint64_t claim_xah = cumDaoXah;
        uint64_t claim_iou = cumDaoIou;
        if (claim_xah == 0 && claim_iou == 0)
            AMM_ROLLBACK("amm: dao claim: nothing to claim.");

        /* The dust the DAO just sent is net-new XAH entering the pool.
           Credit it to reserveXah (LPs benefit from the invocation cost).
           Note: this is a side-effect of claim invocation, intentional. */
        if (reserveXah > (~(uint64_t)0) - in_xah_drops)
            AMM_ROLLBACK("amm: dao claim: reserve overflow dust.");
        reserveXah += in_xah_drops;

        /* Reserve up to two emits (XAH leg + IOU leg). */
        /* etxn_reserve(5) at top of hook covers DAOCLAIM's 2 + 2 offers. */

        if (claim_xah > 0)
        {
            uint32_t fls_dc = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(amm_pay_tx + AMM_PAY_FLS_OUT, fls_dc);
            UINT32_TO_BUF(amm_pay_tx + AMM_PAY_LLS_OUT, fls_dc + 4U);
            AMM_COPY_20(amm_pay_tx + AMM_PAY_ACCT_OUT, hook_acc);
            AMM_COPY_20(amm_pay_tx + AMM_PAY_DEST_OUT, dao_dest);
            AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_AMT_OUT, claim_xah);
            if (etxn_details(amm_pay_tx + AMM_PAY_EMIT_OUT, AMM_PAY_EMIT_LEN) != AMM_PAY_EMIT_LEN)
                AMM_ROLLBACK("amm: DAOCLAIM pay details.");
            int64_t fee_dcx = etxn_fee_base(amm_pay_tx, AMM_PAY_SIZE);
            if (fee_dcx < 0) AMM_ROLLBACK("amm: DAOCLAIM pay fee.");
            AMM_PAY_WRITE_DROPS(amm_pay_tx + AMM_PAY_FEE_OUT, (uint64_t)fee_dcx);
            uint8_t eh[32];
            if (emit(SBUF(eh), amm_pay_tx, AMM_PAY_SIZE) < 0)
                AMM_ROLLBACK("amm: dao claim: emit XAH failed.");
            cumDaoXah = 0;
        }

        if (claim_iou > 0)
        {
            int64_t xfl_dc = float_set(-6, (int64_t)claim_iou);
            if (xfl_dc < 0) AMM_ROLLBACK("amm: DAOCLAIM xfl.");
            uint32_t fls_dc = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_FLS_OUT, fls_dc);
            UINT32_TO_BUF(amm_remit_tx + AMM_REMIT_LLS_OUT, fls_dc + 4U);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_ACCT_OUT, hook_acc);
            AMM_COPY_20(amm_remit_tx + AMM_REMIT_DEST_OUT, dao_dest);
            if (etxn_details(amm_remit_tx + AMM_REMIT_EMIT_OUT, AMM_REMIT_EMIT_LEN) != AMM_REMIT_EMIT_LEN)
                AMM_ROLLBACK("amm: DAOCLAIM remit details.");
            if (float_sto(amm_remit_tx + AMM_REMIT_AMT_OUT, 49, cfg_cur, 20, cfg_issuer, 20, xfl_dc, sfAmount) != 49)
                AMM_ROLLBACK("amm: DAOCLAIM remit sto.");
            int64_t fee_dc = etxn_fee_base(amm_remit_tx, AMM_REMIT_SIZE);
            if (fee_dc < 0) AMM_ROLLBACK("amm: DAOCLAIM remit fee.");
            amm_remit_tx[AMM_REMIT_FEE_OUT + 0] = 0x40U | ((uint8_t)((fee_dc >> 56) & 0x3FU));
            amm_remit_tx[AMM_REMIT_FEE_OUT + 1] = (uint8_t)((fee_dc >> 48) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 2] = (uint8_t)((fee_dc >> 40) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 3] = (uint8_t)((fee_dc >> 32) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 4] = (uint8_t)((fee_dc >> 24) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 5] = (uint8_t)((fee_dc >> 16) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 6] = (uint8_t)((fee_dc >>  8) & 0xFFU);
            amm_remit_tx[AMM_REMIT_FEE_OUT + 7] = (uint8_t)( fee_dc        & 0xFFU);
            uint8_t eh2[32];
            if (emit(SBUF(eh2), SBUF(amm_remit_tx)) < 0)
                AMM_ROLLBACK("amm: DAOCLAIM remit emit.");
            cumDaoIou = 0;
        }

        UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, reserveXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, reserveIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, totalShares);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
        if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
            AMM_ROLLBACK("amm: cfg write failed (DAOCLAIM).");

        AMM_ACCEPT_AFTER_EMIT("amm: DAOCLAIM queued emits.");
    }

    /* TESTDAO debug path removed in v6 audit (A3). Was a one-off Remit
       smoke test from the v3→v4 IOU emit migration. Admin-gated, no
       fund impact, but unnecessary surface area for production. */

    /* ================================================================ */
    /*  RESYNC — split-auth one-shot reserve reconcile                   */
    /*                                                                   */
    /*  ANY account sends a XAH dust Payment with:                       */
    /*    CMD  = "RESYNC"                                                */
    /*    RXAH = uint64 drops   (target reserveXahDrops)                 */
    /*    RIOU = uint64 micro   (target reserveIouMicro)                 */
    /*    RTSH = uint64 shares  (OPTIONAL — DAO_DEST ONLY, see below)    */
    /*                                                                   */
    /*  Why RXAH/RIOU are permissionless: if DAO is blackholed, anyone   */
    /*  needs to be able to heal stale tracker drift. RXAH/RIOU are      */
    /*  non-exploitable — the next command runs XAH-YIELD + IOU-YIELD    */
    /*  which forcibly reconcile reserves from on-chain reality,         */
    /*  overwriting whatever was set here.                               */
    /*                                                                   */
    /*  Why RTSH IS gated to DAO_DEST: totalShares is NEVER reconciled   */
    /*  by YIELD. A permissionless RTSH decrement lets any LP set        */
    /*  new_ts = their own ALP holding, then REM 100% to drain the pool  */
    /*  for ~5 XAH. RXAH/RIOU could never do this because YIELD          */
    /*  overrides; RTSH has no such override. Therefore RTSH writes      */
    /*  require DAO_DEST. Pool-side recovery if DAO is blackholed and    */
    /*  totalShares zombies: not possible via RESYNC. Instead use the    */
    /*  bootstrap ADD path on a totalShares=0 zombie (already            */
    /*  permissionless at L1395) — confirmed in the pre-blackhole       */
    /*  recovery audit as the canonical heal for that state.             */
    /*                                                                   */
    /*  Hard rule: new_ts must NOT exceed current totalShares. An        */
    /*  increase would mint phantom shares and dilute existing LPs       */
    /*  (also a rug-pull primitive, blocked separately).                 */
    /*  Anti-spam: dust XAH must be sent (caller pays gas).              */
    /*  Preserves cumFees + cumDao.                                      */
    /* ================================================================ */
    if (is_resync)
    {
        if (!is_xah_in)
            AMM_ROLLBACK("amm: RESYNC: requires native XAH dust.");

        uint8_t rxb[8];
        if (otxn_param(SBUF(rxb), SBUF_STR("RXAH")) != 8)
            AMM_ROLLBACK("amm: RESYNC: missing RXAH.");
        uint64_t new_rx = UINT64_FROM_BUF(rxb);

        uint8_t ryb[8];
        if (otxn_param(SBUF(ryb), SBUF_STR("RIOU")) != 8)
            AMM_ROLLBACK("amm: RESYNC: missing RIOU.");
        uint64_t new_ri = UINT64_FROM_BUF(ryb);

        uint64_t new_ts = totalShares;
        uint8_t rsb[8];
        if (otxn_param(SBUF(rsb), SBUF_STR("RTSH")) == 8) {
            /* CRITICAL: RTSH writes are a rug-pull primitive. Unlike
               RXAH/RIOU (which YIELD reconciles on the next tx), totalShares
               is NEVER reconciled. A permissionless RTSH decrement lets
               any LP set new_ts = their own ALP holding, then REM 100%
               of the pool. Therefore RTSH writes REQUIRE DAO_DEST. */
            if (!BUFFER_EQUAL_20(sender, dao_dest))
                AMM_ROLLBACK("amm: RESYNC: RTSH admin-only.");
            new_ts = UINT64_FROM_BUF(rsb);
        }

        if (new_ts > totalShares)
            AMM_ROLLBACK("amm: RESYNC: RTSH cannot increase.");

        /* Optional CPXH/CPIO — seed the global pending counters. DAO-only
           because under-seeding lets YIELD treat tracked stash XAH/IOU as
           untracked yield, draining the stashers' value to existing LPs
           (the cross-user absorption bug). Over-seeding only suppresses
           legitimate YIELD absorption and hurts LPs slightly, but doesn't
           drain — still admin-only to prevent griefing. Used once after
           upgrading from a pre-counter install: caller sums all currently-
           outstanding stash slot amounts and sets the matching counter. */
        uint64_t new_cpx = cumPendXah;
        uint8_t cpxb[8];
        if (otxn_param(SBUF(cpxb), SBUF_STR("CPXH")) == 8) {
            if (!BUFFER_EQUAL_20(sender, dao_dest))
                AMM_ROLLBACK("amm: RESYNC: CPXH admin-only.");
            new_cpx = UINT64_FROM_BUF(cpxb);
        }
        uint64_t new_cpi = cumPendIou;
        uint8_t cpib[8];
        if (otxn_param(SBUF(cpib), SBUF_STR("CPIO")) == 8) {
            if (!BUFFER_EQUAL_20(sender, dao_dest))
                AMM_ROLLBACK("amm: RESYNC: CPIO admin-only.");
            new_cpi = UINT64_FROM_BUF(cpib);
        }

        UINT64_TO_BUF(cfg_val + AMM_CFG_RXAH, new_rx);
        UINT64_TO_BUF(cfg_val + AMM_CFG_RIOU, new_ri);
        UINT64_TO_BUF(cfg_val + AMM_CFG_SHARES, new_ts);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEXAH, cumFeeXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_FEEIOU, cumFeeIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOX, cumDaoXah);
        UINT64_TO_BUF(cfg_val + AMM_CFG_DAOY, cumDaoIou);
        UINT64_TO_BUF(cfg_val + AMM_CFG_PENDXAH, new_cpx);
        UINT64_TO_BUF(cfg_val + AMM_CFG_PENDIOU, new_cpi);
        if (state_set(cfg_val, AMM_CFG_LEN, SBUF(cfg_key)) != AMM_CFG_LEN)
            AMM_ROLLBACK("amm: cfg write failed (RESYNC).");

        AMM_ACCEPT("amm: RESYNC applied.");
    }

    AMM_ROLLBACK("amm: unreachable.");
}
