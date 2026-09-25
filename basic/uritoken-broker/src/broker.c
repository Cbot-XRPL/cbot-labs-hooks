#include "hookapi.h"
#include <stdint.h>

#define EB_GUARD(maxiter) _g(__LINE__, (maxiter) + 1)
#define EB_ACCEPT(msg) return accept(SBUF(msg), __LINE__)
#define EB_ROLLBACK(msg) return rollback(SBUF(msg), __LINE__)

/*
 * Ephemeral Broker Hook
 *
 * Supported production flow:
 * - trigger: incoming native XAH Payment to the hook account
 * - tx params:
 *   - NFTID : 32-byte URITokenID
 *   - BUY   : 8-byte uint64 max allowed live ask in drops
 * - install params:
 *   - FEEDEST : ascii r-address for the Vault fee wallet (required when FEEBPS > 0)
 *   - FEEBPS  : 4-byte uint32 fee basis points, 0..10000
 *   - RSVINC  : 4-byte uint32 drops - the ledger's owner-reserve increment the Remit transfers to the buyer
 *               for the URIToken it delivers (v2; 0/absent = default 200000 = 0.2 XAH). Counted as a chain
 *               cost so the fee payout nets it out and the broker stops bleeding 0.2 XAH per sale.
 *   - FEEMIN  : 8-byte uint64 drops - optional minimum broker fee per sale (v2; 0/absent = off). When set,
 *               fee = max(ask * FEEBPS / 10000, FEEMIN); the server's buy builder must use the same floor.
 *   - MEMO    : 2..64 ascii bytes - optional memo stamped on the emitted URITokenBuy (what the seller sees) and
 *               the Remit that delivers the token (what the buyer sees), as Memos[{MemoData, MemoFormat
 *               "text/plain"}] (v3). A 0/1-byte value (e.g. "-") = no memo. Set it explicitly at install: the
 *               first install of a wasm hash stores its params as the DEFINITION defaults for everyone.
 *
 * Runtime behavior:
 * 1. Read the live URIToken object for NFTID.
 * 2. Require a native-XAH open sell amount and require the payment to equal
 *    live ask + broker fee exactly.
 * 3. Emit URITokenBuy from the hook account.
 * 4. On callback success, emit Remit to send the bought NFT to the buyer.
 * 5. On callback success, emit Payment to the fee wallet for the net broker
 *    fee remaining after emitted chain fees.
 * 6. On buy failure, emit a refund Payment back to the buyer.
 *
 * Important limitation:
 * - emitted transactions settle on later ledgers, so the hook can fully
 *   auto-refund buy failures but cannot promise a perfect atomic rollback
 *   after a successful buy if a later remit/fee leg fails. This hook
 *   preflights the known receipt blockers aggressively to make remit failure
 *   rare, and preserves stuck callback state for operator recovery.
 */

#define EB_PENDING_VALUE_LEN 128U
#define EB_KEY_LEN 32U

#define EB_REC_VERSION 0U
#define EB_REC_PHASE 1U
#define EB_REC_BUYER 4U
#define EB_REC_FEE_WALLET 24U
#define EB_REC_SELLER 44U
#define EB_REC_NFTID 64U
#define EB_REC_ASK 96U
#define EB_REC_FEE 104U
#define EB_REC_PAID 112U
#define EB_REC_CHAIN_FEES 120U

#define EB_PENDING_VERSION 1U
#define EB_PHASE_BUY_PENDING 1U
#define EB_PHASE_REMIT_PENDING 2U
#define EB_PHASE_FEE_PENDING 3U
#define EB_PHASE_REFUND_PENDING 4U
#define EB_PHASE_BUY_FAILED_STUCK 5U
#define EB_PHASE_REMIT_FAILED_STUCK 6U
#define EB_PHASE_FEE_FAILED_STUCK 7U
#define EB_PHASE_REFUND_FAILED_STUCK 8U

#define EB_REQUIRE_DEST_TAG_FLAG 0x00020000UL
#define EB_PARTIAL_PAYMENT_FLAG 0x00020000UL
#define EB_DEPOSIT_AUTH_FLAG 0x01000000UL
#define EB_DISALLOW_INCOMING_REMIT_FLAG 0x80000000UL

#define EB_MAX_FEE_BPS 10000U
#define EB_DEFAULT_RSV_INC 200000ULL

#define EB_EMIT_DETAILS_LEN 138U

#define EB_PAYMENT_TX_LEN 260U
#define EB_BUY_TX_LEN 272U
#define EB_REMIT_TX_LEN 287U

#define EB_PAYMENT_FLS_OUT 15U
#define EB_PAYMENT_LLS_OUT 21U
#define EB_PAYMENT_AMOUNT_OUT 26U
#define EB_PAYMENT_FEE_OUT 35U
#define EB_PAYMENT_ACCOUNT_OUT 80U
#define EB_PAYMENT_DEST_OUT 102U
#define EB_PAYMENT_EMIT_OUT 122U

#define EB_BUY_FLS_OUT 15U
#define EB_BUY_LLS_OUT 21U
#define EB_BUY_NFTID_OUT 27U
#define EB_BUY_AMOUNT_OUT 60U
#define EB_BUY_FEE_OUT 69U
#define EB_BUY_ACCOUNT_OUT 114U
#define EB_BUY_EMIT_OUT 134U

#define EB_REMIT_FLS_OUT 15U
#define EB_REMIT_LLS_OUT 21U
#define EB_REMIT_FEE_OUT 26U
#define EB_REMIT_ACCOUNT_OUT 71U
#define EB_REMIT_DEST_OUT 93U
#define EB_REMIT_EMIT_OUT 113U
#define EB_REMIT_URITOKEN_FIELD_OUT 251U   /* base offset; shifts right by the memo block when MEMO is set */
#define EB_REMIT_URITOKEN_ID_OUT 255U

/* v3 memo: Memos(F9) [ Memo(EA) MemoData(7D len data) MemoFormat(7E 0A "text/plain") E1 ] F1 = 18 + len bytes.
 * Canonical order: after EmitDetails (type 14), before URITokenIDs (type 19). */
#define EB_MEMO_MAX 64U
#define EB_MEMO_BLOCK_MAX (18U + EB_MEMO_MAX)
#define EB_MEMO_BLOCK_LEN(mlen) ((mlen) ? (18U + (uint32_t)(mlen)) : 0U)
#define EB_WRITE_MEMO(buf, off, memo, mlen)                                                    \
    {                                                                                          \
        if ((mlen) > 0)                                                                        \
        {                                                                                      \
            uint32_t eb_o = (uint32_t)(off);                                                   \
            (buf)[eb_o + 0] = 0xF9U;                                                           \
            (buf)[eb_o + 1] = 0xEAU;                                                           \
            (buf)[eb_o + 2] = 0x7DU;                                                           \
            (buf)[eb_o + 3] = (uint8_t)(mlen);                                                 \
            for (uint32_t eb_i = 0; EB_GUARD(EB_MEMO_MAX), eb_i < (uint32_t)(mlen); ++eb_i)    \
                (buf)[eb_o + 4 + eb_i] = (memo)[eb_i];                                         \
            eb_o += 4U + (uint32_t)(mlen);                                                     \
            (buf)[eb_o + 0] = 0x7EU;                                                           \
            (buf)[eb_o + 1] = 0x0AU;                                                           \
            (buf)[eb_o + 2] = 't';                                                             \
            (buf)[eb_o + 3] = 'e';                                                             \
            (buf)[eb_o + 4] = 'x';                                                             \
            (buf)[eb_o + 5] = 't';                                                             \
            (buf)[eb_o + 6] = '/';                                                             \
            (buf)[eb_o + 7] = 'p';                                                             \
            (buf)[eb_o + 8] = 'l';                                                             \
            (buf)[eb_o + 9] = 'a';                                                             \
            (buf)[eb_o + 10] = 'i';                                                            \
            (buf)[eb_o + 11] = 'n';                                                            \
            (buf)[eb_o + 12] = 0xE1U;                                                          \
            (buf)[eb_o + 13] = 0xF1U;                                                          \
        }                                                                                      \
    }
/* read the optional MEMO param into a zeroed 64-byte buffer; len 0 unless 2..64 bytes and non-blank */
#define EB_READ_MEMO(memo, mlen)                                                               \
    {                                                                                          \
        uint8_t eb_memo_key[] = {'M', 'E', 'M', 'O'};                                          \
        int64_t eb_ml = hook_param(SBUF(memo), SBUF(eb_memo_key));                             \
        (mlen) = 0U;                                                                           \
        if (eb_ml >= 2 && eb_ml <= (int64_t)EB_MEMO_MAX && (memo)[0] != 0)                     \
            (mlen) = (uint32_t)eb_ml;                                                          \
    }

#define EB_ZERO(buf, len)                             \
    {                                                \
        for (uint32_t i = 0; EB_GUARD(len), i < (uint32_t)(len); ++i) \
            (buf)[i] = 0;                            \
    }

#define EB_COPY_20(dst, src)                         \
    {                                                \
        for (int i = 0; EB_GUARD(20), i < 20; ++i)   \
            (dst)[i] = (src)[i];                     \
    }

#define EB_COPY_32(dst, src)                         \
    {                                                \
        for (int i = 0; EB_GUARD(32), i < 32; ++i)   \
            (dst)[i] = (src)[i];                     \
    }

#define EB_WRITE_DROPS(buf_raw, value)               \
    {                                                \
        uint64_t eb_encoded_drops = ((uint64_t)(value) & 0x3FFFFFFFFFFFFFFFULL) | 0x4000000000000000ULL; \
        UINT64_TO_BUF((buf_raw), eb_encoded_drops);  \
    }

#define EB_WRITE_PENDING_U64(record, offset, value)  \
    UINT64_TO_BUF((record) + (offset), (uint64_t)(value))

#define EB_READ_PENDING_U64(record, offset)          \
    UINT64_FROM_BUF((record) + (offset))

int64_t hook(uint32_t reserved)
{
    (void)reserved;

    if (otxn_type() != ttPAYMENT)
        EB_ACCEPT("ephemeral_broker_hook: ignored non-payment.");

    uint8_t hook_acc[20];
    if (hook_account(SBUF(hook_acc)) != 20)
        EB_ROLLBACK("ephemeral_broker_hook: hook_account failed.");

    uint8_t buyer_acc[20];
    if (otxn_field(SBUF(buyer_acc), sfAccount) != 20)
        EB_ROLLBACK("ephemeral_broker_hook: missing buyer account.");

    if (BUFFER_EQUAL_20(hook_acc, buyer_acc))
        EB_ACCEPT("ephemeral_broker_hook: ignored hook-emitted self-payment.");

    uint8_t flags_buf[4];
    if (otxn_field(SBUF(flags_buf), sfFlags) == 4)
    {
        uint32_t flags = UINT32_FROM_BUF(flags_buf);
        if (flags & EB_PARTIAL_PAYMENT_FLAG)
            EB_ROLLBACK("ephemeral_broker_hook: partial payments are not supported.");
    }

    uint8_t payment_amount_buf[8];
    if (otxn_field(SBUF(payment_amount_buf), sfAmount) != 8)
        EB_ROLLBACK("ephemeral_broker_hook: payment must be native XAH.");

    int64_t incoming_drops = AMOUNT_TO_DROPS(payment_amount_buf);
    if (incoming_drops < 0)
        EB_ROLLBACK("ephemeral_broker_hook: invalid payment amount.");

    uint8_t nft_id[32];
    uint8_t nft_key[] = {'N', 'F', 'T', 'I', 'D'};
    if (otxn_param(SBUF(nft_id), SBUF(nft_key)) != 32)
        EB_ROLLBACK("ephemeral_broker_hook: missing NFTID tx param.");

    uint8_t buy_limit_buf[8];
    uint8_t buy_key[] = {'B', 'U', 'Y'};
    if (otxn_param(SBUF(buy_limit_buf), SBUF(buy_key)) != 8)
        EB_ROLLBACK("ephemeral_broker_hook: missing BUY tx param.");
    uint64_t buy_limit_drops = UINT64_FROM_BUF(buy_limit_buf);

    uint8_t fee_bps_buf[4];
    uint8_t fee_bps_key[] = {'F', 'E', 'E', 'B', 'P', 'S'};
    if (hook_param(SBUF(fee_bps_buf), SBUF(fee_bps_key)) != 4)
        EB_ROLLBACK("ephemeral_broker_hook: missing FEEBPS hook param.");
    uint32_t fee_bps = UINT32_FROM_BUF(fee_bps_buf);
    if (fee_bps > EB_MAX_FEE_BPS)
        EB_ROLLBACK("ephemeral_broker_hook: FEEBPS must be 0..10000.");

    /* v2: reserve the Remit will hand the buyer (optional param, zeroed buffer, default 0.2 XAH) */
    uint8_t rsv_buf[4];
    EB_ZERO(rsv_buf, 4);
    uint8_t rsv_key[] = {'R', 'S', 'V', 'I', 'N', 'C'};
    uint64_t rsv_inc = 0;
    if (hook_param(SBUF(rsv_buf), SBUF(rsv_key)) == 4)
        rsv_inc = UINT32_FROM_BUF(rsv_buf);
    if (rsv_inc == 0)
        rsv_inc = EB_DEFAULT_RSV_INC;

    /* v2: optional minimum fee per sale (zeroed buffer, 0 = off) */
    uint8_t fee_min_buf[8];
    EB_ZERO(fee_min_buf, 8);
    uint8_t fee_min_key[] = {'F', 'E', 'E', 'M', 'I', 'N'};
    uint64_t fee_min = 0;
    if (hook_param(SBUF(fee_min_buf), SBUF(fee_min_key)) == 8)
        fee_min = UINT64_FROM_BUF(fee_min_buf);

    /* v3: optional memo for the buy + remit legs */
    uint8_t memo[EB_MEMO_MAX];
    EB_ZERO(memo, EB_MEMO_MAX);
    uint32_t memo_len = 0;
    EB_READ_MEMO(memo, memo_len);
    uint32_t memo_block = EB_MEMO_BLOCK_LEN(memo_len);

    uint8_t fee_wallet_acc[20];
    EB_ZERO(fee_wallet_acc, 20);
    if (fee_bps > 0)
    {
        uint8_t fee_dest_key[] = {'F', 'E', 'E', 'D', 'E', 'S', 'T'};
        uint8_t fee_dest_raddr[48];
        EB_ZERO(fee_dest_raddr, 48);
        int64_t fee_dest_len = hook_param(SBUF(fee_dest_raddr), SBUF(fee_dest_key));
        if (fee_dest_len < 25 || fee_dest_len > 48)
            EB_ROLLBACK("ephemeral_broker_hook: FEEDEST hook param is invalid.");
        if (util_accid(SBUF(fee_wallet_acc), (uint32_t)fee_dest_raddr, (uint32_t)fee_dest_len) != 20)
            EB_ROLLBACK("ephemeral_broker_hook: FEEDEST is not a valid account.");
    }

    uint8_t buyer_keylet[34];
    if (util_keylet(SBUF(buyer_keylet), KEYLET_ACCOUNT, buyer_acc, 20, 0, 0, 0, 0) != 34)
        EB_ROLLBACK("ephemeral_broker_hook: could not build buyer account keylet.");
    if (slot_set(SBUF(buyer_keylet), 1) != 1)
        EB_ROLLBACK("ephemeral_broker_hook: buyer account does not exist.");
    if (slot_subfield(1, sfFlags, 2) != 2)
        EB_ROLLBACK("ephemeral_broker_hook: could not read buyer flags.");
    uint8_t buyer_flags_buf[4];
    if (slot(SBUF(buyer_flags_buf), 2) != 4)
        EB_ROLLBACK("ephemeral_broker_hook: could not load buyer flags.");
    uint32_t buyer_flags = UINT32_FROM_BUF(buyer_flags_buf);
    if (buyer_flags & EB_REQUIRE_DEST_TAG_FLAG)
        EB_ROLLBACK("ephemeral_broker_hook: buyer account requires a destination tag.");
    if (buyer_flags & EB_DEPOSIT_AUTH_FLAG)
        EB_ROLLBACK("ephemeral_broker_hook: buyer account uses DepositAuth.");
    if (buyer_flags & EB_DISALLOW_INCOMING_REMIT_FLAG)
        EB_ROLLBACK("ephemeral_broker_hook: buyer account disallows incoming Remit.");

    if (fee_bps > 0)
    {
        uint8_t fee_keylet[34];
        if (util_keylet(SBUF(fee_keylet), KEYLET_ACCOUNT, fee_wallet_acc, 20, 0, 0, 0, 0) != 34)
            EB_ROLLBACK("ephemeral_broker_hook: could not build fee wallet keylet.");
        if (slot_set(SBUF(fee_keylet), 3) != 3)
            EB_ROLLBACK("ephemeral_broker_hook: fee wallet account does not exist.");
        if (slot_subfield(3, sfFlags, 4) != 4)
            EB_ROLLBACK("ephemeral_broker_hook: could not read fee wallet flags.");
        uint8_t fee_flags_buf[4];
        if (slot(SBUF(fee_flags_buf), 4) != 4)
            EB_ROLLBACK("ephemeral_broker_hook: could not load fee wallet flags.");
        uint32_t fee_flags = UINT32_FROM_BUF(fee_flags_buf);
        if (fee_flags & EB_REQUIRE_DEST_TAG_FLAG)
            EB_ROLLBACK("ephemeral_broker_hook: fee wallet cannot require destination tags.");
        if (fee_flags & EB_DEPOSIT_AUTH_FLAG)
            EB_ROLLBACK("ephemeral_broker_hook: fee wallet uses DepositAuth.");
    }

    uint8_t token_keylet[34];
    if (util_keylet(SBUF(token_keylet), KEYLET_UNCHECKED, nft_id, 32, 0, 0, 0, 0) != 34)
        EB_ROLLBACK("ephemeral_broker_hook: could not build URIToken keylet.");
    if (slot_set(SBUF(token_keylet), 5) != 5)
        EB_ROLLBACK("ephemeral_broker_hook: target URIToken was not found.");

    if (slot_subfield(5, sfOwner, 6) != 6)
        EB_ROLLBACK("ephemeral_broker_hook: could not read URIToken owner.");
    uint8_t seller_acc[20];
    if (slot(SBUF(seller_acc), 6) != 20)
        EB_ROLLBACK("ephemeral_broker_hook: could not load URIToken owner.");
    if (BUFFER_EQUAL_20(seller_acc, hook_acc))
        EB_ROLLBACK("ephemeral_broker_hook: broker already owns this URIToken.");

    if (slot_subfield(5, sfAmount, 7) != 7)
        EB_ROLLBACK("ephemeral_broker_hook: URIToken has no active sell amount.");
    if (slot_size(7) != 8)
        EB_ROLLBACK("ephemeral_broker_hook: only native XAH sell offers are supported.");
    uint8_t ask_amount_buf[8];
    if (slot(SBUF(ask_amount_buf), 7) != 8)
        EB_ROLLBACK("ephemeral_broker_hook: could not load sell amount.");
    int64_t ask_drops = AMOUNT_TO_DROPS(ask_amount_buf);
    if (ask_drops < 0)
        EB_ROLLBACK("ephemeral_broker_hook: invalid sell amount.");

    int64_t token_dest_slot = slot_subfield(5, sfDestination, 8);
    if (token_dest_slot >= 0)
    {
        uint8_t private_dest_acc[20];
        if (slot(SBUF(private_dest_acc), 8) != 20)
            EB_ROLLBACK("ephemeral_broker_hook: could not load URIToken destination.");
        if (!BUFFER_EQUAL_20(private_dest_acc, hook_acc))
            EB_ROLLBACK("ephemeral_broker_hook: private URIToken sale is not targeted to this broker.");
    }

    if ((uint64_t)ask_drops > buy_limit_drops)
        EB_ROLLBACK("ephemeral_broker_hook: live ask exceeds BUY limit.");

    uint64_t fee_drops = 0;
    if (fee_bps > 0)
    {
        int64_t ask_xfl = float_set(-6, ask_drops);
        if (ask_xfl < 0)
            EB_ROLLBACK("ephemeral_broker_hook: ask amount could not be converted.");
        int64_t fee_xfl = float_mulratio(ask_xfl, 1U, fee_bps, 10000U);
        if (fee_xfl < 0)
            EB_ROLLBACK("ephemeral_broker_hook: fee ratio conversion failed.");
        int64_t fee_drops_signed = float_int(fee_xfl, 6, 1);
        if (fee_drops_signed < 0)
            EB_ROLLBACK("ephemeral_broker_hook: fee amount conversion failed.");
        fee_drops = (uint64_t)fee_drops_signed;
        if (fee_drops < fee_min)
            fee_drops = fee_min;
    }

    if (fee_drops > 0 && (uint64_t)ask_drops > (~(uint64_t)0) - fee_drops)
        EB_ROLLBACK("ephemeral_broker_hook: total payment overflow.");

    uint64_t required_total_drops = (uint64_t)ask_drops + fee_drops;
    if ((uint64_t)incoming_drops != required_total_drops)
        EB_ROLLBACK("ephemeral_broker_hook: payment must equal live ask plus broker fee.");

    uint8_t hook_keylet[34];
    if (util_keylet(SBUF(hook_keylet), KEYLET_ACCOUNT, hook_acc, 20, 0, 0, 0, 0) != 34)
        EB_ROLLBACK("ephemeral_broker_hook: could not build broker account keylet.");
    if (slot_set(SBUF(hook_keylet), 9) != 9)
        EB_ROLLBACK("ephemeral_broker_hook: broker account does not exist.");
    if (slot_subfield(9, sfBalance, 10) != 10)
        EB_ROLLBACK("ephemeral_broker_hook: could not read broker balance.");
    uint8_t hook_balance_buf[8];
    if (slot(SBUF(hook_balance_buf), 10) != 8)
        EB_ROLLBACK("ephemeral_broker_hook: could not load broker balance.");
    int64_t hook_balance_drops = AMOUNT_TO_DROPS(hook_balance_buf);
    if (hook_balance_drops < 0)
        EB_ROLLBACK("ephemeral_broker_hook: invalid broker balance.");

    uint8_t buy_txn[EB_BUY_TX_LEN + EB_MEMO_BLOCK_MAX];
    EB_ZERO(buy_txn, EB_BUY_TX_LEN + EB_MEMO_BLOCK_MAX);
    uint32_t buy_len = EB_BUY_TX_LEN + memo_block;   /* Memos sit after EmitDetails = the tail of the buy tx */
    buy_txn[0] = 0x12U;
    buy_txn[1] = 0x00U;
    buy_txn[2] = 0x2FU;
    buy_txn[3] = 0x22U;
    buy_txn[4] = 0x80U;
    buy_txn[8] = 0x24U;
    buy_txn[13] = 0x20U;
    buy_txn[14] = 0x1AU;
    buy_txn[19] = 0x20U;
    buy_txn[20] = 0x1BU;
    buy_txn[25] = 0x50U;
    buy_txn[26] = 0x24U;
    buy_txn[59] = 0x61U;
    buy_txn[68] = 0x68U;
    buy_txn[77] = 0x73U;
    buy_txn[78] = 0x21U;
    buy_txn[112] = 0x81U;
    buy_txn[113] = 0x14U;

    if (etxn_reserve(1) < 0)
        EB_ROLLBACK("ephemeral_broker_hook: emit reserve failed.");

    uint32_t buy_fls = (uint32_t)ledger_seq() + 1U;
    UINT32_TO_BUF(buy_txn + EB_BUY_FLS_OUT, buy_fls);
    UINT32_TO_BUF(buy_txn + EB_BUY_LLS_OUT, buy_fls + 4U);
    EB_WRITE_DROPS(buy_txn + EB_BUY_AMOUNT_OUT, (uint64_t)ask_drops);
    EB_COPY_32(buy_txn + EB_BUY_NFTID_OUT, nft_id);
    EB_COPY_20(buy_txn + EB_BUY_ACCOUNT_OUT, hook_acc);
    EB_WRITE_DROPS(buy_txn + EB_BUY_FEE_OUT, 0U);
    if (etxn_details(buy_txn + EB_BUY_EMIT_OUT, EB_EMIT_DETAILS_LEN) != EB_EMIT_DETAILS_LEN)
        EB_ROLLBACK("ephemeral_broker_hook: emit details failed.");
    EB_WRITE_MEMO(buy_txn, EB_BUY_TX_LEN, memo, memo_len);
    int64_t buy_fee = etxn_fee_base(buy_txn, buy_len);
    if (buy_fee < 0)
        EB_ROLLBACK("ephemeral_broker_hook: fee calc failed.");
    EB_WRITE_DROPS(buy_txn + EB_BUY_FEE_OUT, (uint64_t)buy_fee);

    uint8_t refund_probe[EB_PAYMENT_TX_LEN];
    EB_ZERO(refund_probe, EB_PAYMENT_TX_LEN);
    refund_probe[0] = 0x12U;
    refund_probe[1] = 0x00U;
    refund_probe[2] = 0x00U;
    refund_probe[3] = 0x22U;
    refund_probe[4] = 0x80U;
    refund_probe[8] = 0x24U;
    refund_probe[13] = 0x20U;
    refund_probe[14] = 0x1AU;
    refund_probe[19] = 0x20U;
    refund_probe[20] = 0x1BU;
    refund_probe[25] = 0x61U;
    refund_probe[34] = 0x68U;
    refund_probe[43] = 0x73U;
    refund_probe[44] = 0x21U;
    refund_probe[78] = 0x81U;
    refund_probe[79] = 0x14U;
    refund_probe[100] = 0x83U;
    refund_probe[101] = 0x14U;
    UINT32_TO_BUF(refund_probe + EB_PAYMENT_FLS_OUT, buy_fls);
    UINT32_TO_BUF(refund_probe + EB_PAYMENT_LLS_OUT, buy_fls + 4U);
    EB_WRITE_DROPS(refund_probe + EB_PAYMENT_AMOUNT_OUT, required_total_drops);
    EB_COPY_20(refund_probe + EB_PAYMENT_ACCOUNT_OUT, hook_acc);
    EB_COPY_20(refund_probe + EB_PAYMENT_DEST_OUT, buyer_acc);
    EB_WRITE_DROPS(refund_probe + EB_PAYMENT_FEE_OUT, 0U);
    if (etxn_details(refund_probe + EB_PAYMENT_EMIT_OUT, EB_EMIT_DETAILS_LEN) != EB_EMIT_DETAILS_LEN)
        EB_ROLLBACK("ephemeral_broker_hook: refund preflight emit details failed.");
    int64_t refund_fee = etxn_fee_base(SBUF(refund_probe));
    if (refund_fee < 0)
        EB_ROLLBACK("ephemeral_broker_hook: refund fee preflight failed.");

    uint8_t remit_probe[EB_REMIT_TX_LEN + EB_MEMO_BLOCK_MAX];
    EB_ZERO(remit_probe, EB_REMIT_TX_LEN + EB_MEMO_BLOCK_MAX);
    uint32_t remit_len = EB_REMIT_TX_LEN + memo_block;
    uint32_t remit_uri_field = EB_REMIT_URITOKEN_FIELD_OUT + memo_block;   /* URITokenIDs follows the memo block */
    remit_probe[0] = 0x12U;
    remit_probe[1] = 0x00U;
    remit_probe[2] = 0x5FU;
    remit_probe[3] = 0x22U;
    remit_probe[4] = 0x80U;
    remit_probe[8] = 0x24U;
    remit_probe[13] = 0x20U;
    remit_probe[14] = 0x1AU;
    remit_probe[19] = 0x20U;
    remit_probe[20] = 0x1BU;
    remit_probe[25] = 0x68U;
    remit_probe[34] = 0x73U;
    remit_probe[35] = 0x21U;
    remit_probe[69] = 0x81U;
    remit_probe[70] = 0x14U;
    remit_probe[91] = 0x83U;
    remit_probe[92] = 0x14U;
    remit_probe[remit_uri_field + 0] = 0x00U;
    remit_probe[remit_uri_field + 1] = 0x13U;
    remit_probe[remit_uri_field + 2] = 0x63U;
    remit_probe[remit_uri_field + 3] = 0x20U;
    UINT32_TO_BUF(remit_probe + EB_REMIT_FLS_OUT, buy_fls);
    UINT32_TO_BUF(remit_probe + EB_REMIT_LLS_OUT, buy_fls + 4U);
    EB_COPY_20(remit_probe + EB_REMIT_ACCOUNT_OUT, hook_acc);
    EB_COPY_20(remit_probe + EB_REMIT_DEST_OUT, buyer_acc);
    EB_COPY_32(remit_probe + remit_uri_field + 4, nft_id);
    EB_WRITE_DROPS(remit_probe + EB_REMIT_FEE_OUT, 0U);
    if (etxn_details(remit_probe + EB_REMIT_EMIT_OUT, EB_EMIT_DETAILS_LEN) != EB_EMIT_DETAILS_LEN)
        EB_ROLLBACK("ephemeral_broker_hook: remit preflight emit details failed.");
    EB_WRITE_MEMO(remit_probe, EB_REMIT_URITOKEN_FIELD_OUT, memo, memo_len);
    int64_t remit_fee = etxn_fee_base(remit_probe, remit_len);
    if (remit_fee < 0)
        EB_ROLLBACK("ephemeral_broker_hook: remit fee preflight failed.");

    uint64_t refund_reserve_needed = (uint64_t)buy_fee + (uint64_t)refund_fee;
    if ((uint64_t)hook_balance_drops < refund_reserve_needed)
        EB_ROLLBACK("ephemeral_broker_hook: broker needs XAH reserve for refund-path fees.");

    if (required_total_drops > (~(uint64_t)0) - (uint64_t)hook_balance_drops)
        EB_ROLLBACK("ephemeral_broker_hook: projected broker balance overflow.");
    uint64_t projected_balance_after_payment = (uint64_t)hook_balance_drops + required_total_drops;

    if ((uint64_t)ask_drops > (~(uint64_t)0) - (uint64_t)buy_fee)
        EB_ROLLBACK("ephemeral_broker_hook: projected buy spend overflow.");
    uint64_t success_required_spend = (uint64_t)ask_drops + (uint64_t)buy_fee;
    if (success_required_spend > (~(uint64_t)0) - (uint64_t)remit_fee)
        EB_ROLLBACK("ephemeral_broker_hook: projected remit spend overflow.");
    success_required_spend += (uint64_t)remit_fee;
    if (success_required_spend > (~(uint64_t)0) - rsv_inc)
        EB_ROLLBACK("ephemeral_broker_hook: projected reserve spend overflow.");
    success_required_spend += rsv_inc;

    if (projected_balance_after_payment < success_required_spend)
        EB_ROLLBACK("ephemeral_broker_hook: broker needs more XAH headroom to finish buy and remit.");

    uint8_t buy_hash[32];
    if (emit(SBUF(buy_hash), buy_txn, buy_len) < 0)
        EB_ROLLBACK("ephemeral_broker_hook: URITokenBuy emit failed.");

    uint8_t pending[EB_PENDING_VALUE_LEN];
    EB_ZERO(pending, EB_PENDING_VALUE_LEN);
    pending[EB_REC_VERSION] = EB_PENDING_VERSION;
    pending[EB_REC_PHASE] = EB_PHASE_BUY_PENDING;
    EB_COPY_20(pending + EB_REC_BUYER, buyer_acc);
    EB_COPY_20(pending + EB_REC_FEE_WALLET, fee_wallet_acc);
    EB_COPY_20(pending + EB_REC_SELLER, seller_acc);
    EB_COPY_32(pending + EB_REC_NFTID, nft_id);
    EB_WRITE_PENDING_U64(pending, EB_REC_ASK, (uint64_t)ask_drops);
    EB_WRITE_PENDING_U64(pending, EB_REC_FEE, fee_drops);
    EB_WRITE_PENDING_U64(pending, EB_REC_PAID, required_total_drops);
    EB_WRITE_PENDING_U64(pending, EB_REC_CHAIN_FEES, (uint64_t)buy_fee);

    if (state_set(SBUF(pending), SBUF(buy_hash)) != EB_PENDING_VALUE_LEN)
        EB_ROLLBACK("ephemeral_broker_hook: pending broker state save failed.");

    EB_ACCEPT("ephemeral_broker_hook: buy emitted.");
}

int64_t cbak(uint32_t ctx)
{
    uint8_t callback_key[EB_KEY_LEN];
    EB_ZERO(callback_key, EB_KEY_LEN);
    int64_t callback_key_len = -1;
    if (ctx == 0U)
        callback_key_len = otxn_id(SBUF(callback_key), 0);
    else
        callback_key_len = otxn_field(SBUF(callback_key), sfEmittedTxnID);
    if (callback_key_len != 32)
        callback_key_len = otxn_id(SBUF(callback_key), 0);
    if (callback_key_len != 32)
        EB_ACCEPT("ephemeral_broker_hook: callback missing key.");

    uint8_t pending[EB_PENDING_VALUE_LEN];
    if (state(SBUF(pending), SBUF(callback_key)) != EB_PENDING_VALUE_LEN)
        EB_ACCEPT("ephemeral_broker_hook: callback state missing.");

    if (pending[EB_REC_VERSION] != EB_PENDING_VERSION)
        EB_ACCEPT("ephemeral_broker_hook: callback state version mismatch.");

    uint8_t phase = pending[EB_REC_PHASE];
    if (phase < EB_PHASE_BUY_PENDING || phase > EB_PHASE_REFUND_PENDING)
        EB_ACCEPT("ephemeral_broker_hook: callback state already terminal.");

    uint8_t hook_acc[20];
    if (hook_account(SBUF(hook_acc)) != 20)
        EB_ACCEPT("ephemeral_broker_hook: callback hook_account failed.");

    int64_t tx_success = (ctx == 0U);
    if (phase == EB_PHASE_BUY_PENDING)
    {
        tx_success = 0;
        if (ctx == 0U)
        {
            uint8_t token_keylet[34];
            if (util_keylet(SBUF(token_keylet), KEYLET_UNCHECKED, pending + EB_REC_NFTID, 32, 0, 0, 0, 0) == 34
                && slot_set(SBUF(token_keylet), 9) == 9
                && slot_subfield(9, sfOwner, 10) == 10)
            {
                uint8_t current_owner[20];
                if (slot(SBUF(current_owner), 10) == 20 && BUFFER_EQUAL_20(current_owner, hook_acc))
                    tx_success = 1;
            }
        }
    }
    else if (phase == EB_PHASE_REMIT_PENDING)
    {
        tx_success = 0;
        if (ctx == 0U)
        {
            uint8_t token_keylet[34];
            if (util_keylet(SBUF(token_keylet), KEYLET_UNCHECKED, pending + EB_REC_NFTID, 32, 0, 0, 0, 0) == 34
                && slot_set(SBUF(token_keylet), 9) == 9
                && slot_subfield(9, sfOwner, 10) == 10)
            {
                uint8_t current_owner[20];
                if (slot(SBUF(current_owner), 10) == 20 && BUFFER_EQUAL_20(current_owner, pending + EB_REC_BUYER))
                    tx_success = 1;
            }
        }
    }

    if (phase == EB_PHASE_BUY_PENDING)
    {
        if (!tx_success)
        {
            uint8_t refund_txn[EB_PAYMENT_TX_LEN];
            EB_ZERO(refund_txn, EB_PAYMENT_TX_LEN);
            refund_txn[0] = 0x12U;
            refund_txn[1] = 0x00U;
            refund_txn[2] = 0x00U;
            refund_txn[3] = 0x22U;
            refund_txn[4] = 0x80U;
            refund_txn[8] = 0x24U;
            refund_txn[13] = 0x20U;
            refund_txn[14] = 0x1AU;
            refund_txn[19] = 0x20U;
            refund_txn[20] = 0x1BU;
            refund_txn[25] = 0x61U;
            refund_txn[34] = 0x68U;
            refund_txn[43] = 0x73U;
            refund_txn[44] = 0x21U;
            refund_txn[78] = 0x81U;
            refund_txn[79] = 0x14U;
            refund_txn[100] = 0x83U;
            refund_txn[101] = 0x14U;

            if (etxn_reserve(1) < 0)
            {
                pending[EB_REC_PHASE] = EB_PHASE_BUY_FAILED_STUCK;
                state_set(SBUF(pending), SBUF(callback_key));
                EB_ACCEPT("ephemeral_broker_hook: refund reserve failed.");
            }

            uint32_t refund_fls = (uint32_t)ledger_seq() + 1U;
            UINT32_TO_BUF(refund_txn + EB_PAYMENT_FLS_OUT, refund_fls);
            UINT32_TO_BUF(refund_txn + EB_PAYMENT_LLS_OUT, refund_fls + 4U);
            EB_WRITE_DROPS(refund_txn + EB_PAYMENT_AMOUNT_OUT, EB_READ_PENDING_U64(pending, EB_REC_PAID));
            EB_COPY_20(refund_txn + EB_PAYMENT_ACCOUNT_OUT, hook_acc);
            EB_COPY_20(refund_txn + EB_PAYMENT_DEST_OUT, pending + EB_REC_BUYER);
            EB_WRITE_DROPS(refund_txn + EB_PAYMENT_FEE_OUT, 0U);
            if (etxn_details(refund_txn + EB_PAYMENT_EMIT_OUT, EB_EMIT_DETAILS_LEN) != EB_EMIT_DETAILS_LEN)
            {
                pending[EB_REC_PHASE] = EB_PHASE_BUY_FAILED_STUCK;
                state_set(SBUF(pending), SBUF(callback_key));
                EB_ACCEPT("ephemeral_broker_hook: refund emit details failed.");
            }
            int64_t refund_fee = etxn_fee_base(SBUF(refund_txn));
            if (refund_fee < 0)
            {
                pending[EB_REC_PHASE] = EB_PHASE_BUY_FAILED_STUCK;
                state_set(SBUF(pending), SBUF(callback_key));
                EB_ACCEPT("ephemeral_broker_hook: refund fee calc failed.");
            }
            EB_WRITE_DROPS(refund_txn + EB_PAYMENT_FEE_OUT, (uint64_t)refund_fee);

            uint8_t refund_hash[32];
            if (emit(SBUF(refund_hash), SBUF(refund_txn)) < 0)
            {
                pending[EB_REC_PHASE] = EB_PHASE_BUY_FAILED_STUCK;
                state_set(SBUF(pending), SBUF(callback_key));
                EB_ACCEPT("ephemeral_broker_hook: refund emit failed.");
            }

            pending[EB_REC_PHASE] = EB_PHASE_REFUND_PENDING;
            if (state_set(SBUF(pending), SBUF(refund_hash)) != EB_PENDING_VALUE_LEN)
            {
                pending[EB_REC_PHASE] = EB_PHASE_REFUND_FAILED_STUCK;
                state_set(SBUF(pending), SBUF(callback_key));
                EB_ACCEPT("ephemeral_broker_hook: refund state handoff failed.");
            }
            state_set(0, 0, SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: refund emitted.");
        }

        /* v3: same optional memo as the buy leg (hook_param works in cbak) */
        uint8_t cb_memo[EB_MEMO_MAX];
        EB_ZERO(cb_memo, EB_MEMO_MAX);
        uint32_t cb_memo_len = 0;
        EB_READ_MEMO(cb_memo, cb_memo_len);
        uint32_t cb_memo_block = EB_MEMO_BLOCK_LEN(cb_memo_len);
        uint32_t cb_remit_len = EB_REMIT_TX_LEN + cb_memo_block;
        uint32_t cb_uri_field = EB_REMIT_URITOKEN_FIELD_OUT + cb_memo_block;

        uint8_t remit_txn[EB_REMIT_TX_LEN + EB_MEMO_BLOCK_MAX];
        EB_ZERO(remit_txn, EB_REMIT_TX_LEN + EB_MEMO_BLOCK_MAX);
        remit_txn[0] = 0x12U;
        remit_txn[1] = 0x00U;
        remit_txn[2] = 0x5FU;
        remit_txn[3] = 0x22U;
        remit_txn[4] = 0x80U;
        remit_txn[8] = 0x24U;
        remit_txn[13] = 0x20U;
        remit_txn[14] = 0x1AU;
        remit_txn[19] = 0x20U;
        remit_txn[20] = 0x1BU;
        remit_txn[25] = 0x68U;
        remit_txn[34] = 0x73U;
        remit_txn[35] = 0x21U;
        remit_txn[69] = 0x81U;
        remit_txn[70] = 0x14U;
        remit_txn[91] = 0x83U;
        remit_txn[92] = 0x14U;
        remit_txn[cb_uri_field + 0] = 0x00U;
        remit_txn[cb_uri_field + 1] = 0x13U;
        remit_txn[cb_uri_field + 2] = 0x63U;
        remit_txn[cb_uri_field + 3] = 0x20U;

        if (etxn_reserve(1) < 0)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REMIT_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: remit reserve failed.");
        }

        uint32_t remit_fls = (uint32_t)ledger_seq() + 1U;
        UINT32_TO_BUF(remit_txn + EB_REMIT_FLS_OUT, remit_fls);
        UINT32_TO_BUF(remit_txn + EB_REMIT_LLS_OUT, remit_fls + 4U);
        EB_COPY_20(remit_txn + EB_REMIT_ACCOUNT_OUT, hook_acc);
        EB_COPY_20(remit_txn + EB_REMIT_DEST_OUT, pending + EB_REC_BUYER);
        EB_COPY_32(remit_txn + cb_uri_field + 4, pending + EB_REC_NFTID);
        EB_WRITE_DROPS(remit_txn + EB_REMIT_FEE_OUT, 0U);
        if (etxn_details(remit_txn + EB_REMIT_EMIT_OUT, EB_EMIT_DETAILS_LEN) != EB_EMIT_DETAILS_LEN)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REMIT_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: remit emit details failed.");
        }
        EB_WRITE_MEMO(remit_txn, EB_REMIT_URITOKEN_FIELD_OUT, cb_memo, cb_memo_len);
        int64_t remit_fee = etxn_fee_base(remit_txn, cb_remit_len);
        if (remit_fee < 0)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REMIT_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: remit fee calc failed.");
        }
        EB_WRITE_DROPS(remit_txn + EB_REMIT_FEE_OUT, (uint64_t)remit_fee);

        /* v2: the Remit also transfers the buyer's URIToken owner-reserve (RSVINC, default 0.2 XAH) out of the
         * broker - count it as a chain cost so the fee payout nets it out instead of bleeding it every sale. */
        uint8_t cb_rsv_buf[4];
        EB_ZERO(cb_rsv_buf, 4);
        uint8_t cb_rsv_key[] = {'R', 'S', 'V', 'I', 'N', 'C'};
        uint64_t cb_rsv_inc = 0;
        if (hook_param(SBUF(cb_rsv_buf), SBUF(cb_rsv_key)) == 4)
            cb_rsv_inc = UINT32_FROM_BUF(cb_rsv_buf);
        if (cb_rsv_inc == 0)
            cb_rsv_inc = EB_DEFAULT_RSV_INC;
        uint64_t remit_cost = (uint64_t)remit_fee + cb_rsv_inc;

        uint64_t chain_fees_paid = EB_READ_PENDING_U64(pending, EB_REC_CHAIN_FEES);
        if (chain_fees_paid > (~(uint64_t)0) - remit_cost)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REMIT_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: remit fee tracking overflow.");
        }
        EB_WRITE_PENDING_U64(pending, EB_REC_CHAIN_FEES, chain_fees_paid + remit_cost);

        uint8_t remit_hash[32];
        if (emit(SBUF(remit_hash), remit_txn, cb_remit_len) < 0)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REMIT_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: remit emit failed.");
        }

        pending[EB_REC_PHASE] = EB_PHASE_REMIT_PENDING;
        if (state_set(SBUF(pending), SBUF(remit_hash)) != EB_PENDING_VALUE_LEN)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REMIT_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: remit state handoff failed.");
        }
        state_set(0, 0, SBUF(callback_key));
        EB_ACCEPT("ephemeral_broker_hook: remit emitted.");
    }

    if (phase == EB_PHASE_REMIT_PENDING)
    {
        if (!tx_success)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REMIT_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: remit failed after buy.");
        }

        uint64_t gross_fee_drops = EB_READ_PENDING_U64(pending, EB_REC_FEE);
        if (gross_fee_drops == 0)
        {
            state_set(0, 0, SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: broker flow complete.");
        }

        uint64_t chain_fees_paid = EB_READ_PENDING_U64(pending, EB_REC_CHAIN_FEES);
        if (gross_fee_drops <= chain_fees_paid)
        {
            state_set(0, 0, SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: broker flow complete; no net fee.");
        }
        uint64_t net_fee_pool = gross_fee_drops - chain_fees_paid;

        uint8_t fee_txn[EB_PAYMENT_TX_LEN];
        EB_ZERO(fee_txn, EB_PAYMENT_TX_LEN);
        fee_txn[0] = 0x12U;
        fee_txn[1] = 0x00U;
        fee_txn[2] = 0x00U;
        fee_txn[3] = 0x22U;
        fee_txn[4] = 0x80U;
        fee_txn[8] = 0x24U;
        fee_txn[13] = 0x20U;
        fee_txn[14] = 0x1AU;
        fee_txn[19] = 0x20U;
        fee_txn[20] = 0x1BU;
        fee_txn[25] = 0x61U;
        fee_txn[34] = 0x68U;
        fee_txn[43] = 0x73U;
        fee_txn[44] = 0x21U;
        fee_txn[78] = 0x81U;
        fee_txn[79] = 0x14U;
        fee_txn[100] = 0x83U;
        fee_txn[101] = 0x14U;

        if (etxn_reserve(1) < 0)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee reserve failed.");
        }

        uint32_t fee_fls = (uint32_t)ledger_seq() + 1U;
        UINT32_TO_BUF(fee_txn + EB_PAYMENT_FLS_OUT, fee_fls);
        UINT32_TO_BUF(fee_txn + EB_PAYMENT_LLS_OUT, fee_fls + 4U);
        EB_WRITE_DROPS(fee_txn + EB_PAYMENT_AMOUNT_OUT, 1U);
        EB_COPY_20(fee_txn + EB_PAYMENT_ACCOUNT_OUT, hook_acc);
        EB_COPY_20(fee_txn + EB_PAYMENT_DEST_OUT, pending + EB_REC_FEE_WALLET);
        EB_WRITE_DROPS(fee_txn + EB_PAYMENT_FEE_OUT, 0U);
        if (etxn_details(fee_txn + EB_PAYMENT_EMIT_OUT, EB_EMIT_DETAILS_LEN) != EB_EMIT_DETAILS_LEN)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee emit details failed.");
        }
        int64_t fee_payment_fee = etxn_fee_base(SBUF(fee_txn));
        if (fee_payment_fee < 0)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee payment calc failed.");
        }

        if (net_fee_pool <= (uint64_t)fee_payment_fee)
        {
            state_set(0, 0, SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: broker flow complete; no net fee.");
        }
        uint64_t net_fee_to_wallet = net_fee_pool - (uint64_t)fee_payment_fee;

        uint8_t fee_hook_keylet[34];
        if (util_keylet(SBUF(fee_hook_keylet), KEYLET_ACCOUNT, hook_acc, 20, 0, 0, 0, 0) != 34
            || slot_set(SBUF(fee_hook_keylet), 11) != 11
            || slot_subfield(11, sfBalance, 12) != 12)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee payout balance check failed.");
        }
        uint8_t current_hook_balance_buf[8];
        if (slot(SBUF(current_hook_balance_buf), 12) != 8)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee payout balance unreadable.");
        }
        int64_t current_hook_balance = AMOUNT_TO_DROPS(current_hook_balance_buf);
        if (current_hook_balance < 0 || (uint64_t)current_hook_balance < net_fee_to_wallet + (uint64_t)fee_payment_fee)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee payout underfunded.");
        }
        EB_WRITE_DROPS(fee_txn + EB_PAYMENT_AMOUNT_OUT, net_fee_to_wallet);
        EB_WRITE_DROPS(fee_txn + EB_PAYMENT_FEE_OUT, (uint64_t)fee_payment_fee);

        uint8_t fee_hash[32];
        if (emit(SBUF(fee_hash), SBUF(fee_txn)) < 0)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee payment emit failed.");
        }

        pending[EB_REC_PHASE] = EB_PHASE_FEE_PENDING;
        if (state_set(SBUF(pending), SBUF(fee_hash)) != EB_PENDING_VALUE_LEN)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee state handoff failed.");
        }
        state_set(0, 0, SBUF(callback_key));
        EB_ACCEPT("ephemeral_broker_hook: fee emitted.");
    }

    if (phase == EB_PHASE_FEE_PENDING)
    {
        if (!tx_success)
        {
            pending[EB_REC_PHASE] = EB_PHASE_FEE_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: fee payment failed.");
        }

        state_set(0, 0, SBUF(callback_key));
        EB_ACCEPT("ephemeral_broker_hook: fee settled.");
    }

    if (phase == EB_PHASE_REFUND_PENDING)
    {
        if (!tx_success)
        {
            pending[EB_REC_PHASE] = EB_PHASE_REFUND_FAILED_STUCK;
            state_set(SBUF(pending), SBUF(callback_key));
            EB_ACCEPT("ephemeral_broker_hook: refund failed.");
        }

        state_set(0, 0, SBUF(callback_key));
        EB_ACCEPT("ephemeral_broker_hook: refund settled.");
    }

    EB_ACCEPT("ephemeral_broker_hook: callback phase ignored.");
}
