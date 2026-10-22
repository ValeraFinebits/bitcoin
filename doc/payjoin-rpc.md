# Experimental Payjoin v2 wallet RPC

Core's experimental v2 sender uses an external receiver, directory and OHTTP relay;
[Core receiver support](payjoin-todo.md#async-v2-receiver) is planned.

Build with wallet support and `ENABLE_PAYJOIN=ON` ([instructions](payjoin-integration.md)).
Local keys and unlocking are required for acceptance and signing; publishing a signed
transaction needs no unlock. External PSBTs, external signers, v1, GUI
and automatic fallback are unsupported.

Supply the complete receiver Bitcoin URI (`pj` included) and separate HTTP(S) relay URL.
v1 can reserve inputs before failing preparation; use v2 and see [admission work](payjoin-todo.md#admission).

## Minimal workflow

Payments and `request_id` mappings last for one wallet load. Reload or restart loses RPC
access and permits reusing `request_id`; reservations may remain. See [Lifetime](#lifetime).

Use a loaded, funded, unlocked wallet on the URI's network. Replace placeholders; this URI needs an amount.

```sh
wallet='sender'
uri='RECEIVER_V2_URI_WITH_AMOUNT'
relay='https://relay.example'

bitcoin-cli -rpcwallet="$wallet" -named sendpayjoin \
  uri="$uri" relay="$relay" request_id='invoice-1'

# Copy payment_id from the reply.
payment_id='RETURNED_PAYMENT_ID'
bitcoin-cli -rpcwallet="$wallet" getpayjoin "$payment_id"
bitcoin-cli -rpcwallet="$wallet" listpayjoins
```

Supply `amount=...` in BTC if absent from URI. Replies below omit fields and use illustrative IDs:

```json
{
  "payment_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "duplicate": false,
  "payment": {"phase": "queued"}
}
```

Save `payment_id` and poll `getpayjoin`; inspect `problem`, `available_actions` and `settlement`.
Acceptance queues preparation; funding, signing or publication can still fail. Reads may miss phases.
Confirmed Payjoin:

```json
{
  "phase": "confirmed",
  "original": {"txid": "1111111111111111111111111111111111111111111111111111111111111111"},
  "selected": {"txid": "2222222222222222222222222222222222222222222222222222222222222222"},
  "settlement": {"kind": "selected", "presence": "confirmed"}
}
```

`settlement.kind=original` instead means the original confirmed, including after
explicit fallback or receiver broadcast. See RPC `help` for schemas and codes.

## Sending

| Argument | Rule |
| --- | --- |
| `amount` | BTC; required if absent from URI, otherwise must match |
| `fee_rate` | Optional sat/vB, up to three decimals; default: wallet policy |
| `max_total_fee` | Positive BTC cap on original or proposal total fee; wallet maximum is default and ceiling |
| `timeout` | Integer seconds, 1-86400, default 120; monotonic from acceptance |
| `request_id` | Optional case-sensitive 1-128 bytes without NUL; spaces preserved |

Repeat identical parameters and `request_id` for `duplicate=true`, including after lost
replies. Mismatches fail. Duplicates skip unlock, network and fee checks without resending
or extending deadlines. Errors before acceptance leave `request_id` free; later errors retain it.

Omitted and JSON `null` arguments match; amounts and fee rates compare by value. URI, relay and
`request_id` are not normalized; explicit defaults differ from omissions.

## Reading results

Reads refresh spend observations after a notification barrier and reconcile confirmed spends.
Reservations may be released when ownership and storage permit. Negotiation does not resume;
later events need another read.

`phase` describes workflow separately from spend presence and input ownership.
`queued` covers preparation; `ready` is prepared for dispatch; `negotiating` means a request
was accepted by transport, without proving receiver receipt. For `attention`, inspect `problem`
and `available_actions`. `published` and `rejected` record publication results;
`confirmed` may mean original; `conflicted` means a confirmed competing spend.

| Field | Meaning |
| --- | --- |
| `original`, `selected` | Signed original and publication choice; fallback selects original; no PSBTs returned |
| `observed_spend`, `settlement` | Known spend of original inputs; settlement denotes confirmation. A spend matching both transactions has kind `original` |
| `reservations.owned`, `reservations.locks_verified` | Ownership and current in-memory locks; no proof of database persistence |
| `possibly_exposed` | Receiver may hold and broadcast the signed original |
| `storage_uncertain` | Uncertain storage result blocks unsafe actions |

## Control commands and problems

| Command | Effect |
| --- | --- |
| `cancelpayjoin payment_id` | Stop negotiation without fallback; proven non-delivery may permit releasing inputs |
| `publishpayjoinfallback payment_id` | Select and publish saved original after ownership, storage and broadcast checks |
| `retrypayjoin payment_id retry_signing` | Sign saved receiver proposal and attempt publication on success |
| `retrypayjoin payment_id retry_publication` | Publish selected transaction again |

Retries do not restart preparation or repeat the initial POST; timeout alone does not
forbid them. Cancellation or timeout does not prove non-delivery or allow releasing inputs.
`available_actions` are hints; commands recheck conditions and network policy.

RPC errors report invalid calls, admission refusals, unknown IDs or storage/service failures.
Reads may have partial effects and fail without returning a payment object.

`payment.problem` reports the latest payment problem. Control replies return `result` and `payment`,
including partial effects on failure. Use codes, not messages, for decisions.

For `problem.code="publication"` with `available_actions=["retry_publication"]`,
resolve the cause and retry the signed transaction:

```sh
bitcoin-cli -rpcwallet="$wallet" retrypayjoin "$payment_id" retry_publication
```

```json
{"result": "completed", "payment": {"phase": "published"}}
```

Check `result` and `payment`; `published` still needs confirmation. For `refused` or `failed`,
inspect `refusal`, `payment.problem` and updated actions.

`problem.code=storage` differs from `storage_uncertain`; ownership or storage may need
reconciliation. No force-release RPC exists; manual unlocking is no general repair.

## Networking

Direct relay HTTP(S) ignores proxy environment variables; TLS verification and limits apply.
Effective Core proxies, I2P SAM, `-onlynet`, disabled DNS or inactive networking block new
payments; disabled proxies and inbound-only settings are allowed. Each HTTP handoff
rechecks policy; non-delivery cannot erase prior exposure.

Reads and cancellation remain available. No proxy, DNS or CA RPC options or automatic direct fallback exist.

`-walletbroadcast=0` blocks local publication, allowing exchange: the receiver can publish
the signed original. Later local publication may report `broadcast_disabled`.

## Lifetime

Disconnect does not cancel work. Unload stops negotiation and completes pending operations;
RPC shutdown may interrupt waits. Persisted payment records (including signed transactions),
journals, input ownership records and persistent coin locks can remain. After reload or
restart, Payjoin RPC cannot read or control previous payments; their `request_id` mappings
are lost.

Reservations can exclude inputs from coin selection while the receiver may still
publish the signed original; unloading does not make releasing them safe.
[Recovery](payjoin-todo.md#recovery) is planned. Reorg can remove settlement without resuming
negotiation or reserving inputs again.
