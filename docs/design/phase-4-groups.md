# Phase 4 design: groups and key rotation

Status: implemented in v0.4.0. Binding contract for the packages of this
phase. Builds on Phases 2 and 3: identities, pairwise ratchet sessions and the
offline queue are unchanged.

> Like Phase 3, this is a composition of standard primitives (inspired by
> Signal's Sender Keys), not an analysed protocol. It has not been audited.

## Goals and non-goals

Goals:

- Users can create groups, add and remove members, and promote or demote
  admins. Groups have a name visible only to members.
- Group messages are end-to-end encrypted. The relay learns neither group
  names, membership lists nor which messages belong to which group (beyond
  what timing and identical payload sizes reveal).
- Removing a member rotates every remaining member's sending key, so the
  removed member cannot read later messages (post-removal security).
- Group message authenticity uses hybrid signatures (Ed25519 + ML-DSA-65).

Non-goals: MLS (RFC 9420) — evaluated below, not adopted in this phase;
reading history from before joining; strong consistency of membership under
concurrent conflicting admin actions (resolved deterministically, see rules).

## Pairwise control channel

All group management travels as **control messages over the existing pairwise
ratchet sessions** (Phase 3 envelope, plaintext `Kind = 2` group control,
`Kind = 3` sender-key distribution). So every control message is already
end-to-end encrypted, authenticated and forward-secret per recipient.

## Group state (package `internal/group`)

```
State {
  GroupID [32]   random, chosen by the creator
  Name    string (1..64 runes, no control/bidi characters)
  Epoch   uint64  incremented by every accepted membership change
  Members []ID    sorted; Admins ⊆ Members, at least one admin
  Admins  []ID
}
```

Control message (canonical CBOR, signed by the acting admin with hybridsig,
ctx `qchat/v1/group-control`, over all fields except the signature):

```
Control { 1: Version=1, 2: GroupID, 3: Epoch (the new epoch = old + 1), 4: Actor ID,
          5: Op (1 create, 2 add, 3 remove, 4 promote, 5 demote, 6 rename, 7 leave),
          6: Target ID (add/remove/promote/demote), 7: Name (create/rename),
          8: Members (create only; full initial list incl. creator),
          9: StateHash [32] (SHA-256 of the canonical state before the change; zero for create),
          10: Sig }
```

Rules (pure function `Apply(state, control, now) (newState, error)`):

- `create`: Actor = creator = sole initial admin; Members contains the actor.
- `add`, `remove`, `promote`, `demote`, `rename`: Actor must be an admin.
  `leave`: Actor must be a member and removes itself; the last admin cannot
  leave while other members remain (it must promote someone first).
  An admin cannot demote the last admin.
- `Epoch` must equal `state.Epoch + 1` and `StateHash` must match the
  receiver's current state; otherwise the control is rejected as stale or
  conflicting. Conflicts (two admins acting on the same epoch) are resolved
  deterministically: the control whose (Actor ID, SHA-256 of the encoding) is
  lexicographically smaller wins; the loser's client re-issues its change on
  top of the winner's state.
- A member that is removed deletes the group's sender keys and stops
  accepting group messages for it.
- Controls are sent by the actor to **all members of the resulting state plus
  the removed member** (so they learn about their removal), and each receiver
  forwards nothing (no gossip) in this phase.

## Sender keys (package `internal/senderkey`)

Each member has, per group, a current **sender key generation**:

```
SenderKey { GroupID, Owner ID, Generation uint32, ChainKey [32], SigningKey (hybridsig key pair) }
```

- Distribution message (sent pairwise, `Kind = 3`, canonical CBOR):
  `{1: Version=1, 2: GroupID, 3: Generation, 4: Iteration uint32 (current chain index),
  5: ChainKey [32], 6: SigningPub (hybridsig public key), 7: GroupEpoch}`.
- Chain: `MK = HMAC-SHA256(CK, 0x01)`, `CK = HMAC-SHA256(CK, 0x02)`;
  `key||nonce = HKDF-SHA256(salt = random 16-byte header salt, ikm = MK,
  info = "qchat/v1/group-message-key")`, ChaCha20-Poly1305.
- Group message header: `{1: Version=1, 2: GroupID, 3: Sender ID,
  4: Generation, 5: Iteration, 6: Salt}`. AD = CBOR(header).
  Signature: hybridsig with the generation's signing key, ctx
  `qchat/v1/group-message`, over CBOR(header) || ciphertext.
- Receivers keep the sender's chain at the newest iteration and store at most
  1000 skipped message keys per sender generation; message keys are deleted
  after use. Old generations are deleted once a newer generation of the same
  sender has delivered a message, or after 7 days.

Rotation:

- On **remove/leave**, every remaining member generates a new sender key
  generation and distributes it pairwise to the remaining members only.
  Messages under an older generation sent after the removal epoch are rejected
  (distribution messages carry `GroupEpoch`).
- On **add**, every member sends its *current* generation (at the current
  iteration) to the new member only; the new member cannot read earlier
  messages because chains only move forward.
- Every member also rotates after 1000 messages or 7 days (bounds the damage
  of a leaked chain key; chain keys alone give forward secrecy but no
  post-compromise security).

## Group message transport

Plaintext `Kind = 4` group message `{1: MsgID, 2: Sent, 3: Body}` is
encrypted once with the sender key; the resulting **group envelope**
`{1: Version=1, 2: Header, 3: Ciphertext, 4: Sig}` is sent with a new relay
frame:

| Type | Name | Direction | Body |
|---|---|---|---|
| 22 | SendMulti | C→S | `{1: To [][32] (1..256, distinct, not self), 2: Payload}` → SendResult Accepted |

The relay enqueues the identical payload once per recipient (each with its own
queue ID) and pushes it as an ordinary `Deliver`. The relay therefore sees one
sender, a recipient list and one payload size, but no group ID, name or
membership semantics. Recipients distinguish group envelopes from pairwise
envelopes by their top-level version/shape (envelope version 3 for groups).

Limits: groups have at most 256 members. Group size limit enforced by clients;
the relay limits `To` to 256 and applies queue limits per recipient.

## MLS evaluation (RFC 9420)

MLS gives logarithmic-cost rekeying (TreeKEM), strong agreement on group state
and well-analysed security, which would be preferable for large groups. It is
not adopted in this phase because (a) no maintained, audited pure-Go MLS
implementation with a post-quantum hybrid ciphersuite is available, (b)
standardised PQ ciphersuites for MLS are still drafts, and (c) a hand-written
MLS implementation would contradict the rule of not building our own complex
cryptographic protocols without review. Groups here are capped at 256 members
where pairwise fan-out of control and distribution messages is acceptable.
MLS remains the preferred path once a suitable library exists.
