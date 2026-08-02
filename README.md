AU
==

[![CI](https://github.com/synrc/au/workflows/zen/badge.svg)](https://github.com/synrc/au/actions)
[![CD](https://img.shields.io/hexpm/v/au.svg?style=flat)](https://hex.pm/packages/au)

`synrc/au` is a minimal, zero-dependency Erlang/OTP library for high-assurance audit
logging in the **ERP.1 three-plane architecture** (Security Admin BEAM, System Admin BEAM, Application BEAM).

It enforces strict privilege segregation, fail-secure append-only event logging,
distributed CRDT Merkle log merging, and compliance with **NIST SP 800-53 Rev.
5 AU (Audit and Accountability)** controls.

> [!NOTE]
> For formal mathematical models, theoretical requirements, proof of CRDT convergence,
> and the complete NIST SP 800-53 Rev. 5 attestation matrix, see the LaTeX article
> in [priv/audit.tex](file:///Users/tonpa/depot/synrc/audit/priv/audit.tex).

Features
--------

- **Zero External Dependencies**: Standard Erlang/OTP (`crypto`, `stdlib`, `kernel`, `eunit`, `common_test`).
- **NIST Cryptographic Profile**: ECDSA P-384 (`secp384r1`), SHA-384 / SHA-512 chain hashing, HMAC-SHA-512, and RFC 3161 timestamps.
- **Three-Plane Isolation Model**:
  - `Security Admin BEAM`: Holds long-term ECDSA P-384 keys and signs critical events & checkpoints.
  - `System Admin BEAM`: Central aggregator (`audit_core`) maintaining append-only hash chains and fail-secure commits.
  - `Application BEAM`: Capability-limited clients (`audit_client`) sending session events over bridge channels.
- **Distributed CRDT Merkle Merging**: Add-only Merkle-CRDT log merging for multi-node / multi-DC deployments with total order linearization.
- **Pure Offline Verification**: Tooling (`audit_verify`) for independent offline verification of record chains, signatures, and inclusion proofs without running OTP processes.
- **SIEM & Compliance Export**: Export to JSON, OSCAL assessment evidence maps, and Syslog/Wazuh CEF formats (`audit_export`).-

Architecture
------------

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Security Admin BEAM   (Security Plane)                                      │
│  • audit_crypto  : ECDSA P-384 key generation, signing, RFC 3161 TSP        │
└─────────────────────────────────────────────────────────────────────────────┘
                ▲ sealed capability channel
┌─────────────────────────────────────────────────────────────────────────────┐
│ System Admin BEAM     (Control Plane)                                       │
│  • audit_core    : gen_server log aggregator, ETS storage, fail-secure sync │
│  • audit_chain   : SHA-384 append-only chain, HMAC-SHA-512 integrity        │
│  • audit_merge   : CRDT G-Set multi-node log merging & total ordering       │
└─────────────────────────────────────────────────────────────────────────────┘
                ▲ capability bridge
┌─────────────────────────────────────────────────────────────────────────────┐
│ Application BEAM(s)   (Application Plane)                                   │
│  • audit_client  : Lightweight event generation API                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

Module Index
------------

| Module | Description | Plane |
| :--- | :--- | :--- |
| [`audit_client`](file:///Users/tonpa/depot/synrc/audit/src/audit_client.erl) | Application API for submitting standard & critical audit events | Application |
| [`audit_core`](file:///Users/tonpa/depot/synrc/audit/src/audit_core.erl) | `gen_server` aggregator, fail-secure synchronous commit (AU-5) | System Admin |
| [`audit_crypto`](file:///Users/tonpa/depot/synrc/audit/src/audit_crypto.erl) | ECDSA P-384, SHA-384/512, HMAC-SHA-512, RFC 3161 wrappers | Security Admin |
| [`audit_chain`](file:///Users/tonpa/depot/synrc/audit/src/audit_chain.erl) | Genesis calculation, `prev_hash` linking, payload serialization | System Admin |
| [`audit_checkpoint`](file:///Users/tonpa/depot/synrc/audit/src/audit_checkpoint.erl) | Merkle tree construction, Merkle roots, signed checkpoints | Security/System |
| [`audit_merge`](file:///Users/tonpa/depot/synrc/audit/src/audit_merge.erl) | CRDT G-Set multi-node log merging & total order linearization | System Admin |
| [`audit_verify`](file:///Users/tonpa/depot/synrc/audit/src/audit_verify.erl) | Pure offline chain, HMAC, and signature verifier | Tooling |
| [`audit_export`](file:///Users/tonpa/depot/synrc/audit/src/audit_export.erl) | JSON, OSCAL evidence maps, Syslog/Wazuh CEF exporters | Tooling |
| [`audit_archive`](file:///Users/tonpa/depot/synrc/audit/src/audit_archive.erl) | Cold storage log segmentation & WORM export helper | Tooling |

Quickstart & Examples
---------------------

### 1. Start the Audit Service (`audit_core`)

```erlang
{PubKey, PrivKey} = audit_crypto:generate_keypair(),
MacKey = audit_crypto:generate_mac_key(),

{ok, _Pid} = audit_core:start_link(#{
    node_id     => <<"node-datacenter-1">>,
    boot_time   => erlang:system_time(millisecond),
    mac_key     => MacKey,
    sec_keypair => {PubKey, PrivKey}
}).
```

### 2. Submit Application Audit Events (`audit_client`)

```erlang
% Standard application event
ok = audit_client:log(
    application,
    <<"user_session_101">>,
    login,
    <<"/api/v1/auth">>,
    authenticate,
    success,
    #{<<"ip">> => <<"10.0.4.2">>}
).

% Critical event requiring ECDSA P-384 signature & RFC 3161 timestamp
ok = audit_client:log_critical(
    security,
    <<"sec_admin">>,
    cert_issuance,
    <<"CA-Root-2026">>,
    issue_certificate,
    success,
    #{<<"dn">> => <<"CN=SysAdmin">>}
).
```

### 3. Generate & Verify Signed Checkpoints

```erlang
% Retrieve checkpoint from active log
Checkpoint = audit_core:get_checkpoint(),

% Verify signature offline using Security Admin public key
true = audit_checkpoint:verify(Checkpoint, PubKey).
```

### 4. Multi-Node CRDT Log Merging (`audit_merge`)

```erlang
% Merge log sets from Node A and Node B
LogSetA = audit_merge:add_node_log(audit_merge:new_log_set(), CheckpointA, RecordsA),
LogSetB = audit_merge:add_node_log(audit_merge:new_log_set(), CheckpointB, RecordsB),

MergedSet = audit_merge:merge(LogSetA, LogSetB),

% Verify entire multi-node log set
true = audit_merge:verify_merged(MergedSet, PubKey),

% Linearize into a deterministic global order
OrderedRecords = audit_merge:linearize(MergedSet).
```

### 5. Pure Offline Verification (`audit_verify`)

```erlang
GenesisHash = audit_chain:genesis_hash(<<"node-datacenter-1">>, BootTime),

case audit_verify:verify_chain(Records, GenesisHash, MacKey, PubKey) of
    ok ->
        io:format("Chain integrity verified successfully!~n");
    {error, {tampered_record, Index, BadRecord}} ->
        io:format("Tampering detected at record #~p!~n", [Index])
end.
```

### 6. Export to Wazuh / SIEM Format (`audit_export`)

```erlang
% Format record into Syslog / Wazuh CEF line
CEFLine = audit_export:to_siem(Record),

% Export records to JSON
JSONData = audit_export:to_json(Records).
```

---

Building & Testing
------------------

Compile the application:
```bash
rebar3 compile
```

Run EUnit unit tests:
```bash
rebar3 eunit --cover
```

Run Common Test integration suites:
```bash
rebar3 ct --cover
```

Run full suite with coverage report:
```bash
rebar3 do eunit, ct, cover
```

Documentation & Formal Specification
------------------------------------

Detailed formal specifications, theoretical derivations, proofs, and NIST attestation matrices are located in:
- LaTeX source: [`priv/audit.pdf`](priv/audit.pdf)
- OS.1 Taxonomy: [`../../synrc/os/os.txt`](https://os.synrc.com/os.txt)

Credits
-------

* Namdak Tonpa

