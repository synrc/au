# NIST SP 800-53 Security Compliance & Target Profile

## Product: `synrc/au` — High-Assurance Cryptographic Audit Trail Engine

`synrc/au` is an enterprise Erlang/OTP cryptographic audit logging system
engineered to satisfy **NIST SP 800-53 Rev. 5** audit and accountability
requirements for High-Impact and FedRAMP High baseline security controls.

---

## Target Security Profile & Control Mapping

| Control ID | Control Title | Implementation & Architectural Assurance |
| :--- | :--- | :--- | :--- |
| **AU-9** | Protection of Audit Information | Audit trail immutability via cryptographic append-only SHA-384 hash chain (`audit_chain`). Protection against unauthenticated access, truncation, or history rewrite. |
| **AU-9(3)** | Cryptographic Protection | Payload encryption at rest using AES-256-GCM (`audit_crypto:encrypt/3`). Offline archive segment encryption with AEAD tag authentication (`audit_archive`). |
| **AU-10** | Non-Repudiation | Digital signatures on critical security events using ECDSA P-384 with SHA-384 (`audit_chain:append_critical_record/4`). Signed checkpoint roots (`audit_checkpoint`). RFC 3161 timestamping. |
| **SC-28** | Protection of Information at Rest | Symmetric encryption of audit metadata payloads (`audit_record:encrypt_payload/2`) and archived log segments (`audit_archive:serialize_archive/3`) using FIPS-compliant AES-256-GCM. |
| **SC-8** | Transmission Confidentiality and Integrity | Stream encryption (`audit_export:secure_stream/2`) and HMAC-SHA-512 record transmission protection (`audit_export:export_stream/2`) for remote log aggregation over untrusted networks. |
| **AU-3** | Content of Audit Records | Mandatory canonical record payload containing `Id`, `Timestamp` (UTC ms), `Plane` (security/system/application), `Subject`, `Event`, `Resource`, `Action`, `Outcome`, and `Metadata` (`audit_record`). |
| **AU-6** | Audit Record Review, Analysis, and Reporting | CRDT G-Set multi-node log set merging (`audit_merge:merge/2`), deterministic total-order linearization (`audit_merge:linearize/2`), and cluster-wide Merkle root verification (`audit_merge:global_merkle_root/1`). |
| **AU-12** | Audit Record Generation | System and API entry points (`audit_client`, `audit_core`) allowing centralized generation of audit records across application, system, and security planes. |

## Detailed Control Implementations

### 1. AU-9 & AU-9(3): Cryptographic Integrity & Encryption at Rest

- **Cryptographic Hash Chain (AU-9)**:
  Each record $R_i$ links to its predecessor via SHA-384 hash binding:
  $$H_i = \text{SHA-384}(H_{i-1} \parallel \text{CanonicalPayload}(R_i))$$
  Tampering with any historical record invalidates all downstream node hashes.

- **AES-256-GCM Payload Encryption (AU-9(3) / SC-28)**:
  Metadata payloads are encrypted using 256-bit AES-GCM with unique 96-bit initialization vectors (IVs) and 128-bit authentication tags:

  ```erlang
  audit_record:encrypt_payload(Record, EncKey)
  audit_archive:serialize_archive(Segment, Checkpoint, EncKey)
  ```

### 2. AU-10: Cryptographic Non-Repudiation

- **Digital Signatures**: Critical security events (e.g., identity modification, key rotation, privilege escalation) are individually signed by the node's private ECDSA key (`secp384r1` curve):
  ```erlang
  audit_client:log_critical_event(Record)
  audit_chain:append_critical_record(Record, HeadHash, MacKey, SecPrivKey)
  ```
- **Checkpoint Signatures**: Audit log segments are bound by periodic checkpoints signed by the node authority (`audit_checkpoint`).
- **Time-Stamp Authority (TSA) Tokens**: Proof of existence timestamp tokens generated via `audit_crypto:timestamp_token/2`.

### 3. SC-8: Transmission Confidentiality & Integrity

- Audit record streams exported to remote SIEM / syslog infrastructure are protected against transit interception and tampering via AES-256-GCM secure streaming (`audit_export:secure_stream/2`) and HMAC-SHA-512 message authentication tags (`audit_export:export_stream/2`).

### 4. CRDT Log Merging & Global Verification (AU-6)

- Supports multi-node distributed audit logging via Grow-Only Set (G-Set) CRDT semantics (`audit_merge`).
- Verification of multi-node logs via hierarchical Merkle trees over checkpoint heads (`global_merkle_root/1`).

## Test Verification & Code Coverage

- **EUnit Test Suite**: 33 automated unit tests covering key generation, signing, verifying, encryption, decryption, record validation, chain integrity, checkpoint verification, stream exporting, and CRDT merging.
- **Coverage**: **100% Test Coverage** across all Erlang modules (`audit_app`, `audit_archive`, `audit_chain`, `audit_checkpoint`, `audit_client`, `audit_core`, `audit_crypto`, `audit_export`, `audit_merge`, `audit_record`, `audit_sup`, `audit_verify`).

## Verification Commands

To verify tests and code coverage locally:

```bash
rebar3 eunit --cover
rebar3 cover
```
