# SDK Configuration

The purpose of this document is to describe the simplified SDK configuration binary blob format used in the PowerAuth mobile SDK.

Instead of requiring the developer to provide three separate values (application key, application secret, and master server public key), a single Base64-encoded binary blob can be used to configure the PowerAuth mobile SDK.

## Data Format

### Primitive Data Types

The following binary format primitives are compatible with `DataReader` and `DataWriter` classes used internally in the mobile SDK:

- `Byte(N)` – Sequence of one or more bytes with fixed length.
- `Count(N)` – Number of items N, encoded as:
  - `N`, for N < 0x80 (one byte)
  - `0x8000 | N`, for N >= 0x80 && N < 0x4000 (two bytes, big endian)
  - `0xC0000000 | N`, for N >= 0x4000 && N < 0x40000000 (four bytes, big endian)
- `Data(N)` – Sequence of N bytes with variable length, encoded as:
  - `Count(N) + Byte(N)`
- `Key(ID)` – Key with identifier, encoded as:
  - `Byte(1) + Data(N)` where the first byte contains the key identifier and the data contains the key value.

### Configuration Structure

| Field name   | Data type | Description                                      |
|--------------|-----------|--------------------------------------------------|
| `VERSION`    | Byte(1)   | Version of data format. Constant `0x01`          |
| `APP_KEY`    | Byte(16)  | Binary data for `APP_KEY` constant               |
| `APP_SECRET` | Byte(16)  | Binary data for `APP_SECRET` constant            |
| `KEYS_COUNT` | Count     | Number of keys encoded in the following bytes    |
| 1st key      | Key       | First key                                        |
| Nth key      | Key       | N-th key                                         |

The sequence of bytes described above is then Base64-encoded for use in the mobile SDK.

### Key Identifiers

| Key ID | Description                                                        |
|--------|--------------------------------------------------------------------|
| `0x01` | `KEY_MASTER_P256_PUBLIC` on P-256 curve, required for protocol 3.2+ |
| `0x02` | `KEY_MASTER_ECDSA_P384_PUBLIC` on P-384 curve, required for protocol 4.0+ |
| `0x03` | `KEY_MASTER_MLDSA65_PUBLIC`, required for protocol 4.0+           |
| `0x04` | `KEY_MASTER_MLDSA87_PUBLIC`, required for protocol 4.0+           |

### Configuration Validation

The PowerAuth mobile SDK will reject the configuration if:

- A required key is missing (for example, key `0x02` is required for SDK supporting protocol 4.0+).
- `VERSION` is not supported by the implementation.
