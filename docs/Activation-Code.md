# Activation Code

The activation code is a short, user-facing activation identifier. It is not used in any cryptographic calculations. All cryptographic security is established through the shared-secret exchange and subsequent protocol steps.

The activation code has the following properties:

- Format: four groups, each group composed of five Base32 characters, separated by `-`.
- The whole value is treated as a single identifier called `ACTIVATION_CODE`.
- The code is protected by an embedded checksum to detect typing errors.
- `CRC-16/ARC` is used for error detection, primarily for manual re-typing scenarios.
- 96 out of possible 100 bits are used:
    - 80 bits of randomness
    - 16 bits of CRC

## Code Construction

1. Generate 10 random bytes (80 bits of entropy).
2. Calculate `CRC-16/ARC` over those 10 bytes. You can check a [reference implementation](resources/snippets/CRC16.java) in Java.
3. Append the CRC value in big-endian order to the end of the random bytes, producing 12 bytes total.
4. Encode the resulting 12 bytes using Base32 without padding.
5. Split the Base32 string into four groups, each containing five characters, and join them using `-` as a separator:

The resulting format is following:
```
XXXXX-XXXXX-XXXXX-XXXXX
```

## Code Validation

Validation is intentionally simple and independent of the cryptographic layer:
1. Verify that the activation code length is exactly 23 characters (including dashes). If not, the code is invalid.
2. Remove all `-` characters.
3. Verify that the remaining string contains only characters allowed by Base32 encoding.
4. Decode the Base32 string into bytes.
5. Verify that the decoded byte array length is exactly 12.
6. Compute `CRC-16/ARC` over the first 10 bytes.
7. Compare the computed CRC with the last two bytes (interpreted as big-endian).
If the values do not match, the activation code contains mistyped or corrupted characters.

## Test Values

You can use the following values to test validation logic.

- `AAAAA-AAAAA-AAAAA-AAAAA`
- `LLLLL-LLLLL-LLLLL-LQJTA`
- `KKKKK-KKKKK-KKKKK-KDJNQ`
- `MMMMM-MMMMM-MMMMM-MUTOA`
- `VVVVV-VVVVV-VVVVV-VTFVA`
- `55555-55555-55555-55YMA`

Random values:

- `W65WE-3T7VI-7FBS2-A4OYA`
- `DD7P5-SY4RW-XHSNB-GO52A`
- `X3TS3-TI35Z-JZDNT-TRPFA`
- `HCPJX-U4QC4-7UISL-NJYMA`
- `XHGSM-KYQDT-URE34-UZGWQ`
- `45AWJ-BVACS-SBWHS-ABANA`
