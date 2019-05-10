# Activation Code

The PowerAuth protocol 3, defines a new version of activation code, where OTP is no longer applied. The format of the code is the same (four groups, each group is composed from five Base32 characters), but the code is no longer split into `OTP` and `SHORT_ID` parts. The new code has following features:

- The whole code is now a short activation identifier, and we call it simply `ACTIVATION_CODE`. This principally means, that the code is no longer used in the cryptographic calculations.
- The code is using `CRC-16/ARC` to detect a typing errors. This is useful for scenarios, where the user needs to re-type the code manually.
- 96 out of possible 100 bits are used (80 random bits + 16 bits for CRC).

## Code Construction

1. Generate 10 random bytes
2. Calculate `CRC-16/ARC` from that 10 bytes. You can check a [reference implementation](resources/snippets/CRC16.java) in Java.
3. Append CRC-16 in big endian order at the end of random bytes.
4. Generate BASE32 representation from that 12 bytes, without padding characters.
5. Split BASE32 string into four groups, each one contains file characters. Use "-" as a separator.

## Code Validation

The validation process is quite simple:

1. Test whether the length of activation code is equal to 23. If not, then the code is not valid.
2. Remove dashes form the code.
3. Test whether the string contains only characters allowed in Base32 encoding.
4. Decode Base32 string into sequence of bytes
5. The length of decoded sequence must be 12
6. Calculate CRC-16/ARC from first 10 bytes
7. Compare the calculated value to last two bytes (in big endian order). If values doesn't match, then the code contains some mistyped characters.

### Test values

You can use following simple values to test your application's validation logic:

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
