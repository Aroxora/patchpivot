# Disclosure log

One row per submission. Cross-references findings/<slug>/disclosure.md.

| Date | Slug | Channel | Status | Reference |
|---|---|---|---|---|
| 2026-06-01 | CVE-2026-5450-GLIBC-SCANF | psirt (glibc) | poc | ASAN confirmed off-by-one in CHAR (%mc) + WCHAR (%mC) paths; v6 patch fixes all 3 realloc sites (L859,932,987); PoC: harness/poc-reproducer.c |
| 2026-06-01 | CVE-2025-15467-OPENSSL-CMS | psirt (openssl) | poc | Return-value unbounded memcpy; ASN.1 asn1_type_get_int_oct returns full length vs max_len; PoC DER crafted; variant callers mapped |
| 2026-06-01 | CVE-2026-31431-COPYFAIL | psirt (kernel) | poc | Kernel 6.19.11 vulnerable; AEAD gcm(aes) + skcipher/hash/rng accessible; crypto/af_alg.c shared root cause |
| 2026-06-01 | CVE-2025-12727-V8-TYPECONF | Chrome VRP | analysis | 6 high-risk passes identified; cross-CVE framework (10585/13223); no V8 source checkout |
| 2026-06-01 | CVE-2025-14174-WEBKIT | Apple Bounty | analysis | 13 variant locations; 4 backend surfaces; exploit chain pairing (14174+43529) documented |
