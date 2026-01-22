# TLSH and Unicode Text

## TLSH Works on Raw Bytes

TLSH doesn't care about text encoding - it processes **raw bytes**, not characters:

```
ASCII:   "Hello"     → 48 65 6C 6C 6F (5 bytes)
UTF-8:   "Hello"     → 48 65 6C 6C 6F (5 bytes, same)
UTF-8:   "สวัสดี"      → E0 B8 AA E0 B8 A7 E0 B8 B1 ... (18 bytes)
UTF-8:   "你好"       → E4 BD A0 E5 A5 BD (6 bytes)
```

TLSH sees bytes, not characters. This actually **helps** spam detection.

---

## Example: Thai Spam Variants

```
Spam v1: "คุณได้รับรางวัล คลิกที่นี่: http://evil.com/abc123"
Spam v2: "คุณได้รับรางวัล คลิกที่นี่: http://evil.com/xyz789"
                                                    ^^^^^^ (only URL differs)
```

| Bytes | Content |
|-------|---------|
| Both emails | ~95% same bytes |
| TLSH distance | ~15 (very similar, MATCH) |

---

## Why Bytes Work Better Than Characters

**Spammer trick - homoglyph attack:**

```
Legitimate: "PayPal"        → 50 61 79 50 61 6C
Spam:       "PаyPаl"        → 50 D0 B0 79 50 D0 B0 6C
                  ^  ^          (Cyrillic 'а' instead of Latin 'a')
```

| Hash Type | Result |
|-----------|--------|
| Character-based | Might see "PayPal" = "PаyPаl" |
| TLSH (byte-based) | Different bytes → different pattern |

TLSH detects the **byte pattern difference**, even if visually similar.

---

## Guardian's Normalization First

Before TLSH, Guardian normalizes the email:

```go
// From analysis.go
func normalizeEmailBody(body string) string {
    // 1. Convert to lowercase
    // 2. Remove tracking URLs
    // 3. Remove hex strings (tracking IDs)
    // 4. Normalize whitespace
    // 5. Remove image URLs
    return normalized
}
```

This happens **before** TLSH, so:

```
Input:   "สวัสดี   CLICK HERE   http://evil.com/abc123"
                  ^^^^ extra spaces  ^^^^^^ tracking

Normalized: "สวัสดี click here http://evil.com"

Then TLSH hashes the normalized bytes.
```

---

## Multi-Language Spam Detection

| Language | Works? | Why |
|----------|--------|-----|
| Thai | Yes | UTF-8 bytes are consistent |
| Chinese | Yes | Same byte patterns in similar emails |
| Japanese | Yes | Kanji/Hiragana have distinct byte patterns |
| Mixed (Thai+English) | Yes | Byte distribution captured |
| Arabic (RTL) | Yes | Bytes same regardless of display direction |

---

## Practical Example

```bash
# Scan Thai email
curl -X POST -H 'Content-Type: message/rfc822' \
  --data-binary 'From: spammer@evil.com
To: victim@example.com
Subject: =?UTF-8?B?4LiE4Li44LiT4LmE4LiU4LmJ4Lij4Lix4Lia4Lij4Liy4LiH4Lin4Lix4Lil?=
Content-Type: text/plain; charset=utf-8

คุณได้รับรางวัล 1,000,000 บาท
คลิกที่นี่: http://evil-site.com/claim' \
  http://localhost:12421/analyze
```

Response:
```json
{
  "action": "allow",
  "proximity_match": false,
  "hashes": [
    "T1B2C3D4E5F6..."
  ]
}
```

---

## Limitations

| Scenario | Issue |
|----------|-------|
| Very short emails (<50 bytes) | TLSH needs minimum content |
| Entirely different languages | Won't match (different byte distribution) |
| Same meaning, different encoding | UTF-8 vs UTF-16 → different hashes |

Guardian assumes **UTF-8** (standard for email). Most modern emails are UTF-8.

---

## Summary

```
Thai spam v1                     Thai spam v2
"คุณได้รับรางวัล..."              "คุณได้รับรางวัล..."
      ↓                                ↓
UTF-8 bytes                      UTF-8 bytes
      ↓                                ↓
Normalize                        Normalize
      ↓                                ↓
TLSH hash                        TLSH hash
      ↓                                ↓
T1A2B3C4...                      T1A2B3C5...
      └──────────┬───────────────┘
           Distance: ~20
           Result: MATCH (spam)
```

TLSH treats all languages equally - it just sees bytes.
