# Fuzzy Hashing (TLSH) Explained

## Traditional Hash vs Fuzzy Hash

### Traditional hash (MD5, SHA256):

```
"Hello World"     → 2C74FD17...
"Hello World!"    → 86FB269D...  (completely different!)
"hello world"     → B94D27B9...  (completely different!)
```

One character change = completely different hash. Useless for spam detection.

### Fuzzy hash (TLSH):

```
"Hello World"     → T1A9B0C012345678...
"Hello World!"    → T1A9B0C012345679...  (very similar, distance ~5)
"hello world"     → T1A9B0C112345678...  (similar, distance ~15)
```

Similar content = similar hash. Perfect for detecting spam variants.

---

## What "Structure" Means

TLSH analyzes **patterns** in the document, not literal content:

| Feature | What TLSH Captures |
|---------|-------------------|
| **Byte distribution** | Frequency of characters (lots of 'e'? many numbers?) |
| **Chunk patterns** | How content is distributed across the document |
| **Length quartiles** | Document divided into 4 parts, each analyzed |
| **Trigram frequencies** | 3-byte sliding window patterns |

---

## Example: Spam Variants

**Spam email 1:**
```
Dear Customer,
Your account has been locked. Click here to verify:
http://evil-site.com/abc123
```

**Spam email 2:**
```
Dear Customer,
Your account has been locked. Click here to verify:
http://evil-site.com/xyz789
```

**Spam email 3:**
```
Dear User,
Your account has been suspended. Click here to verify:
http://different-evil.com/qwerty
```

| Comparison | TLSH Distance | Result |
|------------|---------------|--------|
| Email 1 vs 2 | ~10 | Match (same campaign) |
| Email 1 vs 3 | ~45 | Match (similar structure) |
| Email 1 vs legitimate bank email | ~150+ | No match |

---

## How TLSH Hash is Built

```
Input email body (after normalization)
           ↓
┌─────────────────────────────────────┐
│ 1. Sliding window (5 bytes)         │
│    "Hello" → triplets: Hel, ell, llo│
├─────────────────────────────────────┤
│ 2. Bucket counting (128 buckets)    │
│    Each triplet → bucket increment  │
├─────────────────────────────────────┤
│ 3. Quartile calculation             │
│    q1, q2, q3 boundaries computed   │
├─────────────────────────────────────┤
│ 4. Digest generation                │
│    Buckets → hex codes based on     │
│    which quartile they fall into    │
└─────────────────────────────────────┘
           ↓
Output: T1A9B0C0240346339CC2CF8910F6183F...
        ││└─────────────────────────────┘
        ││        Body digest (70 chars)
        │└── Header (checksum, length, quartiles)
        └─── Version (T1)
```

---

## Why This Works for Spam

Spammers change:
- URLs (tracking IDs)
- Recipient names
- Random strings to evade detection

But they **keep**:
- Overall message structure
- Sentence patterns
- Paragraph layout
- HTML template

TLSH captures the **structure they can't easily change**.

---

## Distance Calculation

```go
// Simplified concept
func ComputeDistance(hash1, hash2 string) int {
    distance := 0

    // Compare header (length, quartiles)
    distance += headerDiff(hash1, hash2)

    // Compare each digest position
    for i := 0; i < 70; i++ {
        distance += bucketDiff(hash1[i], hash2[i])
    }

    return distance
}
```

| Distance | Meaning |
|----------|---------|
| 0 | Identical structure |
| 1-30 | Very similar (likely same document with minor edits) |
| 31-70 | Similar (likely related/variant) |
| 71-150 | Some similarity (maybe same category) |
| 150+ | Different documents |

Guardian uses **threshold 70** - anything closer is considered a match.

---

## Visual Example

### Legitimate vs Spam (NO match)

```
Legitimate email:                    Spam email:
┌────────────────────┐              ┌────────────────────┐
│ Logo               │              │ Logo               │
├────────────────────┤              ├────────────────────┤
│ Dear John,         │              │ Dear Customer,     │
│                    │              │                    │
│ Your order #12345  │              │ Your account is    │
│ has shipped.       │              │ locked. Click here │
│                    │              │ to verify now!     │
│ Track: [link]      │              │                    │
├────────────────────┤              │ [URGENT LINK]      │
│ Thanks,            │              ├────────────────────┤
│ Amazon             │              │ Security Team      │
└────────────────────┘              └────────────────────┘

TLSH distance: ~120 (different structure, NO match)
```

### Spam v1 vs Spam v2 (MATCH)

```
Spam email v1:                      Spam email v2:
┌────────────────────┐              ┌────────────────────┐
│ Dear Customer,     │              │ Dear User,         │
│                    │              │                    │
│ Your account is    │              │ Your account is    │
│ locked. Click here │              │ suspended. Click   │
│ to verify now!     │              │ to verify now!     │
│                    │              │                    │
│ [URGENT LINK]      │              │ [URGENT LINK]      │
├────────────────────┤              ├────────────────────┤
│ Security Team      │              │ Support Team       │
└────────────────────┘              └────────────────────┘

TLSH distance: ~35 (similar structure, MATCH!)
```

---

## LSH Banding (How Guardian Uses TLSH)

Comparing every email against every known spam hash would be slow. Guardian uses LSH (Locality Sensitive Hashing) to speed this up:

### Band Extraction

```
TLSH hash: T1A9B0C0240346339CC2CF8910F6183F0A0B84D37C2D...
                 └─────┘└─────┘└─────┘
                 Band 1  Band 2  Band 3  ... (6 chars each, 3-stride)
```

### How It Works

1. Extract bands from incoming email hash
2. Look up each band in Redis (`lg_f:BAND` keys)
3. If 4+ bands match a known spam hash → calculate exact distance
4. If distance < 70 → SPAM

This reduces comparisons from millions to just a few.

---

## Summary

| Concept | Traditional Hash | TLSH Fuzzy Hash |
|---------|------------------|-----------------|
| Purpose | Exact match only | Similar content detection |
| One char change | Completely different | Slightly different |
| Spam detection | Useless | Perfect |
| What it captures | Exact bytes | Document structure |
| Output | Fixed length hash | Fixed length + distance metric |
