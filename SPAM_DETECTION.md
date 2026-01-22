# Spam Detection Algorithm

## How Guardian Detects Spam

### Detection Flow

```
Email arrives
    ↓
1. TLSH Fingerprint computed (structural hash, not content hash)
    ↓
2. LSH Bands extracted (6-char bands, 3-stride)
    ↓
3. Check LOCAL learning database (Redis lg_f:* keys)
   - If 4+ bands match known spam → check distance
   - Distance < 70 → SPAM (local match)
    ↓
4. Check ORACLE cache (Redis oc_f:* keys)
   - Same band matching logic
    ↓
5. If proximity detected → call Oracle API for confirmation
    ↓
6. Return: allow | spam
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **TLSH** | Fuzzy hash based on structure, not exact content. Similar emails = similar hash |
| **Distance** | TLSH distance metric (0-300+). Lower = more similar |
| **Threshold** | Distance < 70 = considered a match |
| **Bands** | 4+ matching bands required before flagging |

### Example Detection

```
Known spam hash:  T1A9B0C0123456789ABC...
Incoming email:   T1A9B0C0123456789XYZ...
                        ^^^^^^ (bands match)
Distance: 45 (< 70) → SPAM
```

---

## False Positive Risk

### Low Risk Because:

1. **Two-step verification** - Bands match first, then distance calculated
2. **Distance threshold (70)** - Requires high structural similarity
3. **4+ bands required** - Single band match isn't enough
4. **TLSH is structural** - Different text with same structure won't match random emails

### Possible False Positives:

| Scenario | Risk Level |
|----------|------------|
| Legitimate newsletter similar to reported spam newsletter | Medium |
| Template emails (receipts, notifications) from same provider | Low-Medium |
| Completely unrelated emails | Very Low |

### Protection Mechanisms:

1. **HAM_WEIGHT (default: 2)** - False positive reports count double
2. **Local retention (15 days)** - Bad reports expire
3. **Oracle confirmation** - Cross-checks with community data

---

## Commands

### Report Email as Spam

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"message-id":"<msg-id>","report_type":"spam"}' \
  http://localhost:12421/report
```

### Report False Positive (HAM)

If a legitimate email gets flagged:

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"message-id":"<msg-id>","report_type":"ham"}' \
  http://localhost:12421/report
```

This decreases the spam score by `HAM_WEIGHT` (2), helping correct mistakes.

### Check Current Learning Data

```bash
# Count local spam signatures
redis-cli --pass YOUR_PASS KEYS "lg_f:*" | wc -l

# See spam scores
redis-cli --pass YOUR_PASS KEYS "lg_s:*"
```

---

## Shell Aliases for Remote Servers

Add to `~/.bashrc`:

```bash
GUARDIAN_URL="http://GUARDIAN_IP:12421"

# Scan email file
gscan() {
  curl -sS -X POST -H 'Content-Type: message/rfc822' --data-binary @"$1" "$GUARDIAN_URL/analyze" | jq
}

# Report email file as spam (scans first, handles folded Message-ID headers)
greport() {
  msgid=$(sed -n '/^[Mm]essage-[Ii][Dd]:/,/^[^ \t]/{
    /^[Mm]essage-[Ii][Dd]:/{ s/^[Mm]essage-[Ii][Dd]:[[:space:]]*//; h; }
    /^[ \t]/{ s/^[ \t]*//; H; }
    /^[^ \t]/{ x; p; q; }
  }' "$1" | tr -d '\r\n')

  if [ -z "$msgid" ]; then
    echo "Error: No Message-ID found in $1"
    return 1
  fi

  echo "Scanning: $1"
  curl -sS -X POST -H 'Content-Type: message/rfc822' --data-binary @"$1" "$GUARDIAN_URL/analyze" > /dev/null

  echo "Reporting: $msgid"
  json=$(jq -n --arg mid "$msgid" '{"message-id": $mid, "report_type": "spam"}')
  curl -sS -X POST -H 'Content-Type: application/json' -d "$json" "$GUARDIAN_URL/report"
  echo ""
}

# Check Guardian status
gstatus() {
  curl -sS "$GUARDIAN_URL/status" | jq
}
```

Usage:
```bash
gscan email.eml       # Scan email
greport email.eml     # Report as spam
gstatus               # Check service status
```

---

## Batch Processing

Since `greport` is a shell function, use `for` loops (not xargs/find -exec).

**Important:** Add `sleep` to avoid Oracle rate limiting ("Too many reports from this node_id").

### Report All .msg Files in Current Directory

```bash
for f in *.msg; do greport "$f"; sleep 2; done
```

### With Progress Output

```bash
for f in *.msg; do echo "=== $f ==="; greport "$f"; sleep 2; done
```

### Include Subdirectories

```bash
for f in $(find . -name "*.msg"); do greport "$f"; sleep 2; done
```

### With Count

```bash
files=(*.msg); total=${#files[@]}; i=0
for f in "${files[@]}"; do ((i++)); echo "[$i/$total] $f"; greport "$f"; sleep 2; done
```

### Skip Already Processed (if tracking in a file)

```bash
for f in *.msg; do
  grep -q "$f" processed.txt 2>/dev/null && continue
  greport "$f" && echo "$f" >> processed.txt
  sleep 2
done
```

---

## Email Parts Used for TLSH Hashing

### 1. Normalized Body (Primary Hash)

| Source | Description |
|--------|-------------|
| `env.Text` | Plain text part of email |
| `env.HTML` | HTML part of email |
| Combined | Text + "\n\n" + HTML |

**Normalization applied:**
- Replace image URLs with "imgurl"
- Replace hex strings (8+ chars) with "****"
- Replace long numbers (6+ digits) with "****"
- Remove `style="..."` attributes
- Remove tracking params (utm_*, gclid, fbclid, etc.)
- Convert to lowercase
- Normalize whitespace

### 2. Raw Body (Secondary Hash)

- Same text + HTML, but **no normalization**
- Catches spam that evades normalization

### 3. Attachments

| Type | Minimum Size |
|------|--------------|
| Images (image/*) | 50 KB |
| Other files | 128 bytes |

---

## What is NOT Hashed

| Part | Reason |
|------|--------|
| Headers (From, To, Subject) | Too variable, easy to spoof |
| Message-ID | Unique per email |
| Date | Always different |
| Small attachments | Not enough content for TLSH |
| Inline images < 50KB | Too small |

---

## Example: What Gets Hashed

```
Email:
├── Headers (NOT hashed)
│   ├── From: spammer@evil.com
│   ├── To: victim@example.com
│   ├── Subject: You won!
│   └── Message-ID: <abc@xyz>
│
├── Text Body (HASHED - normalized + raw)
│   └── "Click here to claim your prize..."
│
├── HTML Body (HASHED - normalized + raw)
│   └── "<html>Click here to claim...</html>"
│
└── Attachments
    ├── logo.png (60KB) → HASHED
    ├── icon.png (10KB) → NOT hashed (too small)
    └── document.pdf (200KB) → HASHED
```

**Result: 4 hashes**
1. Normalized (Text + HTML)
2. Raw (Text + HTML)
3. logo.png
4. document.pdf
