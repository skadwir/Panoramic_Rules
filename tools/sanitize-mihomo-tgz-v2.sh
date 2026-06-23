#!/bin/sh
set -eu
umask 077

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

[ "$#" -ge 1 ] || die "Usage: $0 INPUT.tgz [OUTPUT.tgz]"

INPUT="$1"
[ -f "$INPUT" ] || die "Input archive not found: $INPUT"

if [ "$#" -ge 2 ]; then
    OUTPUT="$2"
else
    case "$INPUT" in
        *.tar.gz) OUTPUT="${INPUT%.tar.gz}-safe.tar.gz" ;;
        *.tgz) OUTPUT="${INPUT%.tgz}-safe.tgz" ;;
        *) OUTPUT="${INPUT}-safe.tgz" ;;
    esac
fi

[ "$INPUT" != "$OUTPUT" ] || die "Output must differ from input"

TMPROOT="$(mktemp -d /tmp/mihomo-sanitize.XXXXXX)" || die "mktemp failed"
trap 'rm -rf "$TMPROOT"' EXIT INT TERM HUP
WORK="$TMPROOT/work"
mkdir -p "$WORK"

tar -xzf "$INPUT" -C "$WORK" || die "Could not extract archive"

sanitize_yaml() {
    src="$1"
    tmp="${src}.tmp.$$"

    awk '
    function key_of(line, t, k) {
        t=line
        sub(/^[ \t]*/, "", t)
        sub(/^-+[ \t]*/, "", t)
        k=t
        sub(/:.*/, "", k)
        gsub(/[ \t]/, "", k)
        return tolower(k)
    }

    function replace_value(line, marker, comma) {
        comma = (line ~ /,[ \t]*$/) ? "," : ""
        sub(/:.*/, ": \"" marker "\"" comma, line)
        return line
    }

    {
        line=$0
        key=key_of(line)
        low=tolower(line)

        if (key ~ /^(secret|password|passwd|username|user|uuid|token|api-key|apikey|access-token|refresh-token|client-id|client-secret|private-key|privatekey|pre-shared-key|preshared-key|psk|age-secret-key|authorization|proxy-authorization|cookie|x-api-key)$/) {
            print replace_value(line, "__REDACTED__")
            next
        }

        if (key ~ /^(server|servername|server-name|sni|host|hostname|remote-address|remote-addr)$/) {
            print replace_value(line, "__REDACTED_HOST__")
            next
        }

        if (key ~ /^(public-key|publickey)$/) {
            print replace_value(line, "__REDACTED_PUBLIC_KEY__")
            next
        }

        if (key == "url") {
            if (low ~ /(token=|access_token=|auth=|apikey=|api_key=|key=|subscribe|subscription)/) {
                print replace_value(line, "__REDACTED_URL__")
                next
            }

            if (low !~ /(github\.com|raw\.githubusercontent\.com|githubusercontent\.com|jsdelivr\.net|metacubex)/) {
                print replace_value(line, "__REDACTED_URL__")
                next
            }
        }

        print line
    }
    ' "$src" > "$tmp" || {
        rm -f "$tmp"
        die "Failed to sanitize $src"
    }

    mv "$tmp" "$src"
}

find "$WORK" -type f \( -name "*.yaml" -o -name "*.yml" \) |
while IFS= read -r file; do
    sanitize_yaml "$file"
done

# BusyBox find may not support -delete; use -exec rm instead.
find "$WORK" -type f \( \
    -name "api-proxies.json" -o \
    -name "api-providers.json" -o \
    -name "mihomo-log.txt" -o \
    -name "*.pcap" -o \
    -name "*.pcapng" \
\) -exec rm -f {} \;

cat > "$WORK/SANITIZE_REPORT.txt" <<EOF
Sanitized:
- YAML credentials, node hosts/SNI and private URLs
Removed:
- api-proxies.json
- api-providers.json
- mihomo-log.txt
- packet captures
Note:
- No automated sanitizer can guarantee removal of unknown provider-specific fields.
EOF

TMP_OUT="${OUTPUT}.tmp.$$"
tar -czf "$TMP_OUT" -C "$WORK" . || die "Could not create output"
mv "$TMP_OUT" "$OUTPUT"

echo "[OK] Created: $OUTPUT"
ls -lh "$OUTPUT"
command -v sha256sum >/dev/null 2>&1 && sha256sum "$OUTPUT"
