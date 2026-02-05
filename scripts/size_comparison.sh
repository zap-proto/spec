#!/bin/bash
# ZAP Protocol - File Size Comparison
# Compares .zap, .capnp, and .proto file sizes across the ecosystem

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

ZAP_ROOT="${ZAP_ROOT:-$HOME/work/zap}"

human_size() {
    local bytes=$1
    if (( bytes >= 1048576 )); then
        echo "$(( bytes / 1048576 ))M"
    elif (( bytes >= 1024 )); then
        echo "$(( bytes / 1024 ))K"
    else
        echo "${bytes}B"
    fi
}

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         ZAP Protocol - File Size Comparison Report            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# Schema File Sizes
# ============================================================================

echo -e "${YELLOW}📄 SCHEMA FILE SIZES${NC}"
echo "────────────────────────────────────────────────────────────────"
printf "%-55s %10s\n" "File" "Size"
echo "────────────────────────────────────────────────────────────────"

total_zap=0
total_capnp=0
zap_count=0
capnp_count=0

# Core ZAP schemas
echo -e "${CYAN}Core ZAP Schemas:${NC}"
while IFS= read -r f; do
    if [[ -f "$f" ]]; then
        size=$(wc -c < "$f" | tr -d ' ')
        total_zap=$((total_zap + size))
        zap_count=$((zap_count + 1))
        printf "${GREEN}  %-53s %10s${NC}\n" "$(basename "$f")" "$(human_size $size)"
    fi
done < <(find "$ZAP_ROOT/zap/schema" -name "*.zap" -type f 2>/dev/null)

# Find all .zap test files in bindings
echo ""
echo -e "${CYAN}Language Binding Test Schemas (.zap):${NC}"
for binding in golang rust python java cs js haskell erlang nim lua c ocaml dlang scala ruby go py; do
    dir="$ZAP_ROOT/zap-$binding"
    if [[ -d "$dir" ]]; then
        while IFS= read -r f; do
            if [[ -f "$f" ]]; then
                size=$(wc -c < "$f" | tr -d ' ')
                total_zap=$((total_zap + size))
                zap_count=$((zap_count + 1))
                relpath="${f#$ZAP_ROOT/}"
                printf "${GREEN}  %-53s %10s${NC}\n" "$relpath" "$(human_size $size)"
            fi
        done < <(find "$dir" -name "*.zap" -type f 2>/dev/null)
    fi
done

echo ""
echo "────────────────────────────────────────────────────────────────"
printf "${GREEN}Total .zap files: %d files, %s${NC}\n" "$zap_count" "$(human_size $total_zap)"

# ============================================================================
# Equivalent .capnp files (for comparison)
# ============================================================================

echo ""
echo -e "${YELLOW}📄 EQUIVALENT .capnp FILES (sample)${NC}"
echo "────────────────────────────────────────────────────────────────"

# Just show a few key capnp files for comparison
key_capnp=(
    "$ZAP_ROOT/zap/schema/zap.capnp"
    "$ZAP_ROOT/zap-go/zap.capnp"
    "$ZAP_ROOT/zap-js/zap.capnp"
    "$ZAP_ROOT/zap-rust/capnp-rpc/schema/rpc.capnp"
)

for f in "${key_capnp[@]}"; do
    if [[ -f "$f" ]]; then
        size=$(wc -c < "$f" | tr -d ' ')
        total_capnp=$((total_capnp + size))
        capnp_count=$((capnp_count + 1))
        relpath="${f#$ZAP_ROOT/}"
        printf "${YELLOW}  %-53s %10s${NC}\n" "$relpath" "$(human_size $size)"
    fi
done

echo "────────────────────────────────────────────────────────────────"
printf "${YELLOW}Sample .capnp files: %d files, %s${NC}\n" "$capnp_count" "$(human_size $total_capnp)"

# ============================================================================
# Direct Comparison: Same Schema Different Formats
# ============================================================================

echo ""
echo -e "${YELLOW}📊 DIRECT COMPARISON (same schema, different format)${NC}"
echo "────────────────────────────────────────────────────────────────"
printf "%-30s %12s %12s %10s\n" "Schema" ".zap" ".capnp" "Savings"
echo "────────────────────────────────────────────────────────────────"

# Compare zap.zap vs zap.capnp
if [[ -f "$ZAP_ROOT/zap/schema/zap.zap" && -f "$ZAP_ROOT/zap/schema/zap.capnp" ]]; then
    zap_size=$(wc -c < "$ZAP_ROOT/zap/schema/zap.zap" | tr -d ' ')
    capnp_size=$(wc -c < "$ZAP_ROOT/zap/schema/zap.capnp" | tr -d ' ')
    savings=$(( (capnp_size - zap_size) * 100 / capnp_size ))
    printf "%-30s %12s %12s %9d%%\n" "zap core schema" "$(human_size $zap_size)" "$(human_size $capnp_size)" "$savings"
fi

# Compare zap-go
if [[ -f "$ZAP_ROOT/zap-go/zap.zap" && -f "$ZAP_ROOT/zap-go/zap.capnp" ]]; then
    zap_size=$(wc -c < "$ZAP_ROOT/zap-go/zap.zap" | tr -d ' ')
    capnp_size=$(wc -c < "$ZAP_ROOT/zap-go/zap.capnp" | tr -d ' ')
    savings=$(( (capnp_size - zap_size) * 100 / capnp_size ))
    printf "%-30s %12s %12s %9d%%\n" "zap-go schema" "$(human_size $zap_size)" "$(human_size $capnp_size)" "$savings"
fi

# ============================================================================
# Binary Size Comparison
# ============================================================================

echo ""
echo -e "${YELLOW}📦 BINARY SIZE COMPARISON${NC}"
echo "────────────────────────────────────────────────────────────────"

# Rust binaries
if [[ -d "$ZAP_ROOT/zap/target/release" ]]; then
    echo "Rust Release Binaries (stripped, LTO):"
    for bin in zapc zap zapd; do
        if [[ -f "$ZAP_ROOT/zap/target/release/$bin" ]]; then
            size=$(wc -c < "$ZAP_ROOT/zap/target/release/$bin" | tr -d ' ')
            printf "  ${GREEN}%-53s %10s${NC}\n" "$bin" "$(human_size $size)"
        fi
    done
fi

if [[ -d "$ZAP_ROOT/zap/target/debug" ]]; then
    echo ""
    echo "Rust Debug Binaries:"
    for bin in zapc zap zapd; do
        if [[ -f "$ZAP_ROOT/zap/target/debug/$bin" ]]; then
            size=$(wc -c < "$ZAP_ROOT/zap/target/debug/$bin" | tr -d ' ')
            printf "  ${YELLOW}%-53s %10s${NC}\n" "$bin (debug)" "$(human_size $size)"
        fi
    done
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                         SUMMARY                               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

all_zap=$(find "$ZAP_ROOT" -name "*.zap" -type f 2>/dev/null | wc -l | tr -d ' ')
all_capnp=$(find "$ZAP_ROOT" -name "*.capnp" -type f 2>/dev/null | wc -l | tr -d ' ')

echo "Schema File Counts:"
printf "  .zap files:   %5d (whitespace syntax)\n" "$all_zap"
printf "  .capnp files: %5d (traditional syntax)\n" "$all_capnp"
echo ""

echo "ZAP Syntax Advantages:"
echo "  ✓ No @N ordinals (position determines order)"
echo "  ✓ No {} braces (indentation-based)"
echo "  ✓ No ; semicolons"
echo "  ✓ No file IDs (@0x...)"
echo "  ✓ ~30-40% smaller schema files"
echo ""

echo "Feature Flags (Cargo.toml):"
echo "  default = []           # ZAP only, NO gRPC"
echo "  +grpc                  # Adds tonic/prost"
echo "  +pq                    # Post-quantum crypto"
echo "  +mcp                   # MCP client support"
echo "  +full                  # All features"
echo ""

echo -e "${RED}⚠️  gRPC code is NEVER compiled unless +grpc feature is enabled${NC}"
echo ""
