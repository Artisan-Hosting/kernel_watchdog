#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME=$(basename "$0")
DEFAULT_SIZE_M=2
SIZE_M=$DEFAULT_SIZE_M
MODE="dry-run"
IOMEM_PATH="${AWDOG_IOMEM_PATH:-/proc/iomem}"
ALIGN_BYTES=$((2 * 1024 * 1024))
GRUB_DROPIN="/etc/default/grub.d/40-awdog-ramoops.cfg"

usage() {
  cat <<USAGE
Usage: $SCRIPT_NAME [--size-m N] [--dry-run | --apply]

Options:
  --size-m N    Reserve N MiB for ramoops (default: $DEFAULT_SIZE_M)
  --dry-run     Print discovered reservation and generated kernel args (default)
  --apply       Write GRUB drop-in and rebuild GRUB config (requires root)
  -h, --help    Show this help text
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 1
}

align_down() {
  local value=$1
  local align=$2
  echo $((value & ~(align - 1)))
}

to_hex() {
  printf '0x%x' "$1"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --size-m)
        shift
        [[ $# -gt 0 ]] || fail "--size-m requires a value"
        [[ "$1" =~ ^[0-9]+$ ]] || fail "--size-m must be a positive integer"
        [[ "$1" -ge 1 ]] || fail "--size-m must be >= 1"
        SIZE_M=$1
        ;;
      --dry-run)
        MODE="dry-run"
        ;;
      --apply)
        MODE="apply"
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
    shift
  done
}

find_region() {
  local size_bytes=$1
  local best_start=0
  local best_end=0
  local line
  local found=0

  [[ -r "$IOMEM_PATH" ]] || fail "cannot read $IOMEM_PATH"

  while IFS= read -r line; do
    if [[ "$line" =~ ^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)[[:space:]]+:[[:space:]]System[[:space:]]RAM$ ]]; then
      local start_hex=${BASH_REMATCH[1]}
      local end_hex=${BASH_REMATCH[2]}
      local start=$((16#$start_hex))
      local end=$((16#$end_hex))
      local region_size=$((end - start + 1))

      if (( region_size >= size_bytes )); then
        if (( end > best_end )); then
          best_start=$start
          best_end=$end
          found=1
        fi
      fi
    fi
  done < "$IOMEM_PATH"

  (( found == 1 )) || fail "no top-level System RAM region is large enough for ${SIZE_M} MiB"

  local candidate
  candidate=$(align_down $((best_end + 1 - size_bytes)) "$ALIGN_BYTES")
  if (( candidate < best_start )); then
    fail "found RAM region but no ${ALIGN_BYTES}-byte aligned window of ${SIZE_M} MiB inside it"
  fi

  echo "$candidate $best_start $best_end"
}

detect_grub_mkconfig_cmd() {
  if command -v grub2-mkconfig >/dev/null 2>&1; then
    echo "grub2-mkconfig"
    return 0
  fi
  if command -v grub-mkconfig >/dev/null 2>&1; then
    echo "grub-mkconfig"
    return 0
  fi
  return 1
}

detect_grub_cfg_target() {
  if [[ -f /boot/grub2/grub.cfg ]]; then
    echo "/boot/grub2/grub.cfg"
    return 0
  fi
  if [[ -f /boot/grub/grub.cfg ]]; then
    echo "/boot/grub/grub.cfg"
    return 0
  fi
  if [[ -d /boot/efi/EFI ]]; then
    local candidate
    candidate=$(find /boot/efi/EFI -maxdepth 2 -type f -name grub.cfg 2>/dev/null | head -n1 || true)
    if [[ -n "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  fi
  return 1
}

build_kernel_args() {
  local base=$1
  local size_bytes=$2
  local base_hex

  # Keep partitioning simple and proportional for arbitrary --size-m.
  local record_size=$((size_bytes / 4))
  local console_size=$((size_bytes / 4))
  local pmsg_size=$((size_bytes / 16))

  record_size=$(align_down "$record_size" 4096)
  console_size=$(align_down "$console_size" 4096)
  pmsg_size=$(align_down "$pmsg_size" 4096)

  (( record_size >= 4096 )) || record_size=4096
  (( console_size >= 4096 )) || console_size=4096
  (( pmsg_size >= 4096 )) || pmsg_size=4096

  base_hex=$(to_hex "$base")
  printf 'memmap=%sM\\$%s ramoops.mem_address=%s ramoops.mem_size=%s ramoops.record_size=%s ramoops.console_size=%s ramoops.pmsg_size=%s ramoops.ecc=0\n' \
    "$SIZE_M" "$base_hex" "$base_hex" "$(to_hex "$size_bytes")" \
    "$(to_hex "$record_size")" "$(to_hex "$console_size")" "$(to_hex "$pmsg_size")"
}

run_apply() {
  local kernel_args=$1

  (( EUID == 0 )) || fail "--apply requires root (run with sudo)"

  mkdir -p "$(dirname "$GRUB_DROPIN")"
  cat > "$GRUB_DROPIN" <<EOF_CFG
# Managed by $SCRIPT_NAME
GRUB_CMDLINE_LINUX="\$GRUB_CMDLINE_LINUX $kernel_args"
EOF_CFG

  if command -v update-grub >/dev/null 2>&1; then
    echo "Running: update-grub"
    update-grub
    return 0
  fi

  local mkconfig_cmd
  mkconfig_cmd=$(detect_grub_mkconfig_cmd) || fail "could not find grub2-mkconfig or grub-mkconfig"

  local grub_cfg
  grub_cfg=$(detect_grub_cfg_target) || fail "could not find grub.cfg target under /boot"

  echo "Running: $mkconfig_cmd -o $grub_cfg"
  "$mkconfig_cmd" -o "$grub_cfg"
}

main() {
  parse_args "$@"

  local size_bytes=$((SIZE_M * 1024 * 1024))
  local discovery
  local base
  local region_start
  local region_end
  local kernel_args

  discovery=$(find_region "$size_bytes")
  read -r base region_start region_end <<< "$discovery"
  kernel_args=$(build_kernel_args "$base" "$size_bytes")

  echo "ramoops discovery result"
  echo "  requested_size_mib: $SIZE_M"
  echo "  reserved_size_bytes: $size_bytes"
  echo "  selected_base: $(to_hex "$base")"
  echo "  selected_region: $(to_hex "$region_start")-$(to_hex "$region_end")"
  echo ""
  echo "kernel args"
  echo "  $kernel_args"

  if [[ "$MODE" == "dry-run" ]]; then
    echo ""
    echo "dry-run only; no files were changed"
    echo "apply with: sudo $0 --size-m $SIZE_M --apply"
    return 0
  fi

  run_apply "$kernel_args"

  echo ""
  echo "applied GRUB drop-in: $GRUB_DROPIN"
  echo "reboot required for reservation to take effect"
}

main "$@"
