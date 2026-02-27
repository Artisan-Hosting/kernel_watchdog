#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME=$(basename "$0")
DEFAULT_SIZE_M=2
SIZE_M=$DEFAULT_SIZE_M
MODE="dry-run"
IOMEM_PATH="${AWDOG_IOMEM_PATH:-/proc/iomem}"
BASE_ALIGN_BYTES=$((1 * 1024 * 1024))
GUARD_BYTES=$((64 * 1024 * 1024))
VERIFY=0
GRUB_DROPIN="/etc/default/grub.d/40-awdog-ramoops.cfg"

SELECTED_LINE=""
SELECTED_RANGE_START=0
SELECTED_RANGE_END=0
SELECTED_USABLE_START=0
SELECTED_USABLE_END_EXCL=0
SELECTED_BASE=0
SELECTED_END=0

usage() {
  cat <<USAGE
Usage: $SCRIPT_NAME [--size-m N] [--dry-run | --apply] [--verify]

Options:
  --size-m N    Reserve N MiB for ramoops (default: $DEFAULT_SIZE_M)
  --dry-run     Print discovered reservation and generated kernel args (default)
  --apply       Write GRUB drop-in and rebuild GRUB config (requires root)
  --verify      Print candidate validation details from /proc/iomem
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

align_up() {
  local value=$1
  local align=$2
  echo $(((value + align - 1) & ~(align - 1)))
}

to_hex() {
  printf '0x%x' "$1"
}

is_forbidden_marker() {
  local marker="${1,,}"

  [[ "$marker" == *"crash kernel"* ]] && return 0
  [[ "$marker" == kernel\ * ]] && return 0
  [[ "$marker" == *reserved* ]] && return 0
  [[ "$marker" == acpi* ]] && return 0
  return 1
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
      --verify)
        VERIFY=1
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

consider_candidate() {
  local start=$1
  local end=$2
  local forbidden=$3
  local line="$4"
  local size_bytes=$5
  local -n best_size_ref=$6
  local -n best_start_ref=$7
  local -n best_end_ref=$8
  local -n best_line_ref=$9
  local -n best_usable_start_ref=${10}
  local -n best_usable_end_excl_ref=${11}
  local -n found_ref=${12}

  local range_size
  local usable_start
  local usable_end_excl
  local usable_size

  (( forbidden == 0 )) || return 0

  range_size=$((end - start + 1))
  usable_start=$((start + GUARD_BYTES))
  usable_end_excl=$((end + 1 - GUARD_BYTES))
  usable_size=$((usable_end_excl - usable_start))

  (( usable_size >= size_bytes )) || return 0

  if (( range_size > best_size_ref )) || \
     (( range_size == best_size_ref && end > best_end_ref )); then
    best_size_ref=$range_size
    best_start_ref=$start
    best_end_ref=$end
    best_line_ref="$line"
    best_usable_start_ref=$usable_start
    best_usable_end_excl_ref=$usable_end_excl
    found_ref=1
  fi
}

find_region() {
  local size_bytes=$1
  local best_size=0
  local best_start=0
  local best_end=0
  local best_line=""
  local best_usable_start=0
  local best_usable_end_excl=0
  local found=0

  local current_active=0
  local current_forbidden=0
  local current_start=0
  local current_end=0
  local current_line=""

  local line

  [[ -r "$IOMEM_PATH" ]] || fail "cannot read $IOMEM_PATH"

  while IFS= read -r line; do
    if [[ "$line" =~ ^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)[[:space:]]+:[[:space:]](.+)$ ]]; then
      local start_hex=${BASH_REMATCH[1]}
      local end_hex=${BASH_REMATCH[2]}
      local label=${BASH_REMATCH[3]}

      if (( current_active == 1 )); then
        consider_candidate "$current_start" "$current_end" "$current_forbidden" \
          "$current_line" "$size_bytes" best_size best_start best_end best_line \
          best_usable_start best_usable_end_excl found
      fi

      current_active=0
      if [[ "${label,,}" == "system ram" ]]; then
        current_active=1
        current_forbidden=0
        current_start=$((16#$start_hex))
        current_end=$((16#$end_hex))
        current_line="$line"
      fi
      continue
    fi

    if [[ "$line" =~ ^[[:space:]]+[0-9A-Fa-f]+-[0-9A-Fa-f]+[[:space:]]+:[[:space:]](.+)$ ]] && \
       (( current_active == 1 )); then
      local child_label=${BASH_REMATCH[1]}
      if is_forbidden_marker "$child_label"; then
        current_forbidden=1
      fi
    fi
  done < "$IOMEM_PATH"

  if (( current_active == 1 )); then
    consider_candidate "$current_start" "$current_end" "$current_forbidden" \
      "$current_line" "$size_bytes" best_size best_start best_end best_line \
      best_usable_start best_usable_end_excl found
  fi

  (( found == 1 )) || fail "no top-level System RAM region is large enough for ${SIZE_M} MiB"

  local min_base max_base mid base
  min_base=$(align_up "$best_usable_start" "$BASE_ALIGN_BYTES")
  max_base=$(align_down $((best_usable_end_excl - size_bytes)) "$BASE_ALIGN_BYTES")

  if (( min_base > max_base )); then
    fail "found System RAM region but no ${BASE_ALIGN_BYTES}-byte aligned window of ${SIZE_M} MiB inside guarded range"
  fi

  mid=$((best_usable_start + ((best_usable_end_excl - best_usable_start - size_bytes) / 2)))
  base=$(align_down "$mid" "$BASE_ALIGN_BYTES")
  (( base < min_base )) && base=$min_base
  (( base > max_base )) && base=$max_base

  SELECTED_LINE="$best_line"
  SELECTED_RANGE_START=$best_start
  SELECTED_RANGE_END=$best_end
  SELECTED_USABLE_START=$best_usable_start
  SELECTED_USABLE_END_EXCL=$best_usable_end_excl
  SELECTED_BASE=$base
  SELECTED_END=$((base + size_bytes - 1))
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
  local kernel_args

  find_region "$size_bytes"
  kernel_args=$(build_kernel_args "$SELECTED_BASE" "$size_bytes")

  echo "ramoops discovery result"
  echo "  requested_size_mib: $SIZE_M"
  echo "  reserved_size_bytes: $size_bytes"
  echo "  selected_base: $(to_hex "$SELECTED_BASE")"
  echo "  selected_end: $(to_hex "$SELECTED_END")"
  echo "  selected_region: $(to_hex "$SELECTED_RANGE_START")-$(to_hex "$SELECTED_RANGE_END")"

  if (( VERIFY == 1 )); then
    echo ""
    echo "verification"
    echo "  chosen_iomem_line: $SELECTED_LINE"
    echo "  guard_band_each_side_bytes: $GUARD_BYTES"
    echo "  guarded_window: $(to_hex "$SELECTED_USABLE_START")-$(to_hex "$((SELECTED_USABLE_END_EXCL - 1))")"
    echo "  final_base_end: $(to_hex "$SELECTED_BASE")-$(to_hex "$SELECTED_END")"
  fi

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
