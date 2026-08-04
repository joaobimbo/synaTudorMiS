#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

required='windows/Collect-DriverMetadata.ps1
windows/Export-Pairing.ps1
windows/Complete-PairingExport.ps1
docs/windows-final-export-runbook.md
docs/coexistence-complete-procedure.md
packaging/fprintd.service.d/10-synatlsmoc-coexist.conf
packaging/net.reactivated.Fprint.service
libfprint/fprintd-load-store-persistent-data-from-device.patch
libfprint/fprintd-isolated-prefix.patch'

printf '%s\n' "$required" | while IFS= read -r path; do
  test -f "$path" || {
    echo "Missing release input: $path" >&2
    exit 1
  }
done

if rg -n -i 'TudorFinalWindowsExport-v[0-9]+' \
     docs/windows-final-export-runbook.md docs/windows-chatgpt-handoff.md; then
  echo 'Release documentation contains machine-specific or obsolete Windows data.' >&2
  exit 1
fi

if rg -n '\$Pid\b|-Pid 0x00c9|\$Input[[:space:]]*=|-Encoding[[:space:]]+utf8NoBOM' \
     windows docs/windows-final-export-runbook.md docs/windows-chatgpt-handoff.md; then
  echo 'Release inputs contain a known PowerShell compatibility regression.' >&2
  exit 1
fi

if test -d build-fprintd; then
  manifest=$(meson introspect --installed build-fprintd)
  if printf '%s\n' "$manifest" | rg -q '"/usr/'; then
    echo 'fprintd install manifest escapes the isolated /opt prefix.' >&2
    exit 1
  fi
fi

if test -d fprintd-1.94.5/.git; then
  git -C fprintd-1.94.5 apply --check --reverse \
    "$repo/libfprint/fprintd-load-store-persistent-data-from-device.patch"
  git -C fprintd-1.94.5 apply --check --reverse \
    "$repo/libfprint/fprintd-isolated-prefix.patch"
fi

if test -x build-fprintd/src/fprintd; then
  resolved=$(ldd build-fprintd/src/fprintd | sed -n '/libfprint-2/p')
  case "$resolved" in
    *'/opt/synatlsmoc-coexist/'*) ;;
    *) echo "fprintd does not resolve isolated libfprint: $resolved" >&2; exit 1 ;;
  esac
fi

PYTHONPATH=pydrv pydrv/.venv/bin/python -m unittest discover -s pydrv/tests -v
git diff --check

echo 'Release checks passed.'
echo 'This validates inputs; it does not build a distributable package.'
