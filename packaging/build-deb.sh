#!/usr/bin/env bash
# Assemble only the ordinary governed-loop CLI; experimental executors are excluded.
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P)
case "$version" in *[!0-9A-Za-z.+:~-]*|'') exit 2;; esac
case "$arch" in amd64|arm64) ;; *) exit 2;; esac
[[ -x "$bin_dir/docket" ]] || { echo 'missing docket binary' >&2; exit 2; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
mkdir -p "$4"; out_dir=$(cd "$4" && pwd -P)
stage=$(mktemp -d "$out_dir/.stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
d=$stage/constellation-docket
install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$d/usr/share/doc/constellation-docket"
install -m 0755 "$bin_dir/docket" "$d/usr/bin/docket"
install -m 0644 "$root/LICENSE" "$d/usr/share/doc/constellation-docket/copyright"
install -m 0644 "$root/packaging/README.md" "$d/usr/share/doc/constellation-docket/"
cat > "$d/DEBIAN/control" <<CONTROL
Package: constellation-docket
Version: $version
Section: admin
Priority: optional
Architecture: $arch
Maintainer: Constellation contributors
Depends: libc6 (>= 2.35)
Description: Docket governed-loop custody and reconciliation CLI
 Inert CLI payload. Installs no issuer trust, observer/executor enrollment,
 configuration, credentials or state. Experimental VM/session executors and
 the Git work provider/broker profile are not included.
CONTROL
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out_dir/constellation-docket_${version}_${arch}.deb" >/dev/null
(cd "$out_dir" && sha256sum "constellation-docket_${version}_${arch}.deb" > "constellation-docket_${version}_${arch}.deb.sha256")
