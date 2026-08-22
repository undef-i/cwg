#!/usr/bin/env bash
set -euo pipefail

REPO=https://github.com/undef-i/cwg.git
WG_TOOLS_REPO=https://github.com/WireGuard/wireguard-tools.git
AWG_TOOLS_REPO=https://github.com/amnezia-vpn/amneziawg-tools.git
PREFIX=${PREFIX:-/usr/local}
BINDIR=${BINDIR:-$PREFIX/bin}
TOOL_PREFIX=${TOOL_PREFIX:-/usr}
TOOLS_CHOICE=
BINARY_CHOICE=
LINK_CHOICE=
NON_INTERACTIVE=0
APT_UPDATED=0
SCRIPT_DIR=
if [[ -n ${BASH_SOURCE[0]:-} ]]; then
  SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)
fi
TMP_DIRS=()

usage() {
  cat <<'EOF'
Usage: install.sh [options]

  --install-tools     install missing wg/awg tools
  --skip-tools        skip tool installation
  --prebuilt          use a prebuilt binary when available
  --source            build cwg from source
  --link              link cwg as wireguard-go/amneziawg-go
  --no-link           leave existing userspace backends unchanged
  --non-interactive   skip prompts
  --uninstall         remove cwg
EOF
}

die() {
  printf 'quickstart: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local dir
  for dir in "${TMP_DIRS[@]}"; do
    rm -rf "$dir"
  done
}
trap cleanup EXIT

run_root() {
  if (( EUID == 0 )); then
    "$@"
  else
    sudo "$@"
  fi
}

require_command() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing command: $cmd"
  done
}

set_choice() {
  local var=$1 value=$2 current
  current=${!var}
  if [[ -n $current && $current != "$value" ]]; then
    die "conflicting options for $var"
  fi
  printf -v "$var" '%s' "$value"
}

prompt_yes_no() {
  local prompt=$1 default=$2 answer
  [[ -r /dev/tty ]] || die "interactive mode requires a terminal"
  while :; do
    printf '%s' "$prompt" >&2
    IFS= read -r answer </dev/tty || die "failed to read prompt"
    answer=$(printf '%s' "${answer:-$default}" | tr -d '[:space:]')
    [[ -z $answer ]] && answer=$default
    case "${answer,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) printf 'Please answer y or n.\n' >&2 ;;
    esac
  done
}

tool_compiler() {
  command -v cc 2>/dev/null || command -v gcc 2>/dev/null \
    || command -v clang 2>/dev/null || true
}

cwg_compiler() {
  command -v musl-gcc 2>/dev/null || command -v gcc 2>/dev/null || true
}

package_manager() {
  if command -v apt-get >/dev/null 2>&1; then printf 'apt\n'
  elif command -v apk >/dev/null 2>&1; then printf 'apk\n'
  elif command -v dnf >/dev/null 2>&1; then printf 'dnf\n'
  elif command -v yum >/dev/null 2>&1; then printf 'yum\n'
  elif command -v pacman >/dev/null 2>&1; then printf 'pacman\n'
  elif command -v zypper >/dev/null 2>&1; then printf 'zypper\n'
  elif command -v xbps-install >/dev/null 2>&1; then printf 'xbps\n'
  fi
}

try_install_package() {
  local pkg=$1 manager
  manager=$(package_manager)
  case "$manager" in
    apt)
      if ! apt-cache show "$pkg" >/dev/null 2>&1; then
        if (( ! APT_UPDATED )); then
          run_root apt-get update
          APT_UPDATED=1
        fi
      fi
      apt-cache show "$pkg" >/dev/null 2>&1 || return 1
      run_root apt-get install -y "$pkg" ;;
    apk)
      apk search --exact "$pkg" >/dev/null 2>&1 || return 1
      run_root apk add --no-cache "$pkg" ;;
    dnf)
      run_root dnf install -y "$pkg" ;;
    yum)
      run_root yum install -y "$pkg" ;;
    pacman)
      run_root pacman -S --needed --noconfirm "$pkg" ;;
    zypper)
      run_root zypper --non-interactive install "$pkg" ;;
    xbps)
      run_root xbps-install -Sy "$pkg" ;;
    *)
      return 1 ;;
  esac
}

install_missing_dependencies() {
  local manager item need_compiler=0
  local -a packages=()
  manager=$(package_manager)
  printf 'quickstart: installing missing build dependencies\n'
  for item in "$@"; do
    case "$item" in
      compiler)
        need_compiler=1 ;;
      bash|ca-certificates|curl|git|make|perl|tar|unzip)
        packages+=("$item") ;;
      linux-headers)
        case "$manager" in
          apt) packages+=(linux-libc-dev) ;;
          apk|xbps) packages+=(linux-headers) ;;
          dnf|yum|zypper) packages+=(kernel-headers) ;;
          pacman) packages+=(linux-api-headers) ;;
        esac ;;
    esac
  done
  case "$manager" in
    apt)
      (( need_compiler )) && packages+=(build-essential)
      if (( ! APT_UPDATED )); then
        run_root apt-get update
        APT_UPDATED=1
      fi
      run_root apt-get install -y "${packages[@]}" ;;
    apk)
      (( need_compiler )) && packages+=(build-base)
      run_root apk add --no-cache "${packages[@]}" ;;
    dnf)
      (( need_compiler )) && packages+=(gcc)
      run_root dnf install -y "${packages[@]}" ;;
    yum)
      (( need_compiler )) && packages+=(gcc)
      run_root yum install -y "${packages[@]}" ;;
    pacman)
      (( need_compiler )) && packages+=(base-devel)
      run_root pacman -S --needed --noconfirm "${packages[@]}" ;;
    zypper)
      (( need_compiler )) && packages+=(gcc)
      run_root zypper --non-interactive install "${packages[@]}" ;;
    xbps)
      (( need_compiler )) && packages+=(base-devel)
      run_root xbps-install -Sy "${packages[@]}" ;;
    *)
      die "missing build dependencies ($*); install them with your system package manager"
      ;;
  esac
}

ensure_commands() {
  local cmd
  local -a missing=()
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if ((${#missing[@]})); then
    install_missing_dependencies "${missing[@]}"
    for cmd in "${missing[@]}"; do
      command -v "$cmd" >/dev/null 2>&1 \
        || die "dependency installation did not provide: $cmd"
    done
  fi
}

compiler_works() {
  local compiler=$1 probe
  probe=$(mktemp -d)
  printf '#include <stdio.h>\n#include <linux/types.h>\nint main(void) { return 0; }\n' > "$probe/test.c"
  if "$compiler" -x c -c "$probe/test.c" -o "$probe/test.o" \
     >/dev/null 2>&1; then
    rm -rf "$probe"
    return 0
  fi
  rm -rf "$probe"
  return 1
}

ensure_compiler() {
  local compiler=$1
  if [[ -n $compiler ]]; then
    if compiler_works "$compiler"; then
      return
    fi
  fi
  install_missing_dependencies compiler linux-headers
  compiler=$(tool_compiler)
  [[ -n $compiler ]] && compiler_works "$compiler" \
    || die "compiler installation did not provide a working C compiler"
}

systemd_unit_dir() {
  local dir
  if ! command -v systemctl >/dev/null 2>&1 \
     && [[ ! -d /run/systemd/system ]] \
     && [[ ! -d /usr/lib/systemd/system ]] \
     && [[ ! -d /lib/systemd/system ]]; then
    return 1
  fi
  dir=$(pkg-config --variable=systemdsystemunitdir systemd 2>/dev/null || true)
  if [[ -z $dir && -d /usr/lib/systemd/system ]]; then
    dir=/usr/lib/systemd/system
  fi
  if [[ -z $dir && -d /lib/systemd/system ]]; then
    dir=/lib/systemd/system
  fi
  [[ -n $dir ]] || dir=/usr/lib/systemd/system
  printf '%s\n' "$dir"
}

install_tool_repo() {
  local name=$1 url=$2 dir=$3 compiler unitdir
  local -a service_args
  ensure_commands git make bash
  compiler=$(tool_compiler)
  ensure_compiler "$compiler"
  compiler=$(tool_compiler)
  [[ -n $compiler ]] || die "a C compiler is required to build $name"
  git clone --depth 1 "$url" "$dir"
  make -C "$dir/src" CC="$compiler"
  service_args=(WITH_SYSTEMDUNITS=no)
  if unitdir=$(systemd_unit_dir); then
    service_args=(WITH_SYSTEMDUNITS=yes SYSTEMDUNITDIR="$unitdir")
  fi
  run_root make -C "$dir/src" PREFIX="$TOOL_PREFIX" \
    WITH_WGQUICK=yes WITH_BASHCOMPLETION=yes "${service_args[@]}" install
}

try_install_awg_release() {
  local arch asset url tmp extract inner host_ver req_ver
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) ;;
    *) return 1 ;;
  esac
  case "$(package_manager)" in
    apk) asset=alpine-3.19-amneziawg-tools.zip ;;
    *) asset=ubuntu-22.04-amneziawg-tools.zip ;;
  esac
  url="https://github.com/amnezia-vpn/amneziawg-tools/releases/latest/download/$asset"
  ensure_commands curl unzip
  tmp=$(mktemp -d)
  TMP_DIRS+=("$tmp")
  extract="$tmp/awg-release"
  mkdir -p "$extract"
  printf 'quickstart: trying amneziawg-tools release %s\n' "$asset"
  if ! curl -fsSL "$url" -o "$tmp/awg.zip"; then
    printf 'quickstart: failed to download %s\n' "$asset" >&2
    return 1
  fi
  if ! unzip -q "$tmp/awg.zip" -d "$extract"; then
    printf 'quickstart: failed to unzip %s\n' "$asset" >&2
    return 1
  fi
  inner=$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n 1)
  if [[ -z $inner || ! -f "$inner/awg" || ! -f "$inner/awg-quick" ]]; then
    printf 'quickstart: release archive missing awg binaries\n' >&2
    return 1
  fi
  if [[ -f "$inner/awg.sha256" ]]; then
    if ! (cd "$inner" && echo "$(awk '{print $1}' awg.sha256)  awg" | sha256sum -c - >/dev/null 2>&1); then
      printf 'quickstart: awg sha256 mismatch, falling back to source\n' >&2
      return 1
    fi
  fi
  if [[ -f "$inner/awg-quick.sha256" ]]; then
    if ! (cd "$inner" && echo "$(awk '{print $1}' awg-quick.sha256)  awg-quick" | sha256sum -c - >/dev/null 2>&1); then
      printf 'quickstart: awg-quick sha256 mismatch, falling back to source\n' >&2
      return 1
    fi
  fi
  run_root install -d "$TOOL_PREFIX/bin"
  run_root install -m 0755 "$inner/awg" "$TOOL_PREFIX/bin/awg"
  run_root install -m 0755 "$inner/awg-quick" "$TOOL_PREFIX/bin/awg-quick"
  if ! "$TOOL_PREFIX/bin/awg" --help >/dev/null 2>&1; then
    printf 'quickstart: amneziawg-tools release not compatible with this libc, falling back\n' >&2
    run_root rm -f "$TOOL_PREFIX/bin/awg" "$TOOL_PREFIX/bin/awg-quick"
    return 1
  fi
  command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1
}

install_openrc_service() {
  local name=$1 command=$2 description=$3 dir file
  dir=$(mktemp -d)
  TMP_DIRS+=("$dir")
  file="$dir/$name"
  cat > "$file" <<EOF
#!/sbin/openrc-run
name="$description"
description="$description"
CONF="\${SVCNAME#*.}"

depend() {
  need net
  use dns
}

checkconfig() {
  if [ "\$CONF" = "\$SVCNAME" ]; then
    eerror "link this script as $name.<interface>"
    return 1
  fi
}

start() {
  checkconfig || return 1
  ebegin "Starting $description for \$CONF"
  $command up "\$CONF"
  eend \$? "Failed to start $description for \$CONF"
}

stop() {
  checkconfig || return 1
  ebegin "Stopping $description for \$CONF"
  $command down "\$CONF"
  eend \$? "Failed to stop $description for \$CONF"
}
EOF
  if [[ ! -e /etc/init.d/$name ]]; then
    run_root install -m 0755 "$file" "/etc/init.d/$name"
  fi
}

install_openrc_services() {
  if systemd_unit_dir >/dev/null 2>&1 || [[ ! -x /sbin/openrc-run ]]; then
    return
  fi
  if [[ ! -e /etc/init.d/wg-quick ]]; then
    if ! try_install_package wireguard-tools-openrc; then
      install_openrc_service wg-quick wg-quick "WireGuard via wg-quick"
    fi
  fi
  if [[ ! -e /etc/init.d/awg-quick ]]; then
    install_openrc_service awg-quick awg-quick "AmneziaWG via awg-quick"
  fi
}

install_systemd_services() {
  local manager
  if ! systemd_unit_dir >/dev/null 2>&1; then
    return
  fi
  manager=$(package_manager)
  if [[ $manager = apk ]]; then
    try_install_package wireguard-tools-systemd || true
  fi
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    run_root systemctl daemon-reload
  fi
}

install_tools() {
  local tools_tmp
  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1 \
     && command -v awg >/dev/null 2>&1 \
     && command -v awg-quick >/dev/null 2>&1; then
    printf 'quickstart: wg and awg tools already installed\n'
    install_openrc_services
    install_systemd_services
    return
  fi
  tools_tmp=$(mktemp -d)
  TMP_DIRS+=("$tools_tmp")

  if ! command -v wg >/dev/null 2>&1 || \
     ! command -v wg-quick >/dev/null 2>&1; then
    if try_install_package wireguard-tools \
       && command -v wg >/dev/null 2>&1 \
       && command -v wg-quick >/dev/null 2>&1; then
      printf 'quickstart: installed wireguard-tools from the system repository\n'
    else
      printf 'quickstart: installing wireguard-tools from source\n'
      install_tool_repo wireguard-tools "$WG_TOOLS_REPO" \
        "$tools_tmp/wireguard-tools"
    fi
  fi

  if ! command -v awg >/dev/null 2>&1 || \
     ! command -v awg-quick >/dev/null 2>&1; then
    if try_install_package amneziawg-tools \
       && command -v awg >/dev/null 2>&1 \
       && command -v awg-quick >/dev/null 2>&1; then
      printf 'quickstart: installed amneziawg-tools from the system repository\n'
    elif try_install_awg_release; then
      printf 'quickstart: installed amneziawg-tools from release\n'
    else
      printf 'quickstart: installing amneziawg-tools from source\n'
      install_tool_repo amneziawg-tools "$AWG_TOOLS_REPO" \
        "$tools_tmp/amneziawg-tools"
    fi
  fi
  install_openrc_services
  install_systemd_services
}

install_prebuilt() {
  local asset arch archive extract
  arch=$(uname -m)
  arch=${arch/x86_64/amd64}
  asset="cwg-linux-$arch.tar.gz"

  ensure_commands curl tar
  extract=$(mktemp -d)
  TMP_DIRS+=("$extract")
  archive="$extract/cwg.tar.gz"
  printf 'quickstart: trying prebuilt binary for %s\n' "$arch"
  if ! curl -fsSL "https://github.com/undef-i/cwg/releases/latest/download/$asset" \
    -o "$archive"; then
    return 1
  fi
  tar -xzf "$archive" -C "$extract"
  [[ -f "$extract/cwg" ]] || return 1
  run_root install -d "$BINDIR"
  run_root install -m 0755 "$extract/cwg" "$BINDIR/cwg"
  return 0
}

source_root() {
  local root clone
  if [[ -n $SCRIPT_DIR && -f "$SCRIPT_DIR/Makefile" && \
        -d "$SCRIPT_DIR/ext/boringssl" ]]; then
    root=$SCRIPT_DIR
    if [[ ! -f "$root/ext/boringssl/crypto/cipher/asm/chacha20_poly1305_x86_64.pl" \
       && ! -f "$root/ext/boringssl/crypto/cipher/asm/chacha20_poly1305_armv8.pl" ]]; then
      git -C "$root" submodule update --init --recursive >&2
    fi
  else
    require_command git
    clone=$(mktemp -d)
    TMP_DIRS+=("$clone")
    root="$clone/cwg"
    git clone --depth 1 --recurse-submodules --shallow-submodules "$REPO" "$root" >&2
  fi
  printf '%s\n' "$root"
}

build_from_source() {
  local root compiler
  ensure_commands git make perl
  compiler=$(cwg_compiler)
  ensure_compiler "$compiler"
  compiler=$(cwg_compiler)
  [[ -n $compiler ]] || die "gcc or musl-gcc is required to build cwg"
  root=$(source_root)
  make -C "$root" CC="$compiler"
  run_root install -d "$BINDIR"
  run_root install -m 0755 "$root/build/cwg" "$BINDIR/cwg"
}

backup_link() {
  local target=$1 backup
  if [[ ! -e $target && ! -L $target ]]; then
    return
  fi
  if [[ -L $target && $(readlink "$target") == "$BINDIR/cwg" ]]; then
    return
  fi
  backup="$target.cwg-bak"
  if [[ -e $backup || -L $backup ]]; then
    backup="$target.cwg-bak.$(date +%s)"
  fi
  printf 'quickstart: backing up %s to %s\n' "$target" "$backup"
  run_root mv "$target" "$backup"
}

replace_backends() {
  run_root install -d "$BINDIR"
  backup_link "$BINDIR/wireguard-go"
  run_root ln -sfn "$BINDIR/cwg" "$BINDIR/wireguard-go"
  backup_link "$BINDIR/amneziawg-go"
  run_root ln -sfn "$BINDIR/cwg" "$BINDIR/amneziawg-go"
}

do_uninstall() {
  local target backup
  for target in "$BINDIR/cwg" "$BINDIR/wireguard-go" "$BINDIR/amneziawg-go"; do
    if [[ -L $target && $(readlink "$target") == "$BINDIR/cwg" ]]; then
      printf 'quickstart: removing link %s\n' "$target"
      run_root rm -f "$target"
    fi
  done
  if [[ -f $BINDIR/cwg && ! -L $BINDIR/cwg ]]; then
    printf 'quickstart: removing %s\n' "$BINDIR/cwg"
    run_root rm -f "$BINDIR/cwg"
  fi
  for target in "$BINDIR/wireguard-go" "$BINDIR/amneziawg-go"; do
    backup=$(ls -t "$target.cwg-bak"* 2>/dev/null | head -n 1 || true)
    if [[ -n $backup ]]; then
      printf 'quickstart: restoring %s from %s\n' "$target" "$backup"
      run_root mv "$backup" "$target"
    fi
  done
  printf 'quickstart: uninstall complete\n'
  exit 0
}

if [[ $(uname -s) != Linux ]]; then
  die "Linux is required"
fi

while (($#)); do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=1 ;;
    --install-tools) set_choice TOOLS_CHOICE install ;;
    --skip-tools) set_choice TOOLS_CHOICE skip ;;
    --prebuilt) set_choice BINARY_CHOICE prebuilt ;;
    --source) set_choice BINARY_CHOICE source ;;
    --link) set_choice LINK_CHOICE link ;;
    --no-link) set_choice LINK_CHOICE no-link ;;
    --uninstall) do_uninstall ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

if (( EUID != 0 )); then
  require_command sudo
fi

if [[ -z $TOOLS_CHOICE ]]; then
  (( NON_INTERACTIVE )) && die "choose --install-tools or --skip-tools"
  if prompt_yes_no 'install missing wg/awg tools? [Y/n] ' y; then
    TOOLS_CHOICE=install
  else
    TOOLS_CHOICE=skip
  fi
fi
if [[ $TOOLS_CHOICE = install ]]; then
  install_tools
else
  printf 'quickstart: skipping wg/awg tool installation\n'
fi

if [[ -z $BINARY_CHOICE ]]; then
  (( NON_INTERACTIVE )) && die "choose --prebuilt or --source"
  if prompt_yes_no 'use a prebuilt cwg binary when available? [Y/n] ' y; then
    BINARY_CHOICE=prebuilt
  else
    BINARY_CHOICE=source
  fi
fi
if [[ $BINARY_CHOICE = source ]]; then
  printf 'quickstart: building cwg from source\n'
  build_from_source
elif ! install_prebuilt; then
  printf 'quickstart: no usable prebuilt binary; building cwg from source\n'
  build_from_source
fi

if [[ -z $LINK_CHOICE ]]; then
  (( NON_INTERACTIVE )) && die "choose --link or --no-link"
  if prompt_yes_no 'link cwg as wireguard-go/amneziawg-go? [Y/n] ' y; then
    LINK_CHOICE=link
  else
    LINK_CHOICE=no-link
  fi
fi
if [[ $LINK_CHOICE = link ]]; then
    replace_backends
    printf 'quickstart: installed cwg and userspace backend links in %s\n' "$BINDIR"
else
  printf 'quickstart: leaving wireguard-go and amneziawg-go unchanged\n'
  printf 'quickstart: installed cwg in %s\n' "$BINDIR"
fi
