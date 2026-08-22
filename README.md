# cwg

A userspace implementation of AmneziaWG and WireGuard

## Quick Start

```sh
curl -fsSL https://raw.githubusercontent.com/undef-i/cwg/master/quickstart.sh | bash
```

To run it in a non-interactive terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/undef-i/cwg/master/quickstart.sh |
  bash -s -- --non-interactive [--install-tools/--skip-tools] \
  [--prebuilt/--source] [--link/--no-link]
```

## Install

### Prebuilt binary

```sh
curl -fsSL https://github.com/undef-i/cwg/releases/latest/download/cwg-linux-amd64.tar.gz |
  tar -xz -C /usr/local/bin
ln -sf cwg /usr/local/bin/wireguard-go
ln -sf cwg /usr/local/bin/amneziawg-go
```

### Build from source

```sh
git clone --recurse-submodules https://github.com/undef-i/cwg
cd cwg && make
install -m 0755 build/cwg /usr/local/bin/cwg
ln -sf cwg /usr/local/bin/wireguard-go
ln -sf cwg /usr/local/bin/amneziawg-go
```

## Usage

Run directly with a mode:

```sh
cwg --wg wg0
cwg --awg awg0
```

With the installed links you can also run them directly as `wireguard-go` or
`amneziawg-go`:

```sh
sudo wireguard-go wg0
sudo amneziawg-go awg0
```

`cwg --wg` or `wireguard-go` serves the WireGuard UAPI at
`/var/run/wireguard/wg0.sock`.
`cwg --awg` or `amneziawg-go` serves the AmneziaWG UAPI at
`/var/run/amneziawg/awg0.sock`.

Pass `-f` or `--foreground` to run directly without forking.

## License

GNU General Public License, version 3.
