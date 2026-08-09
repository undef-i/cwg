# cwg

A userspace implementation of AmneziaWG and WireGuard

## Building

```sh
git submodule update --init
make
```

## Installation

```sh
sudo install -m 0755 build/cwg /usr/local/bin/cwg
sudo ln -sf cwg /usr/local/bin/wireguard-go
sudo ln -sf cwg /usr/local/bin/amneziawg-go
```

## Usage

```sh
cwg --wg wg0
cwg --awg awg0
```

The links provide compatible entry points for `wg-quick(8)` and
`awg-quick(8)`. They select the matching mode automatically. Pass `-f` or
`--foreground` to run without forking.

## License

GNU General Public License, version 2.
