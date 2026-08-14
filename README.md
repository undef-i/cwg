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

Run directly with an explicit mode:

```sh
cwg --wg wg0
cwg --awg awg0
```

`--wg` serves the WireGuard UAPI at `/var/run/wireguard/wg0.sock`.
`--awg` serves the AmneziaWG UAPI at `/var/run/amneziawg/awg0.sock`.

Pass `-f` or `--foreground` to run directly without forking.

The installed links provide `wireguard-go` and `amneziawg-go` compatible entry
points. `wg-quick(8)` and `awg-quick(8)` select the matching mode automatically:

```sh
sudo wg-quick up wg0
sudo awg-quick up awg0
```

## License

GNU General Public License, version 2.
