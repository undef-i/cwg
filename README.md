# cwg

A userspace implementation of AmneziaWG and WireGuard

## Installation

### Prebuilt binary

```sh
sudo curl -L https://github.com/undef-i/cwg/releases/latest/download/cwg-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin
sudo ln -sf cwg /usr/local/bin/wireguard-go
sudo ln -sf cwg /usr/local/bin/amneziawg-go
```

### Build from source

```sh
git clone --recurse-submodules https://github.com/undef-i/cwg
cd cwg && make && sudo install -m 0755 build/cwg /usr/local/bin/cwg
sudo ln -sf cwg /usr/local/bin/wireguard-go
sudo ln -sf cwg /usr/local/bin/amneziawg-go
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

GNU General Public License, version 2.
