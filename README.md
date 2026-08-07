# cwg

This is a userspace implementation of WireGuard.

## Building

```sh
$ git submodule update --init
$ make
```

## Installation

```sh
$ sudo install -m 0755 build/cwg /usr/local/bin/cwg
```

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip
link add wg0 type wireguard`. With `cwg`, instead simply run:

```sh
$ cwg wg0
```

This creates an interface and forks into the background. To remove the
interface, use the usual `ip link del wg0`, or, if the system does not support
removing interfaces directly, remove its control socket:

```sh
$ rm -f /var/run/wireguard/wg0.sock
```

This causes `cwg` to shut down the interface. To run `cwg` without forking to
the background, pass `-f` or `--foreground`:

```sh
$ cwg -f wg0
```

When an interface is running, use `wg(8)` to configure it, along with the
usual `ip(8)` and `ifconfig(8)` commands. To enable debug logging, set
`LOG_LEVEL=debug`.

## License

GNU General Public License, version 2.
