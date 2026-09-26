# android-nbd-server

Tiny TCP NBD server intended for rooted Android devices, especially ARMv7
devices, to export a physical block device such as `/dev/block/mmcblk1`
over Wi-Fi/TCP to a Linux NBD client.

## Features

- Modern NBD fixed-newstyle negotiation.
- `NBD_OPT_GO`.
- `NBD_OPT_INFO`.
- `NBD_OPT_EXPORT_NAME`.
- `NBD_OPT_LIST`.
- `NBD_OPT_ABORT`.
- Explicitly reports TLS / structured-reply as unsupported.
- Read-only by default.
- Optional read-write mode.
- `NBD_CMD_READ`.
- `NBD_CMD_WRITE`.
- `NBD_CMD_FLUSH`.
- Safe range validation.
- Up to 8 MiB per I/O request.
- No GLib, OpenSSL, GnuTLS, libnbd, Meson or Autotools dependency.
- Single-threaded request handling to keep the binary small.

## Android side

First make sure the target card is not mounted:

```sh
su
mount | grep mmcblk1
```

Unmount every filesystem on the card before exporting it.

Read-only export:

```sh
su
chmod 755 /data/local/tmp/nbd-server-android-armv7
/data/local/tmp/nbd-server-android-armv7 -v 10809 /dev/block/mmcblk1
```

Read-write export:

```sh
su
/data/local/tmp/nbd-server-android-armv7 -v --rw 10809 /dev/block/mmcblk1
```

The server listens on all IPv4 interfaces (`0.0.0.0:10809`).

You can use a custom export name:

```sh
/data/local/tmp/nbd-server-android-armv7 -n android 10809 /dev/block/mmcblk1
```

The empty NBD export name is also accepted by `NBD_OPT_GO` and
`NBD_OPT_EXPORT_NAME` as the default export.

## Arch Linux client

Install the client package and load the kernel module:

```sh
sudo pacman -S nbd
sudo modprobe nbd max_part=16
```

Then connect:

```sh
sudo nbd-client ANDROID_IP 10809 /dev/nbd0
```

Inspect:

```sh
lsblk /dev/nbd0
sudo fdisk -l /dev/nbd0
```

For a read-only test, mount the partition read-only where appropriate:

```sh
sudo mount -o ro /dev/nbd0p1 /mnt/test
```

Disconnect:

```sh
sudo nbd-client -d /dev/nbd0
```

## Important data-safety notes

Do not export a filesystem for read-write use while Android is also mounting
or modifying it. Doing so can corrupt the filesystem.

The recommended workflow for recovering/cloning a TF card is:

1. Boot Android and make sure the card is unmounted.
2. Start the server in read-only mode.
3. Connect `/dev/nbd0` on the Arch machine.
4. Create an image from `/dev/nbd0`, or inspect/copy the filesystem.
5. Disconnect before remounting the card on Android.

Example:

```sh
sudo dd if=/dev/nbd0 of=tfcard.img bs=4M status=progress conv=fsync
```

## Why this is not the full nbd-server

The upstream `NetworkBlockDevice/nbd` server is much larger and depends on
GLib and a larger build stack. This project intentionally implements only
the protocol and block I/O needed for a single Android block-device export.
