#!/bin/sh

# This script installs the Nix package manager on your system by
# downloading a binary distribution and running its installer script
# (which in turn creates and populates /nix).

{ # Prevent execution if this script was only partially downloaded
oops() {
    echo "$0:" "$@" >&2
    exit 1
}

umask 0022

tmpDir="$(mktemp -d -t nix-binary-tarball-unpack.XXXXXXXXXX || \
          oops "Can't create temporary directory for downloading the Nix binary tarball")"
cleanup() {
    rm -rf "$tmpDir"
}
trap cleanup EXIT INT QUIT TERM

require_util() {
    command -v "$1" > /dev/null 2>&1 ||
        oops "you do not have '$1' installed, which I need to $2"
}

case "$(uname -s).$(uname -m)" in
    Linux.x86_64)
        hash=b12ab64a291e41846b9da37b7f56eafa7683deaa267bafb2ed43440ab2f45f13
        path=wqdxm0z1r4kdf9cmiqyiczbqk27v8vza/nix-2.35.6-x86_64-linux.tar.xz
        system=x86_64-linux
        ;;
    Linux.i?86)
        hash=952fe04411f0db3897e41f9be65e0cdfa031af3c101136fe6483f4bad5ffb6b1
        path=g1iy2m2nl3jmmsrslwr692567njas7kk/nix-2.35.6-i686-linux.tar.xz
        system=i686-linux
        ;;
    Linux.aarch64)
        hash=1f177b572baadf8c09750028f047fe943a3615a34f3e4a43927367a1e0120801
        path=d07531pcfzqv8q1jj90hx2nz32ra98ry/nix-2.35.6-aarch64-linux.tar.xz
        system=aarch64-linux
        ;;
    Linux.armv6l)
        hash=9bd475de3056374aa6d9bab8d1608e4c31378c6f9f6ddfa44e7f0b49ca9ee936
        path=wa2d0vkx8b9g31978xh0r3kwqcdcv7ws/nix-2.35.6-armv6l-linux.tar.xz
        system=armv6l-linux
        ;;
    Linux.armv7l)
        hash=340be0f49e764adbd53252864d8caaab227b27ccb18b4d4e4ec1286fceba70c4
        path=fgsv57pqz5pid12pl3i4k2bip84y6q2v/nix-2.35.6-armv7l-linux.tar.xz
        system=armv7l-linux
        ;;
    Linux.riscv64)
        hash=9cb51ddb6dee847651269167ad3c8518b9489c73c09d7e40cd50e5f874f0a177
        path=pk3bjgpxsvajxq64mhqvi2xy173qga0i/nix-2.35.6-riscv64-linux.tar.xz
        system=riscv64-linux
        ;;
    Darwin.x86_64)
        hash=dd73d0128d48073dc0bfc042da30cfe72f8f63f13cfbdf7b8b29e23632378019
        path=1csvj1k1hqhpxi9wc98p9v20z4a3lgdk/nix-2.35.6-x86_64-darwin.tar.xz
        system=x86_64-darwin
        ;;
    Darwin.arm64|Darwin.aarch64)
        hash=75e6c8f3f488313a074aad454483b0ec8d23b3316e1af75f2762215942729690
        path=8gkvcrrx1snr7g1w37g9skrdh8lx8kg8/nix-2.35.6-aarch64-darwin.tar.xz
        system=aarch64-darwin
        ;;
    FreeBSD.amd64|FreeBSD.x86_64)
        hash=ff7e023f958382507bf98896fdcc61dd73481db9a5d384fa114338705a1d4d98
        path=bbmpdhr54k2zy868s2qgb1rrixamvybb/nix-2.35.6-x86_64-freebsd.tar.xz
        system=x86_64-freebsd
        ;;
    *) oops "sorry, there is no binary distribution of Nix for your platform";;
esac

# Use this command-line option to fetch the tarballs using nar-serve or Cachix
if [ "${1:-}" = "--tarball-url-prefix" ]; then
    if [ -z "${2:-}" ]; then
        oops "missing argument for --tarball-url-prefix"
    fi
    url=${2}/${path}
    shift 2
else
    url=https://releases.nixos.org/nix/nix-2.35.6/nix-2.35.6-$system.tar.xz
fi

tarball=$tmpDir/nix-2.35.6-$system.tar.xz

require_util tar "unpack the binary tarball"
if [ "$(uname -s)" != "Darwin" ]; then
    require_util xz "unpack the binary tarball"
fi

if command -v curl > /dev/null 2>&1; then
    fetch() { curl --fail -L "$1" -o "$2"; }
elif command -v wget > /dev/null 2>&1; then
    fetch() { wget "$1" -O "$2"; }
else
    oops "you don't have wget or curl installed, which I need to download the binary tarball"
fi

echo "downloading Nix 2.35.6 binary tarball for $system from '$url' to '$tmpDir'..."
fetch "$url" "$tarball" || oops "failed to download '$url'"

if command -v sha256sum > /dev/null 2>&1; then
    hash2="$(sha256sum -b "$tarball" | cut -c1-64)"
elif command -v shasum > /dev/null 2>&1; then
    hash2="$(shasum -a 256 -b "$tarball" | cut -c1-64)"
elif command -v openssl > /dev/null 2>&1; then
    hash2="$(openssl dgst -r -sha256 "$tarball" | cut -c1-64)"
else
    oops "cannot verify the SHA-256 hash of '$url'; you need one of 'shasum', 'sha256sum', or 'openssl'"
fi

if [ "$hash" != "$hash2" ]; then
    oops "SHA-256 hash mismatch in '$url'; expected $hash, got $hash2"
fi

unpack=$tmpDir/unpack
mkdir -p "$unpack"
tar -xJf "$tarball" -C "$unpack" || oops "failed to unpack '$url'"

script=$(echo "$unpack"/*/install)

[ -e "$script" ] || oops "installation script is missing from the binary tarball!"
export INVOKED_FROM_INSTALL_IN=1
"$script" "$@"

} # End of wrapping
