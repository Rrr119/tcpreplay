#!/usr/bin/env python3
#
# Integration test for tcprewrite --bidipnat.
#
# Builds a small Ethernet pcap containing IPv4 and IPv6 TCP/UDP plus an
# ICMPv4 packet, rewrites it with one bidirectional CIDR map, then verifies
# every address and checksum independently of the C implementation.

import os
import socket
import struct
import subprocess
import sys
import tempfile

IPV4_MAP = [
    ("10.0.0.0", 8, "172.16.0.0", 12),
    ("192.168.4.0", 24, "10.200.0.0", 16),
]

IPV6_MAP = [
    ("2001:db8:aaaa::", 48, "2001:db8:1111::", 48),
    ("2001:db8:bbbb::", 48, "2001:db8:2222::", 48),
]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip4_bytes(text):
    return socket.inet_aton(text)


def ip6_bytes(text):
    return socket.inet_pton(socket.AF_INET6, text)


def cidr4_match(addr, network, prefix):
    mask = ((1 << prefix) - 1) << (32 - prefix)
    value = struct.unpack("!I", ip4_bytes(addr))[0]
    net = struct.unpack("!I", ip4_bytes(network))[0]
    return (value & mask) == (net & mask)


def cidr6_match(addr, network, prefix):
    mask = ((1 << prefix) - 1) << (128 - prefix)
    value = int.from_bytes(ip6_bytes(addr), "big")
    net = int.from_bytes(ip6_bytes(network), "big")
    return (value & mask) == (net & mask)


def remap4(addr, network, prefix):
    mask = ((1 << prefix) - 1) << (32 - prefix)
    value = struct.unpack("!I", ip4_bytes(addr))[0]
    net = struct.unpack("!I", ip4_bytes(network))[0]
    return socket.inet_ntoa(struct.pack("!I", (net & mask) | (value & ~mask & 0xFFFFFFFF)))


def remap6(addr, network, prefix):
    mask = ((1 << prefix) - 1) << (128 - prefix)
    value = int.from_bytes(ip6_bytes(addr), "big")
    net = int.from_bytes(ip6_bytes(network), "big")
    return socket.inet_ntop(socket.AF_INET6, ((net & mask) | (value & ~mask & ((1 << 128) - 1))).to_bytes(16, "big"))


def expected(addr, family):
    rules = IPV4_MAP if family == 4 else IPV6_MAP
    match = cidr4_match if family == 4 else cidr6_match
    rewrite = remap4 if family == 4 else remap6

    for network, prefix, target, target_prefix in rules:
        if match(addr, network, prefix):
            return rewrite(addr, target, target_prefix)
    return addr


def tcp_segment(sport, dport, payload, seq=1, ack=1):
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | 0x18, 8192, 0, 0) + payload


def udp_datagram(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def l4_sum(src, dst, family, proto, segment):
    if family == 4:
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
    else:
        pseudo = src + dst + struct.pack("!I3xB", len(segment), proto)
    return checksum(pseudo + segment)


def finish_l4(src, dst, family, proto, segment, checksum_offset):
    value = l4_sum(src, dst, family, proto, segment)
    return segment[:checksum_offset] + struct.pack("!H", value) + segment[checksum_offset + 2 :]


def ipv4_packet(src_text, dst_text, proto, payload):
    src = ip4_bytes(src_text)
    dst = ip4_bytes(dst_text)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6_packet(src_text, dst_text, next_header, payload):
    src = ip6_bytes(src_text)
    dst = ip6_bytes(dst_text)
    header = struct.pack("!IHBB", 6 << 28, len(payload), next_header, 64) + src + dst
    return header + payload


def ethernet(ethertype, payload):
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", ethertype) + payload


def build_packets():
    packets = []

    src4, dst4 = "10.1.2.3", "192.168.4.5"
    segment = tcp_segment(40000, 80, b"GET / HTTP/1.0\r\n\r\n")
    segment = finish_l4(ip4_bytes(src4), ip4_bytes(dst4), 4, 6, segment, 16)
    packets.append(ethernet(0x0800, ipv4_packet(src4, dst4, 6, segment)))

    segment = udp_datagram(53, 40001, b"answer")
    segment = finish_l4(ip4_bytes(dst4), ip4_bytes(src4), 4, 17, segment, 6)
    packets.append(ethernet(0x0800, ipv4_packet(dst4, src4, 17, segment)))

    src6, dst6 = "2001:db8:aaaa:1::10", "2001:db8:bbbb:1::20"
    segment = tcp_segment(40002, 443, b"hello over v6")
    segment = finish_l4(ip6_bytes(src6), ip6_bytes(dst6), 6, 6, segment, 16)
    packets.append(ethernet(0x86DD, ipv6_packet(src6, dst6, 6, segment)))

    segment = udp_datagram(53, 40003, b"v6 answer")
    segment = finish_l4(ip6_bytes(dst6), ip6_bytes(src6), 6, 17, segment, 6)
    packets.append(ethernet(0x86DD, ipv6_packet(dst6, src6, 17, segment)))

    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    packets.append(ethernet(0x0800, ipv4_packet(src4, dst4, 1, icmp)))

    segment = udp_datagram(1, 2, b"x")
    segment = finish_l4(ip4_bytes("198.18.0.1"), ip4_bytes("198.18.0.2"), 4, 17, segment, 6)
    packets.append(ethernet(0x0800, ipv4_packet("198.18.0.1", "198.18.0.2", 17, segment)))

    segment = udp_datagram(3, 4, b"y")
    segment = finish_l4(ip6_bytes("2001:db8:ffff::1"), ip6_bytes("2001:db8:eeee::2"), 6, 17, segment, 6)
    packets.append(ethernet(0x86DD, ipv6_packet("2001:db8:ffff::1", "2001:db8:eeee::2", 17, segment)))

    return packets


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            f.write(struct.pack("<IIII", index + 1, 0, len(packet), len(packet)))
            f.write(packet)


def read_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        raise ValueError("short pcap")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("unknown pcap magic %s" % magic.hex())

    packets = []
    offset = 24
    while offset + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[offset : offset + 16])
        offset += 16
        packets.append(data[offset : offset + caplen])
        offset += caplen
    return packets


def parse_packet(packet):
    if len(packet) < 14:
        raise ValueError("short frame")
    ethertype = struct.unpack("!H", packet[12:14])[0]
    payload = packet[14:]
    if ethertype == 0x0800:
        ihl = (payload[0] & 0x0F) * 4
        header = payload[:ihl]
        if checksum(header) != 0:
            raise ValueError("bad IPv4 header checksum")
        family = 4
        proto = payload[9]
        src = socket.inet_ntoa(payload[12:16])
        dst = socket.inet_ntoa(payload[16:20])
        l4 = payload[ihl:]
        src_bytes, dst_bytes = payload[12:16], payload[16:20]
    elif ethertype == 0x86DD:
        family = 6
        proto = payload[6]
        src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
        l4 = payload[40 : 40 + struct.unpack("!H", payload[4:6])[0]]
        src_bytes, dst_bytes = payload[8:24], payload[24:40]
    else:
        raise ValueError("unexpected ethertype 0x%04x" % ethertype)

    if proto in (6, 17):
        if l4_sum(src_bytes, dst_bytes, family, proto, l4) != 0:
            raise ValueError("bad %s checksum for %s -> %s" % ("TCP" if proto == 6 else "UDP", src, dst))
    elif proto == 1 and family == 4:
        if checksum(l4) != 0:
            raise ValueError("bad ICMP checksum for %s -> %s" % (src, dst))

    return family, src, dst


def main():
    if len(sys.argv) != 2:
        print("usage: %s /path/to/tcprewrite" % sys.argv[0], file=sys.stderr)
        return 2

    tcprewrite = sys.argv[1]
    packets = build_packets()

    with tempfile.TemporaryDirectory() as tmpdir:
        infile = os.path.join(tmpdir, "in.pcap")
        outfile = os.path.join(tmpdir, "out.pcap")
        write_pcap(infile, packets)

        maps = ",".join(
            ["%s/%d:%s/%d" % rule for rule in IPV4_MAP]
            + ["[%s/%d]:[%s/%d]" % rule for rule in IPV6_MAP]
        )
        result = subprocess.run(
            [tcprewrite, "-i", infile, "-o", outfile, "--bidipnat=" + maps],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode:
            print("tcprewrite failed with %d:\n%s" % (result.returncode, result.stdout), file=sys.stderr)
            return 1

        rewritten = read_pcap(outfile)
        if len(rewritten) != len(packets):
            print("packet count changed: %d -> %d" % (len(packets), len(rewritten)), file=sys.stderr)
            return 1

        failures = 0
        for index, (original, packet) in enumerate(zip(packets, rewritten), 1):
            original_family, original_src, original_dst = parse_packet(original)
            family, src, dst = parse_packet(packet)
            want_src = expected(original_src, original_family)
            want_dst = expected(original_dst, original_family)

            if (family, src, dst) != (original_family, want_src, want_dst):
                print(
                    "packet %d: got %s -> %s, want %s -> %s"
                    % (index, src, dst, want_src, want_dst),
                    file=sys.stderr,
                )
                failures += 1
            else:
                print("packet %d: ok %s -> %s" % (index, src, dst))

    if failures:
        print("%d packet(s) failed" % failures, file=sys.stderr)
        return 1

    print("all %d packets rewritten correctly, checksums valid" % len(packets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
