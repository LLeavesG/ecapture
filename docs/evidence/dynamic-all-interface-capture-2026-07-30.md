# Runtime all-interface capture evidence (2026-07-30)

This verifier covers communication packet capture only. It does not enable TLS
keys, TLS stream hooks, semantic hooks, or any application-decryption path.

## Test

The Linux arm64 verifier started eCapture in raw-packet mode with:

```sh
ecapture tls \
  --model pcap \
  --strategy raw_packets \
  --interfaces all \
  --pcapfile /tmp/ecapture-dynamic-interface-3.pcapng
```

After the probe reported ready, the test created and enabled a new dummy
interface named `ecapdyn1`, waited for the one-second reconciliation interval,
and generated two packets on `198.19.0.0/24`. The interface did not exist when
the BPF manager was initialized.

## Result

- eCapture reported `Attached packet capture to runtime interface` for
  `ecapdyn1`, ifindex 5.
- The PCAPNG contains six interface-description blocks: Ethernet and raw-IP
  variants for the initial `eth0` and `lo`, followed by the same two variants
  for runtime-created `ecapdyn1`.
- `ecapdyn1`'s Ethernet interface block contains both generated packets.
- `tshark` selected frames 27 and 28 by
  `frame.interface_name == ecapdyn1`; each is 98 bytes.
- The PCAPNG is 5,436 bytes with SHA-256
  `745dc4a2a5bfeff044425466fbde440027db39e5d7489c6ff5117bb65545fd65`.

PCAP mode also reported:

```text
Raw packet text output suppressed; PCAPNG remains active
```

The line-oriented output contained zero `Packet captured` records and was only
3,811 bytes. This prevents remote logging traffic from becoming new captured
traffic and forming a self-amplifying observation loop. An explicit event
collector still opts into structured packet events for offline correlation.
