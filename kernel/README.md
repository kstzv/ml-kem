# ML-KEM Kernel Implementation

Linux kernel implementation of ML-KEM (FIPS 203), integrated as a KPP-compatible kernel crypto module.

This directory contains the kernel-space version of the ML-KEM implementation. 
It reuses the same core cryptographic architecture as the userspace version, but replaces userspace dependencies with Linux kernel primitives such as `kzalloc`, `kfree`, `memzero_explicit`, `get_random_bytes`, atomics, scatterlists, and the kernel crypto KPP interface.

> Status: early beta / experimental kernel implementation. 
Builds successfully, loads and unloads cleanly on Linux kernel 6.12.74.

---

## Overview

The kernel implementation provides ML-KEM key encapsulation and decapsulation inside the Linux kernel.

Main design goals:

- zero external crypto-library dependencies
- explicit memory ownership and cleanup
- Linux-kernel-compatible allocation and zeroization
- reusable decapsulation contexts through a preallocated pool
- integration with the kernel crypto API through KPP
- architecture shared with the userspace implementation where possible

The current module registers a KPP algorithm named:

ml-kem

## License

This project is dual-licensed under:

- GNU General Public License v2.0
- MIT License

You may choose either license.

---

## 📬 Contact

- GitHub: kstzv(https://github.com/kstzv)
- Email: kstzavertaylo@gmail.com
