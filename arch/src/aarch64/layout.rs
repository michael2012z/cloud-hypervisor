// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Reference for memory layout: http://infocenter.arm.com/help/topic/com.arm.doc.den0001c/DEN0001C_principles_of_arm_memory_maps.pdf.

use vm_memory::{GuestAddress, GuestUsize};

/// Start of RAM on 64 bit ARM.
pub const DRAM_MEM_START: u64 = 0x8000_0000; // 2 GB.
/// The maximum addressable RAM address.
pub const DRAM_MEM_END: u64 = 0x00FF_8000_0000; // 1024 - 2 = 1022 GB.
/// The maximum RAM size.
pub const DRAM_MEM_MAX_SIZE: u64 = DRAM_MEM_END - DRAM_MEM_START;

/// Kernel command line start address.
pub const CMDLINE_START: usize = 0x0;
/// Kernel command line maximum size.
/// As per `arch/arm64/include/uapi/asm/setup.h`.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Maximum size of the device tree blob as specified in https://www.kernel.org/doc/Documentation/arm64/booting.txt.
pub const FDT_MAX_SIZE: usize = 0x20_0000;

// As per virt/kvm/arm/vgic/vgic-kvm-device.c we need
// the number of interrupts our GIC will support to be:
// * bigger than 32
// * less than 1023 and
// * a multiple of 32.
// We are setting up our interrupt controller to support a maximum of 128 interrupts.
/// First usable interrupt on aarch64.
pub const IRQ_BASE: u32 = 32;

/// Last usable interrupt on aarch64.
pub const IRQ_MAX: u32 = 159;

/// Below this address will reside the GIC, above this address will reside the MMIO devices.
pub const MAPPED_IO_START: u64 = 0x4000_0000; // 1 GB

/// NOTE: above layout configuration is reused from Firecracker.
// ** 32-bit reserved area (start: 1GiB, length: 1GiB) **
pub const MEM_32BIT_RESERVED_START: GuestAddress = GuestAddress(MAPPED_IO_START);
pub const MEM_32BIT_RESERVED_SIZE: GuestUsize = (1024 << 20);

// == Fixed constants within the "32-bit reserved" range ==

// Sub range: 32-bit PCI devices (start: 3GiB, length: 640Mib)
pub const MEM_32BIT_DEVICES_START: GuestAddress = MEM_32BIT_RESERVED_START;
pub const MEM_32BIT_DEVICES_SIZE: GuestUsize = (640 << 20);

// PCI MMCONFIG space (start: after the device space, length: 256MiB)
pub const PCI_MMCONFIG_START: GuestAddress =
    GuestAddress(MEM_32BIT_DEVICES_START.0 + MEM_32BIT_DEVICES_SIZE);
pub const PCI_MMCONFIG_SIZE: GuestUsize = (256 << 20);

// TODO: This is only a temp solution in prototype.
// The address should be allocated from the allocator.
// The MMIO allocator need to be updated to cover more MMIO allocation besides
// PCI-transport virtio devices.
pub const SERIAL_DEVICE_MMIO_START: u64 = PCI_MMCONFIG_START.0 + PCI_MMCONFIG_SIZE;
// Same here for RTC
pub const RTC_DEVICE_MMIO_START: u64 = SERIAL_DEVICE_MMIO_START + 0x1000;
// BAD NAME for aarch64. We uses this for the start of DRAM
pub const RAM_64BIT_START: GuestAddress = GuestAddress(0x8000_0000);

/*
/// TOTO: just to comfort the compiler
pub const IOAPIC_START: GuestAddress = GuestAddress(0xfec0_0000);
/// TOTO: just to comfort the compiler
pub const IOAPIC_SIZE: GuestUsize = 0x20;
/// TOTO: just to comfort the compiler
pub const APIC_START: GuestAddress = GuestAddress(0xfee0_0000);

// ** 32-bit reserved area (start: 3GiB, length: 1GiB) **
/// TOTO: just to comfort the compiler
pub const MEM_32BIT_RESERVED_START: GuestAddress = GuestAddress(0xc000_0000);
/// TOTO: just to comfort the compiler
pub const MEM_32BIT_RESERVED_SIZE: GuestUsize = (1024 << 20);

// == Fixed constants within the "32-bit reserved" range ==

// Sub range: 32-bit PCI devices (start: 3GiB, length: 640Mib)
/// TOTO: just to comfort the compiler
pub const MEM_32BIT_DEVICES_START: GuestAddress = MEM_32BIT_RESERVED_START;
/// TOTO: just to comfort the compiler
pub const MEM_32BIT_DEVICES_SIZE: GuestUsize = (640 << 20);

// PCI MMCONFIG space (start: after the device space, length: 256MiB)
/// TOTO: just to comfort the compiler
pub const PCI_MMCONFIG_START: GuestAddress =
    GuestAddress(MEM_32BIT_DEVICES_START.0 + MEM_32BIT_DEVICES_SIZE);
/// TOTO: just to comfort the compiler
pub const PCI_MMCONFIG_SIZE: GuestUsize = (256 << 20);

// ** 64-bit RAM start (start: 4GiB, length: varies) **
/// TOTO: just to comfort the compiler
pub const RAM_64BIT_START: GuestAddress = GuestAddress(0x1_0000_0000);
*/
