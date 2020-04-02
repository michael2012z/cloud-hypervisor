// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for the flattened device tree.
pub mod fdt;
/// Module for the global interrupt controller configuration.
pub mod gic;
mod gicv2;
mod gicv3;
/// Layout for this aarch64 system.
pub mod layout;
/// Logic for configuring aarch64 registers.
pub mod regs;

use aarch64::gic::GICDevice;
use std::collections::HashMap;
use std::ffi::CStr;

use crate::RegionType;
use std::fmt::Debug;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestUsize};

// TODO -----------------------------------------
#[derive(Debug, Copy, Clone)]
/// X
pub enum BootProtocol {
    /// X
    LinuxBoot,
    /// X
    PvhBoot,
}

impl ::std::fmt::Display for BootProtocol {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            BootProtocol::LinuxBoot => write!(f, "Linux 64-bit boot protocol"),
            BootProtocol::PvhBoot => write!(f, "PVH boot protocol"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code, as well as which of the supported boot protocols
/// is to be used to configure the guest initial state.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
    /// Specifies which boot protocol to use
    pub protocol: BootProtocol,
}

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a Flattened Device Tree for this aarch64 VM.
    SetupFDT(fdt::Error),
    /// Failed to compute the initrd address.
    InitrdAddress,
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::Aarch64Setup(e)
    }
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;

pub use self::fdt::DeviceInfoForFDT;
use crate::DeviceType;

pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    let mut regions = Vec::new();
    regions.push((
        GuestAddress(layout::DRAM_MEM_START),
        size as usize,
        RegionType::Ram,
    ));

    regions
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
pub fn configure_system<T: DeviceInfoForFDT + Clone + Debug>(
    guest_mem: &GuestMemoryMmap,
    cmdline_cstring: &CStr,
    vcpu_mpidr: Vec<u64>,
    device_info: &HashMap<(DeviceType, String), T>,
    gic_device: &Box<dyn GICDevice>,
    initrd: &Option<super::InitrdConfig>,
) -> super::Result<()> {
    let dtb = fdt::create_fdt(
        guest_mem,
        cmdline_cstring,
        vcpu_mpidr,
        device_info,
        gic_device,
        initrd,
    )
    .map_err(Error::SetupFDT)?;

    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    let path = PathBuf::from("./");
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path.join("output.dtb"))
        .unwrap();
    output.write_all(&dtb).unwrap();

    Ok(())
}

/// Returns the memory address reserved for MMIO devices.
pub fn get_reserved_mem_addr() -> u64 {
    layout::MAPPED_IO_START
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::DRAM_MEM_START
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(guest_mem: &GuestMemoryMmap, initrd_size: usize) -> super::Result<u64> {
    let round_to_pagesize = |size| (size + (super::PAGE_SIZE - 1)) & !(super::PAGE_SIZE - 1);
    match GuestAddress(get_fdt_addr(&guest_mem)).checked_sub(round_to_pagesize(initrd_size) as u64)
    {
        Some(offset) => {
            if guest_mem.address_in_range(offset) {
                return Ok(offset.raw_value());
            } else {
                return Err(super::Error::Aarch64Setup(Error::InitrdAddress));
            }
        }
        None => return Err(super::Error::Aarch64Setup(Error::InitrdAddress)),
    }
}

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr(mem: &GuestMemoryMmap) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(addr) = mem.last_addr().checked_sub(layout::FDT_MAX_SIZE as u64 - 1) {
        if mem.address_in_range(addr) {
            return addr.raw_value();
        }
    }

    layout::DRAM_MEM_START
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regions_lt_1024gb() {
        let regions = arch_memory_regions(1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let regions = arch_memory_regions(1usize << 41);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(super::layout::DRAM_MEM_MAX_SIZE, regions[0].1 as u64);
    }

    #[test]
    fn test_get_fdt_addr() {
        let regions = arch_memory_regions(layout::FDT_MAX_SIZE - 0x1000);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let regions = arch_memory_regions(layout::FDT_MAX_SIZE);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let regions = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), 0x1000 + layout::DRAM_MEM_START);
    }
}
