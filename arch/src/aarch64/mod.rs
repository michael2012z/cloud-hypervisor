// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for the flattened device tree.
pub mod fdt;
/// Module for the global interrupt controller configuration.
pub mod gic;
/// Layout for this aarch64 system.
pub mod layout;
/// Logic for configuring aarch64 registers.
pub mod regs;

pub use self::fdt::DeviceInfoForFdt;
use crate::DeviceType;
use crate::RegionType;
use aarch64::gic::GicDevice;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Debug;
use std::sync::Arc;
use vm_memory::{
    Address, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap,
    GuestUsize,
};

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a FDT.
    SetupFdt(fdt::Error),

    /// Failed to create a GIC.
    SetupGic(gic::Error),

    /// Failed to compute the initramfs address.
    InitramfsAddress,

    /// Error configuring the general purpose registers
    RegsConfiguration(regs::Error),

    /// Error configuring the MPIDR register
    VcpuRegMpidr(hypervisor::HypervisorCpuError),
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::AArch64Setup(e)
    }
}

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
}

/// Configure the specified VCPU, and return its MPIDR.
pub fn configure_vcpu(
    fd: &Arc<dyn hypervisor::Vcpu>,
    id: u8,
    kernel_entry_point: Option<EntryPoint>,
    vm_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
) -> super::Result<u64> {
    if let Some(kernel_entry_point) = kernel_entry_point {
        regs::setup_regs(
            fd,
            id,
            kernel_entry_point.entry_addr.raw_value(),
            &vm_memory.memory(),
        )
        .map_err(Error::RegsConfiguration)?;
    }

    let mpidr = fd.read_mpidr().map_err(Error::VcpuRegMpidr)?;
    Ok(mpidr)
}

pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    vec![
        // 0 ~ 256 MiB: Reserved
        (
            GuestAddress(0),
            layout::MEM_32BIT_DEVICES_START.0 as usize,
            RegionType::Reserved,
        ),
        // 256 MiB ~ 1 G: MMIO space
        (
            layout::MEM_32BIT_DEVICES_START,
            layout::MEM_32BIT_DEVICES_SIZE as usize,
            RegionType::SubRegion,
        ),
        // 1G  ~ 2G: reserved. The leading 256M for PCIe MMCONFIG space
        (
            layout::PCI_MMCONFIG_START,
            (layout::RAM_64BIT_START - layout::PCI_MMCONFIG_START.0) as usize,
            RegionType::Reserved,
        ),
        (
            GuestAddress(layout::RAM_64BIT_START),
            size as usize,
            RegionType::Ram,
        ),
    ]
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
#[allow(clippy::too_many_arguments)]
pub fn configure_system<T: DeviceInfoForFdt + Clone + Debug, S: ::std::hash::BuildHasher>(
    vm: &Arc<dyn hypervisor::Vm>,
    guest_mem: &GuestMemoryMmap,
    cmdline_cstring: CString,
    vcpu_count: u64,
    vcpu_mpidr: Vec<u64>,
    device_info: &HashMap<(DeviceType, String), T, S>,
    initrd: &Option<super::InitramfsConfig>,
    pci_space_address: &(u64, u64),
    rsdp_addr: Option<GuestAddress>,
) -> super::Result<Box<dyn GicDevice>> {
    let gic_device = gic::kvm::create_gic(vm, vcpu_count).map_err(Error::SetupGic)?;

    /* This is a walkaround before EFI ready.
     * Append RSDP address to guest kernel command line with `acpi_rsdp=` parameter,
     * if `acpi` feature is enabled.
     * To work with this parameter, a user need to set `acpi` to `off`, `on` or `force`
     * in `--cmdline` parameter of cloud-hypervisor. */
    let cmdline = if let Some(rsdp_addr) = rsdp_addr {
        let cmdline_bytes = cmdline_cstring.to_bytes();
        let mut cmdline_string: String = String::from_utf8(cmdline_bytes.to_vec()).unwrap();
        cmdline_string.push_str(&format!(" acpi_rsdp=0x{:08x}", rsdp_addr.0));
        CString::new(cmdline_string).unwrap()
    } else {
        cmdline_cstring
    };
    debug!("cmdline: {:?}", cmdline);

    fdt::create_fdt(
        guest_mem,
        &cmdline,
        vcpu_mpidr,
        device_info,
        &*gic_device,
        initrd,
        pci_space_address,
    )
    .map_err(Error::SetupFdt)?;

    Ok(gic_device)
}

/// Returns the memory address where the initramfs could be loaded.
pub fn initramfs_load_addr(
    guest_mem: &GuestMemoryMmap,
    initramfs_size: usize,
) -> super::Result<u64> {
    let round_to_pagesize = |size| (size + (super::PAGE_SIZE - 1)) & !(super::PAGE_SIZE - 1);
    match guest_mem
        .last_addr()
        .checked_sub(round_to_pagesize(initramfs_size) as u64 - 1)
    {
        Some(offset) => {
            if guest_mem.address_in_range(offset) {
                Ok(offset.raw_value())
            } else {
                Err(super::Error::AArch64Setup(Error::InitramfsAddress))
            }
        }
        None => Err(super::Error::AArch64Setup(Error::InitramfsAddress)),
    }
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::KERNEL_START
}

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr() -> u64 {
    layout::FDT_START
}

pub fn get_host_cpu_phys_bits() -> u8 {
    // The value returned here is used to determine the physical address space size
    // for a VM (IPA size).
    // In recent kernel versions, the maximum IPA size supported by the host can be
    // known by querying cap KVM_CAP_ARM_VM_IPA_SIZE. And the IPA size for a
    // guest can be configured smaller.
    // But in Cloud-Hypervisor we simply use the maximum value for the VM.
    // Reference https://lwn.net/Articles/766767/.
    //
    // The correct way to query KVM_CAP_ARM_VM_IPA_SIZE is via rust-vmm/kvm-ioctls,
    // which wraps all IOCTL's and provides easy interface to user hypervisors.
    // For now the cap hasn't been supported. A separate patch will be submitted to
    // rust-vmm to add it.
    // So a hardcoded value is used here as a temporary solution.
    // It will be replace once rust-vmm/kvm-ioctls is ready.
    //
    40
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_memory_regions_dram() {
        let regions = arch_memory_regions((1usize << 32) as u64); //4GB
        assert_eq!(4, regions.len());
        assert_eq!(GuestAddress(layout::RAM_64BIT_START), regions[3].0);
        assert_eq!(1usize << 32, regions[3].1);
        assert_eq!(RegionType::Ram, regions[3].2);
    }
}
