// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.

pub mod dist_regs;
pub mod gicv3;
pub mod gicv3_its;
pub mod icc_regs;
pub mod redist_regs;

pub use self::dist_regs::{get_dist_regs, read_ctlr, set_dist_regs, write_ctlr};
pub use self::icc_regs::{get_icc_regs, set_icc_regs};
pub use self::redist_regs::{get_redist_regs, set_redist_regs};
use crate::kvm::kvm_bindings;
use crate::Vgic;
use crate::{CpuState, Device, Vm};
use gicv3_its::KvmGicV3Its;
use std::any::Any;
use std::boxed::Box;
use std::result;
use std::sync::Arc;

/// Errors thrown while setting up the GIC.
#[derive(Debug)]
pub enum Error {
    /// Error while calling KVM ioctl for setting up the global interrupt controller.
    CreateGic(crate::HypervisorVmError),
    /// Error while setting device attributes for the GIC.
    SetDeviceAttribute(crate::HypervisorDeviceError),
    /// Error while getting device attributes for the GIC.
    GetDeviceAttribute(crate::HypervisorDeviceError),
}
type Result<T> = result::Result<T, Error>;

/// Trait for GIC devices.
pub trait KvmGicDevice: Send + Sync + Vgic {
    /// Returns the GIC version of the device
    fn version() -> u32;

    /// Create the GIC device object
    fn create_device(device: Arc<dyn Device>, vcpu_count: u64) -> Box<dyn Vgic>;

    /// Setup the device-specific attributes
    fn init_device_attributes(vm: &dyn Vm, gic_device: &mut dyn Vgic) -> Result<()>;

    /// Initialize a GIC device
    fn init_device(vm: &dyn Vm) -> Result<Arc<dyn Device>> {
        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: Self::version(),
            fd: 0,
            flags: 0,
        };

        vm.create_device(&mut gic_device).map_err(Error::CreateGic)
    }

    /// Set a GIC device attribute
    fn set_device_attribute(
        device: &Arc<dyn Device>,
        group: u32,
        attr: u64,
        addr: u64,
        flags: u32,
    ) -> Result<()> {
        let attr = kvm_bindings::kvm_device_attr {
            flags,
            group,
            attr,
            addr,
        };
        device
            .set_device_attr(&attr)
            .map_err(Error::SetDeviceAttribute)?;

        Ok(())
    }

    /// Get a GIC device attribute
    fn get_device_attribute(
        device: &Arc<dyn Device>,
        group: u32,
        attr: u64,
        addr: u64,
        flags: u32,
    ) -> Result<()> {
        let mut attr = kvm_bindings::kvm_device_attr {
            flags,
            group,
            attr,
            addr,
        };
        device
            .get_device_attr(&mut attr)
            .map_err(Error::GetDeviceAttribute)?;

        Ok(())
    }

    /// Finalize the setup of a GIC device
    fn finalize_device(gic_device: &dyn Vgic) -> Result<()> {
        // FIXME:
        // Redefine some GIC constants to avoid the dependency on `layout` crate.
        // This is temporary solution, will be fixed in future refactoring.
        const LAYOUT_IRQ_NUM: u32 = 256;

        /* We need to tell the kernel how many irqs to support with this vgic.
         * See the `layout` module for details.
         */
        let nr_irqs: u32 = LAYOUT_IRQ_NUM;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        Self::set_device_attribute(
            gic_device.device(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            nr_irqs_ptr as u64,
            0,
        )?;

        /* Finalize the GIC.
         * See https://code.woboq.org/linux/linux/virt/kvm/arm/vgic/vgic-kvm-device.c.html#211.
         */
        Self::set_device_attribute(
            gic_device.device(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            0,
        )?;

        Ok(())
    }

    /// Method to initialize the GIC device
    #[allow(clippy::new_ret_no_self)]
    fn new(vm: &dyn Vm, vcpu_count: u64) -> Result<Box<dyn Vgic>> {
        let vgic_fd = Self::init_device(vm)?;

        let mut device = Self::create_device(vgic_fd, vcpu_count);

        Self::init_device_attributes(vm, &mut *device)?;

        Self::finalize_device(&*device)?;

        Ok(device)
    }

    /// Function that saves RDIST pending tables into guest RAM.
    ///
    /// The tables get flushed to guest RAM whenever the VM gets stopped.
    fn save_pending_tables(gic: &Arc<dyn Device>) -> Result<()> {
        let init_gic_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
            addr: 0,
            flags: 0,
        };
        gic.set_device_attr(&init_gic_attr)
            .map_err(Error::SetDeviceAttribute)
    }
}
