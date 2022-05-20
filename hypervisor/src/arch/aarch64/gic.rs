// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.

pub trait GicDevice: Send {
    /// Returns the hypervisor agnostic Device of the GIC device
    fn device(&self) -> &Arc<dyn hypervisor::Device>;

    /// Returns the hypervisor agnostic Device of the ITS device
    fn its_device(&self) -> Option<&Arc<dyn hypervisor::Device>> {
        None
    }

    /// Returns the fdt compatibility property of the device
    fn fdt_compatibility(&self) -> &str;

    /// Returns the maint_irq fdt property of the device
    fn fdt_maint_irq(&self) -> u32;

    /// Returns an array with GIC device properties
    fn device_properties(&self) -> &[u64];

    /// Returns the number of vCPUs this GIC handles
    fn vcpu_count(&self) -> u64;

    /// Returns whether the GIC device is MSI compatible or not
    fn msi_compatible(&self) -> bool {
        false
    }

    /// Returns the MSI compatibility property of the device
    fn msi_compatibility(&self) -> &str {
        ""
    }

    /// Returns the MSI reg property of the device
    fn msi_properties(&self) -> &[u64] {
        &[]
    }

    fn set_its_device(&mut self, its_device: Option<Arc<dyn hypervisor::Device>>);

    /// Get the values of GICR_TYPER for each vCPU.
    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]);

    /// Downcast the trait object to its concrete type.
    fn as_any_concrete_mut(&mut self) -> &mut dyn Any;
}
