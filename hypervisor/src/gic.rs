// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.

use crate::{CpuState, Device, GicState};
use std::any::Any;
use std::result;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
/// Enum for Gic error
pub enum HypervisorGicError {
    /// Error in saving RDIST pending tables into guest RAM
    #[error("Error in saving RDIST pending tables")]
    SavePendingTables,
    /// Error in saving GIC distributor registers
    #[error("Error in saving GIC distributor registers")]
    SaveDistributorRegisters,
    /// Error in restoring GIC distributor registers
    #[error("Error in restoring GIC distributor registers")]
    RestoreDistributorRegisters,
    /// Error in saving GIC distributor control registers
    #[error("Error in saving GIC distributor control registers")]
    SaveDistributorCtrlRegisters,
    /// Error in restoring GIC distributor control registers
    #[error("Error in restoring GIC distributor control registers")]
    RestoreDistributorCtrlRegisters,
    /// Error in saving GIC redistributor registers
    #[error("Error in saving GIC redistributor registers")]
    SaveRedistributorRegisters,
    /// Error in restoring GIC redistributor registers
    #[error("Error in restoring GIC redistributor registers")]
    RestoreRedistributorRegisters,
    /// Error in saving GIC CPU interface registers
    #[error("Error in saving GIC CPU interface registers")]
    SaveIccRegisters,
    /// Error in restoring GIC CPU interface registers
    #[error("Error in restoring GIC CPU interface registers")]
    RestoreIccRegisters,
    /// Error in saving GICv3ITS IIDR register
    #[error("Error in saving GICv3ITS IIDR register")]
    SaveITSIIDR,
    /// Error in restoring GICv3ITS IIDR register
    #[error("Error in restoring GICv3ITS IIDR register")]
    RestoreITSIIDR,
    /// Error in saving GICv3ITS CBASER register
    #[error("Error in saving GICv3ITS CBASER register")]
    SaveITSCBASER,
    /// Error in restoring GICv3ITS CBASER register
    #[error("Error in restoring GICv3ITS CBASER register")]
    RestoreITSCBASER,
    /// Error in saving GICv3ITS CREADR register
    #[error("Error in saving GICv3ITS CREADR register")]
    SaveITSCREADR,
    /// Error in restoring GICv3ITS CREADR register
    #[error("Error in restoring GICv3ITS CREADR register")]
    RestoreITSCREADR,
    /// Error in saving GICv3ITS CWRITER register
    #[error("Error in saving GICv3ITS CWRITER register")]
    SaveITSCWRITER,
    /// Error in restoring GICv3ITS CWRITER register
    #[error("Error in restoring GICv3ITS CWRITER register")]
    RestoreITSCWRITER,
    /// Error in saving GICv3ITS BASER register
    #[error("Error in saving GICv3ITS BASER register")]
    SaveITSBASER,
    /// Error in restoring GICv3ITS BASER register
    #[error("Error in restoring GICv3ITS BASER register")]
    RestoreITSBASER,
    /// Error in saving GICv3ITS CTLR register
    #[error("Error in saving GICv3ITS CTLR register")]
    SaveITSCTLR,
    /// Error in restoring GICv3ITS CTLR register
    #[error("Error in restoring GICv3ITS CTLR register")]
    RestoreITSCTLR,
    /// Error in saving GICv3ITS restore tables
    #[error("Error in saving GICv3ITS restore tables")]
    SaveITSTables,
    /// Error in restoring GICv3ITS restore tables
    #[error("Error in restoring GICv3ITS restore tables")]
    RestoreITSTables,
}

pub type Result<T> = result::Result<T, HypervisorGicError>;

pub trait Vgic: Send {
    /// Returns the hypervisor agnostic Device of the GIC device
    fn device(&self) -> &Arc<dyn Device>;

    /// Returns the hypervisor agnostic Device of the ITS device
    fn its_device(&self) -> Option<&Arc<dyn Device>> {
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

    fn set_its_device(&mut self, its_device: Option<Arc<dyn Device>>);

    /// Get the values of GICR_TYPER for each vCPU.
    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]);

    /// Downcast the trait object to its concrete type.
    fn as_any_concrete_mut(&mut self) -> &mut dyn Any;

    /// Save the state of GICv3ITS.
    fn state(&self, gicr_typers: &[u64]) -> Result<GicState>;

    /// Restore the state of GICv3ITS.
    fn set_state(&mut self, gicr_typers: &[u64], state: &GicState) -> Result<()>;
}
