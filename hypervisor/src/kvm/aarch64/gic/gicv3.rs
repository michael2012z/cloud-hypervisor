// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// This file implements the GicV3 device.

use super::dist_regs::{get_dist_regs, read_ctlr, set_dist_regs, write_ctlr};
use super::icc_regs::{get_icc_regs, set_icc_regs};
use super::redist_regs::{construct_gicr_typers, get_redist_regs, set_redist_regs};
use super::GicDevice;
use super::KvmGicDevice;
use crate::kvm::kvm_bindings;
use crate::{CpuState, Device, Vm};
use anyhow::anyhow;
use std::any::Any;
use std::convert::TryInto;
use std::sync::Arc;
use std::{boxed::Box, result};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::Address;

/// Errors thrown while saving/restoring the GICv3.
#[derive(Debug)]
pub enum Error {
    /// Error in saving RDIST pending tables into guest RAM.
    SavePendingTables(crate::aarch64::gic::Error),
    /// Error in saving GIC distributor registers.
    SaveDistributorRegisters(crate::aarch64::gic::Error),
    /// Error in restoring GIC distributor registers.
    RestoreDistributorRegisters(crate::aarch64::gic::Error),
    /// Error in saving GIC distributor control registers.
    SaveDistributorCtrlRegisters(crate::aarch64::gic::Error),
    /// Error in restoring GIC distributor control registers.
    RestoreDistributorCtrlRegisters(crate::aarch64::gic::Error),
    /// Error in saving GIC redistributor registers.
    SaveRedistributorRegisters(crate::aarch64::gic::Error),
    /// Error in restoring GIC redistributor registers.
    RestoreRedistributorRegisters(crate::aarch64::gic::Error),
    /// Error in saving GIC CPU interface registers.
    SaveIccRegisters(crate::aarch64::gic::Error),
    /// Error in restoring GIC CPU interface registers.
    RestoreIccRegisters(crate::aarch64::gic::Error),
}

type Result<T> = result::Result<T, Error>;

pub struct KvmGicV3 {
    /// The hypervisor agnostic device for the GicV3
    device: Arc<dyn Device>,

    /// Vector holding values of GICR_TYPER for each vCPU
    gicr_typers: Vec<u64>,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

#[derive(Versionize)]
pub struct Gicv3State {
    dist: Vec<u32>,
    rdist: Vec<u32>,
    icc: Vec<u32>,
    // special register that enables interrupts and affinity routing
    gicd_ctlr: u32,
}

impl VersionMapped for Gicv3State {}

impl KvmGicV3 {
    // Device trees specific constants
    pub const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

    /// Get the address of the GIC distributor.
    pub fn get_dist_addr() -> u64 {
        layout::GIC_V3_DIST_START.raw_value()
    }

    /// Get the size of the GIC distributor.
    pub fn get_dist_size() -> u64 {
        layout::GIC_V3_DIST_SIZE
    }

    /// Get the address of the GIC redistributors.
    pub fn get_redists_addr(vcpu_count: u64) -> u64 {
        KvmGicV3::get_dist_addr() - KvmGicV3::get_redists_size(vcpu_count)
    }

    /// Get the size of the GIC redistributors.
    pub fn get_redists_size(vcpu_count: u64) -> u64 {
        vcpu_count * layout::GIC_V3_REDIST_SIZE
    }

    /// Save the state of GIC.
    fn state(&self, gicr_typers: &[u64]) -> Result<Gicv3State> {
        let gicd_ctlr = read_ctlr(self.device()).map_err(Error::SaveDistributorCtrlRegisters)?;

        let dist_state = get_dist_regs(self.device()).map_err(Error::SaveDistributorRegisters)?;

        let rdist_state = get_redist_regs(self.device(), gicr_typers)
            .map_err(Error::SaveRedistributorRegisters)?;

        let icc_state =
            get_icc_regs(self.device(), gicr_typers).map_err(Error::SaveIccRegisters)?;

        Ok(Gicv3State {
            dist: dist_state,
            rdist: rdist_state,
            icc: icc_state,
            gicd_ctlr,
        })
    }

    /// Restore the state of GIC.
    fn set_state(&mut self, gicr_typers: &[u64], state: &Gicv3State) -> Result<()> {
        write_ctlr(self.device(), state.gicd_ctlr)
            .map_err(Error::RestoreDistributorCtrlRegisters)?;

        set_dist_regs(self.device(), &state.dist).map_err(Error::RestoreDistributorRegisters)?;

        set_redist_regs(self.device(), gicr_typers, &state.rdist)
            .map_err(Error::RestoreRedistributorRegisters)?;

        set_icc_regs(self.device(), gicr_typers, &state.icc).map_err(Error::RestoreIccRegisters)?;

        Ok(())
    }
}

impl GicDevice for KvmGicV3 {
    fn device(&self) -> &Arc<dyn Device> {
        &self.device
    }

    fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    fn fdt_maint_irq(&self) -> u32 {
        KvmGicV3::ARCH_GIC_V3_MAINT_IRQ
    }

    fn device_properties(&self) -> &[u64] {
        &self.properties
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn set_its_device(&mut self, _its_device: Option<Arc<dyn Device>>) {}

    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]) {
        let gicr_typers = construct_gicr_typers(vcpu_states);
        self.gicr_typers = gicr_typers;
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl KvmGicDevice for KvmGicV3 {
    fn version() -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3
    }

    fn create_device(device: Arc<dyn Device>, vcpu_count: u64) -> Box<dyn GicDevice> {
        Box::new(KvmGicV3 {
            device,
            gicr_typers: vec![0; vcpu_count.try_into().unwrap()],
            properties: [
                KvmGicV3::get_dist_addr(),
                KvmGicV3::get_dist_size(),
                KvmGicV3::get_redists_addr(vcpu_count),
                KvmGicV3::get_redists_size(vcpu_count),
            ],
            vcpu_count,
        })
    }

    fn init_device_attributes(
        _vm: &Arc<dyn Vm>,
        gic_device: &mut dyn GicDevice,
    ) -> crate::aarch64::gic::Result<()> {
        /* Setting up the distributor attribute.
         We are placing the GIC below 1GB so we need to substract the size of the distributor.
        */
        Self::set_device_attribute(
            gic_device.device(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            &KvmGicV3::get_dist_addr() as *const u64 as u64,
            0,
        )?;

        /* Setting up the redistributors' attribute.
        We are calculating here the start of the redistributors address. We have one per CPU.
        */
        Self::set_device_attribute(
            gic_device.device(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
            &KvmGicV3::get_redists_addr(gic_device.vcpu_count()) as *const u64 as u64,
            0,
        )?;

        Ok(())
    }
}

pub const GIC_V3_ITS_SNAPSHOT_ID: &str = "gic-v3-its";
impl Snapshottable for KvmGicV3Its {
    fn id(&self) -> String {
        GIC_V3_ITS_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let gicr_typers = self.gicr_typers.clone();
        Snapshot::new_from_versioned_state(&self.id(), &self.state(&gicr_typers).unwrap())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        let gicr_typers = self.gicr_typers.clone();
        self.set_state(&gicr_typers, &snapshot.to_versioned_state(&self.id())?)
            .map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore GICv3ITS state {:?}", e))
            })
    }
}

impl Pausable for KvmGicV3Its {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        // Flush redistributors pending tables to guest RAM.
        KvmGicDevice::save_pending_tables(self.device()).map_err(|e| {
            MigratableError::Pause(anyhow!(
                "Could not save GICv3ITS GIC pending tables {:?}",
                e
            ))
        })?;
        // Flush ITS tables to guest RAM.
        gicv3_its_tables_access(self.its_device().unwrap(), true).map_err(|e| {
            MigratableError::Pause(anyhow!("Could not save GICv3ITS ITS tables {:?}", e))
        })?;

        Ok(())
    }
}
impl Transportable for KvmGicV3Its {}
impl Migratable for KvmGicV3Its {}
