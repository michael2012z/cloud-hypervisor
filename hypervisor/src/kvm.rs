// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsft  Corporation
//
use crate::cpuidpatch::{patch_cpuid, CpuidPatch, CpuidReg};

use crate::params::*;
use crate::wrapper::{Hypervisor, VcpuOps, VmFdOps};
use devices::ioapic;
use kvm_bindings::{kvm_enable_cap, CpuId, KVM_CAP_SPLIT_IRQCHIP};
use kvm_ioctls::{Cap, DeviceFd, IoEventAddress, Kvm, NoDatamatch, VcpuFd, VmFd};
use std::result;
use std::sync::Arc;
use vm_memory::{Address, GuestAddress};

use vmm_sys_util::eventfd::EventFd;
pub const KVM_TSS_ADDRESS: GuestAddress = GuestAddress(0xfffb_d000);
extern crate linux_loader;

pub struct KvmVmFd {
    fd: Arc<VmFd>,
    cpuid: CpuId,
}
impl VmFdOps for KvmVmFd {
    fn set_tss_address(&self, offset: usize) -> ResultOps<()> {
        self.fd.set_tss_address(offset)
    }
    fn create_irq_chip(&self) -> ResultOps<()> {
        self.fd.create_irq_chip()
    }
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()> {
        self.fd.register_irqfd(fd, gsi)
    }
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()> {
        self.fd.unregister_irqfd(fd, gsi)
    }
    fn create_vcpu(&self, id: u8) -> ResultOps<Arc<dyn VcpuOps>> {
        let vc = self.fd.create_vcpu(id).expect("new VcpuFd failed");
        let vcpu = KvmVcpuId { fd: vc };
        Ok(Arc::new(vcpu))
    }
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<u64>,
    ) -> ResultOps<()> {
        if let Some(kvm_datamatch) = datamatch {
            self.fd.register_ioevent(fd, addr, kvm_datamatch)
        } else {
            self.fd.register_ioevent(fd, addr, NoDatamatch)
        }
    }
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> ResultOps<()> {
        self.fd.unregister_ioevent(fd, addr)
    }
    fn set_gsi_routing(&self, irq_routing: &IrqRouting) -> ResultOps<()> {
        self.fd.set_gsi_routing(irq_routing)
    }
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> ResultOps<()> {
        unsafe { self.fd.set_user_memory_region(user_memory_region) }
    }
    fn create_device(&self, device: &mut CreateDevice) -> ResultOps<DeviceFd> {
        self.fd.create_device(device)
    }
    fn patch_cpuid(&self, vcpu: Arc<dyn VcpuOps>, id: u8) {
        let mut cpuid = self.cpuid.clone();
        CpuidPatch::set_cpuid_reg(&mut cpuid, 0xb, None, CpuidReg::EDX, u32::from(id));
        vcpu.set_cpuid2(&cpuid).unwrap()
    }
    fn get_cpu_id(&self) -> ResultOps<CpuId> {
        Ok(self.cpuid.clone())
    }
}
pub struct KvmHyperVisor {
    kvm: Kvm,
}

#[derive(Debug)]
pub enum KvmError {
    /// Cannot set the VM up
    VmSetup(kvm_ioctls::Error),

    /// Failed to create a new KVM instance
    KvmNew(kvm_ioctls::Error),
    CapabilityMissing(Cap),
}

pub type KvmResult<T> = result::Result<T, KvmError>;
impl KvmHyperVisor {
    pub fn new() -> Result<KvmHyperVisor> {
        let kvm_obj = Kvm::new().map_err(KvmError::KvmNew).unwrap();
        Ok(KvmHyperVisor { kvm: kvm_obj })
    }
}
/*
pub struct HyperVHyperVisor {
    name: String,
}
impl HyperVHyperVisor {
    fn new() -> Result<HyperVHyperVisor> {
        Ok(HyperVHyperVisor {
            name: "HyperV".to_string(),
        })
    }
}
*/
pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(KvmError::CapabilityMissing(Cap::SignalMsi));
    }
    if !kvm.check_extension(Cap::TscDeadlineTimer) {
        return Err(KvmError::CapabilityMissing(Cap::TscDeadlineTimer));
    }
    if !kvm.check_extension(Cap::SplitIrqchip) {
        return Err(KvmError::CapabilityMissing(Cap::SplitIrqchip));
    }
    Ok(())
}

impl Hypervisor for KvmHyperVisor {
    fn create_vm(&self) -> Result<Arc<dyn VmFdOps>> {
        // Check required capabilities:
        check_required_kvm_extensions(&self.kvm).expect("Missing KVM capabilities");
        let fd: VmFd;
        loop {
            match self.kvm.create_vm() {
                Ok(res) => fd = res,
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        // If the error returned is EINTR, which means the
                        // ioctl has been interrupted, we have to retry as
                        // this can't be considered as a regular error.
                        continue;
                    } else {
                        return Err(Error::VmCreate);
                    }
                }
            }
            break;
        }
        let vm_fd = Arc::new(fd);

        // Set TSS
        vm_fd
            .set_tss_address(KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(KvmError::VmSetup)
            .unwrap();

        // Create split irqchip
        // Only the local APIC is emulated in kernel, both PICs and IOAPIC
        // are not.
        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = ioapic::NUM_IOAPIC_PINS as u64;
        vm_fd.enable_cap(&cap).map_err(KvmError::VmSetup).unwrap();
        let kvm_cpuid: CpuId = patch_cpuid(&self.kvm).unwrap();

        Ok(Arc::new(KvmVmFd {
            fd: vm_fd,
            cpuid: kvm_cpuid,
        }))
    }
    fn get_api_version(&self) -> i32 {
        let v: i32 = 1;
        v
    }
    fn get_vcpu_mmap_size(&self) -> ResultOps<usize> {
        self.kvm.get_vcpu_mmap_size()
    }
    fn get_max_vcpus(&self) -> ResultOps<usize> {
        Ok(self.kvm.get_max_vcpus())
    }
    fn get_nr_vcpus(&self) -> ResultOps<usize> {
        Ok(self.kvm.get_nr_vcpus())
    }
    fn check_extension(&self, c: Cap) -> bool {
        self.kvm.check_extension(c)
    }
}

pub struct KvmVcpuId {
    fd: VcpuFd,
}
impl VcpuOps for KvmVcpuId {
    fn get_regs(&self) -> ResultOps<StandardRegisters> {
        self.fd.get_regs()
    }
    fn set_regs(&self, regs: &StandardRegisters) -> ResultOps<()> {
        self.fd.set_regs(regs)
    }
    fn get_sregs(&self) -> ResultOps<SpecialRegisters> {
        self.fd.get_sregs()
    }
    fn set_sregs(&self, sregs: &SpecialRegisters) -> ResultOps<()> {
        self.fd.set_sregs(sregs)
    }
    fn get_fpu(&self) -> ResultOps<FpuState> {
        self.fd.get_fpu()
    }
    fn set_fpu(&self, fpu: &FpuState) -> ResultOps<()> {
        self.fd.set_fpu(fpu)
    }
    fn set_cpuid2(&self, cpuid: &CpuId) -> ResultOps<()> {
        self.fd.set_cpuid2(cpuid)
    }
    fn get_cpuid2(&self, num_entries: usize) -> ResultOps<CpuId> {
        self.fd.get_cpuid2(num_entries)
    }
    fn get_lapic(&self) -> ResultOps<LapicState> {
        self.fd.get_lapic()
    }
    fn set_lapic(&self, klapic: &LapicState) -> ResultOps<()> {
        self.fd.set_lapic(klapic)
    }
    fn get_msrs(&self, msrs: &mut MsrEntries) -> ResultOps<usize> {
        self.fd.get_msrs(msrs)
    }
    fn set_msrs(&self, msrs: &MsrEntries) -> ResultOps<usize> {
        self.fd.set_msrs(msrs)
    }
    fn get_mp_state(&self) -> ResultOps<MpState> {
        self.fd.get_mp_state()
    }
    fn set_mp_state(&self, mp_state: MpState) -> ResultOps<()> {
        self.fd.set_mp_state(mp_state)
    }
    fn get_xsave(&self) -> ResultOps<Xsave> {
        self.fd.get_xsave()
    }
    fn set_xsave(&self, xsave: &Xsave) -> ResultOps<()> {
        self.fd.set_xsave(xsave)
    }
    fn get_xcrs(&self) -> ResultOps<ExtendedControlRegisters> {
        self.fd.get_xcrs()
    }
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> ResultOps<()> {
        self.fd.set_xcrs(&xcrs)
    }
    fn run(&self) -> ResultOps<VcpuExit> {
        self.fd.run()
    }
    fn get_vcpu_events(&self) -> ResultOps<VcpuEvents> {
        self.fd.get_vcpu_events()
    }
}
