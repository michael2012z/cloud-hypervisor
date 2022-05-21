pub const GIC_V3_SNAPSHOT_ID: &str = "gic-v3";
impl Snapshottable for KvmGicV3 {
    fn id(&self) -> String {
        GIC_V3_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let gicr_typers = self.gicr_typers.clone();
        Snapshot::new_from_versioned_state(&self.id(), &self.state(&gicr_typers).unwrap())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        let gicr_typers = self.gicr_typers.clone();
        self.set_state(&gicr_typers, &snapshot.to_versioned_state(&self.id())?)
            .map_err(|e| MigratableError::Restore(anyhow!("Could not restore GICv3 state {:?}", e)))
    }
}

impl Pausable for KvmGicV3 {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        // Flush redistributors pending tables to guest RAM.
        save_pending_tables(self.device()).map_err(|e| {
            MigratableError::Pause(anyhow!("Could not save GICv3 GIC pending tables {:?}", e))
        })?;

        Ok(())
    }
}
impl Transportable for KvmGicV3 {}
impl Migratable for KvmGicV3 {}
