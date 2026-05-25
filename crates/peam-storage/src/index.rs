use super::*;

impl FileStore {
    /// Loads canonical state slot index from `canonical.redb`.
    pub fn load_state_index(&mut self) -> Result<(), String> {
        match self.canonical_db.load_state_index() {
            Ok(index) => {
                self.state_by_slot = index;
            }
            Err(_) => {
                self.state_by_slot.clear();
                self.recovery.skipped_corrupt += 1;
            }
        }
        Ok(())
    }

    /// Loads canonical block slot index from `canonical.redb`.
    pub fn load_block_index(&mut self) -> Result<(), String> {
        match self.canonical_db.load_block_index() {
            Ok(index) => {
                self.block_by_slot = index;
            }
            Err(_) => {
                self.block_by_slot.clear();
                self.recovery.skipped_corrupt += 1;
            }
        }
        Ok(())
    }

    /// Atomically writes canonical state slot index to `canonical.redb`.
    pub fn persist_state_index(&self) -> Result<(), String> {
        self.canonical_db.persist_state_index(&self.state_by_slot)
    }

    /// Atomically writes canonical block slot index to `canonical.redb`.
    pub fn persist_block_index(&self) -> Result<(), String> {
        self.canonical_db.persist_block_index(&self.block_by_slot)
    }
}
