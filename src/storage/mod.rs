use rapidhash::RapidHashMap;

use crate::containers::block::Block;
use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::state::State;
use crate::types::bytes::Bytes32;

pub trait Store {
    fn get_state(&self, root: &Bytes32) -> Option<&State>;
    fn put_state(&mut self, root: Bytes32, state: State);
    fn get_block(&self, root: &Bytes32) -> Option<&Block>;
    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation>;
    fn put_block(&mut self, root: Bytes32, block: Block);
    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String>;
    fn get_state_by_slot(&self, slot: u64) -> Option<&State>;
    fn get_block_by_slot(&self, slot: u64) -> Option<&Block>;
    fn finalized(&self) -> Option<Bytes32>;
    fn set_finalized(&mut self, root: Bytes32);
    fn justified(&self) -> Option<Bytes32>;
    fn set_justified(&mut self, root: Bytes32);
    fn head(&self) -> Option<Bytes32>;
    fn set_head(&mut self, root: Bytes32);
}

#[derive(Default)]
pub struct MemoryStore {
    states: RapidHashMap<Bytes32, State>,
    blocks: RapidHashMap<Bytes32, Block>,
    signed_blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    state_by_slot: RapidHashMap<u64, Bytes32>,
    block_by_slot: RapidHashMap<u64, Bytes32>,
    head: Option<Bytes32>,
    finalized: Option<Bytes32>,
    justified: Option<Bytes32>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get_state(&self, root: &Bytes32) -> Option<&State> {
        self.states.get(root)
    }

    fn put_state(&mut self, root: Bytes32, state: State) {
        self.state_by_slot.insert(state.slot.0 .0, root);
        self.states.insert(root, state);
    }

    fn get_block(&self, root: &Bytes32) -> Option<&Block> {
        self.blocks.get(root)
    }

    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        self.signed_blocks.get(root).cloned()
    }

    fn put_block(&mut self, root: Bytes32, block: Block) {
        self.block_by_slot
            .insert(block.slot.0 .0, root);
        self.blocks.insert(root, block);
    }

    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        state.process_signed_block(&signed)?;
        let block = signed.message.block.clone();
        self.block_by_slot.insert(block.slot.0 .0, root);
        self.blocks.insert(root, block);
        self.signed_blocks.insert(root, signed);
        Ok(())
    }

    fn get_state_by_slot(&self, slot: u64) -> Option<&State> {
        let root = self.state_by_slot.get(&slot)?;
        self.states.get(root)
    }

    fn get_block_by_slot(&self, slot: u64) -> Option<&Block> {
        let root = self.block_by_slot.get(&slot)?;
        self.blocks.get(root)
    }

    fn head(&self) -> Option<Bytes32> {
        self.head
    }

    fn set_head(&mut self, root: Bytes32) {
        self.head = Some(root);
    }

    fn finalized(&self) -> Option<Bytes32> {
        self.finalized
    }

    fn set_finalized(&mut self, root: Bytes32) {
        self.finalized = Some(root);
    }

    fn justified(&self) -> Option<Bytes32> {
        self.justified
    }

    fn set_justified(&mut self, root: Bytes32) {
        self.justified = Some(root);
    }
}
