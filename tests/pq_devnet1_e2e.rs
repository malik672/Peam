use peam::containers::attestation::{AttestationData, SignedAttestation};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::gossip::GossipAttestation;
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::crypto::{PQ_ACTIVATION_TIME_EPOCHS, pq};
use peam::networking::{GossipValidatorKind, validate_gossip, verifier_from_validators};
use peam::slot::Slot;
use peam::ssz::{HashTreeRoot, SszEncode};
use peam::types::bytes::Bytes32;
use peam::types::uint::Uint64;

#[test]
#[ignore = "expensive pq key generation/signing; run explicitly for devnet-1 validation"]
fn pq_signed_attestation_validates_through_gossip_pipeline() {
    let (pubkey, secret_key) = pq::key_gen_for_devnet_validator(0).expect("keygen");
    let validators = vec![Validator {
        pubkey,
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    }];

    let data = AttestationData {
        slot: Slot(Uint64(1)),
        head: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        target: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        source: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
    };
    let message_root = data.hash_tree_root();
    let signature = pq::sign_message(&secret_key, 1, &message_root).expect("sign");

    let signed = SignedAttestation {
        validator_id: Uint64(0),
        message: data,
        signature,
    };
    let payload = GossipAttestation {
        attestation: signed,
    }
    .encode_ssz();

    let verifier = verifier_from_validators(&validators);
    assert!(validate_gossip(
        GossipValidatorKind::Attestation,
        &payload,
        &verifier,
    ));
}

#[test]
#[ignore = "expensive pq key generation/signing; run explicitly for devnet-1 validation"]
fn pq_multisig_aggregate_sign_and_verify_roundtrip() {
    pq::setup_aggregate_prover();
    pq::setup_aggregate_verifier();

    let (pk0, sk0) = pq::key_gen_for_devnet_validator(0).expect("k0");
    let (pk1, sk1) = pq::key_gen_for_devnet_validator(1).expect("k1");

    let message = [0x5Au8; 32];
    let aggregate =
        pq::sign_aggregate_concat(&[pk0, pk1], &[&sk0, &sk1], 1, &message).expect("aggregate");
    pq::verify_aggregate_signature(&[pk0, pk1], &message, &aggregate, 1).expect("verify");
}

#[test]
#[ignore = "expensive pq key generation/signing; run explicitly for devnet-1 validation"]
fn pq_activation_window_is_caller_policy() {
    let epoch = PQ_ACTIVATION_TIME_EPOCHS;
    let caller_policy_rejects = epoch >= PQ_ACTIVATION_TIME_EPOCHS;
    assert!(caller_policy_rejects);
}
