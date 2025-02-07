use std::{collections::HashMap, error::Error, str::FromStr};

use num_bigint::BigUint;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    plonk::{
        circuit_data::{ProverCircuitData, VerifierCircuitData},
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer, Write},
};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};

pub type GenerateProofResult = (Vec<u8>, Vec<u8>);

pub fn plonky2_prove(
    prover_data_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<GenerateProofResult, Box<dyn Error>> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
    let pk_bytes = std::fs::read(prover_data_path)?;

    let prover_data: ProverCircuitData<GoldilocksField, C, D> =
        ProverCircuitData::from_bytes(&pk_bytes, &gate_serializer, &generator_serializer).unwrap();

    let a = F::from_noncanonical_biguint(BigUint::from_str(&input["a"][0]).unwrap());
    let b = F::from_noncanonical_biguint(BigUint::from_str(&input["b"][0]).unwrap());
    // Provide initial values.
    let mut pw = PartialWitness::new();
    pw.set_target(prover_data.prover_only.public_inputs[0], a)?;
    pw.set_target(prover_data.prover_only.public_inputs[1], b)?;

    let proof_with_public_inputs = prover_data.prove(pw)?;

    let mut proof_buffer = Vec::new();
    proof_buffer
        .write_proof(&proof_with_public_inputs.proof)
        .unwrap();
    let mut public_inputs_buffer = Vec::new();
    public_inputs_buffer
        .write_usize(proof_with_public_inputs.public_inputs.len())
        .unwrap();
    public_inputs_buffer
        .write_field_vec(&proof_with_public_inputs.public_inputs)
        .unwrap();

    Ok((proof_buffer, public_inputs_buffer))
}

pub fn plonky2_verify(
    verifier_data_path: &str,
    serialized_proof: Vec<u8>,
    serialized_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    let gate_serializer = DefaultGateSerializer;
    let vk_bytes = std::fs::read(verifier_data_path)?;

    let verifier_data: VerifierCircuitData<GoldilocksField, C, D> =
        VerifierCircuitData::from_bytes(vk_bytes, &gate_serializer).unwrap();

    let proof = ProofWithPublicInputs::from_bytes(
        [serialized_proof, serialized_inputs].concat(),
        &verifier_data.common,
    )
    .unwrap();

    let verify = verifier_data.verify(proof);

    Ok(verify.is_ok())
}
