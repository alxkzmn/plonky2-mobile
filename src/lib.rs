uniffi::include_scaffolding!("mopro");

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MoproError {
    #[error("Plonky2Error: {0}")]
    Plonky2Error(String),
}

#[derive(Debug, Clone)]
pub struct GenerateProofResult {
    pub proof: Vec<u8>,
    pub inputs: Vec<u8>,
}

fn generate_plonky2_proof(
    prover_data_path: String,
    inputs: std::collections::HashMap<String, Vec<String>>,
) -> Result<GenerateProofResult, MoproError> {
    let proving_fn = plonky2_fibonacci::plonky2_prove;
    proving_fn(&prover_data_path, inputs)
        .map(|(proof, inputs)| GenerateProofResult { proof, inputs })
        .map_err(|e| MoproError::Plonky2Error(format!("plonky2 error: {}", e)))
}

fn verify_plonky2_proof(
    verifier_data_path: String,
    proof: Vec<u8>,
    inputs: Vec<u8>,
) -> Result<bool, MoproError> {
    let verifying_fn = plonky2_fibonacci::plonky2_verify;
    verifying_fn(&verifier_data_path, proof, inputs)
        .map_err(|e| MoproError::Plonky2Error(format!("error verifying proof: {}", e)))
}
