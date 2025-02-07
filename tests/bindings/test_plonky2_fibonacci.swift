import Foundation
import mopro

do {
  let vkPath = "../../../zk-artifacts/plonky2_fibonacci_vk.bin"
  let pkPath = "../../../zk-artifacts/plonky2_fibonacci_pk.bin"

  // Prepare inputs
  var inputs = [String: [String]]()
  let a = 0
  let b = 1
  inputs["a"] = [String(a)]
  inputs["b"] = [String(b)]

  // Generate Proof
  let generateProofResult = try generatePlonky2Proof(proverDataPath: pkPath, inputs: inputs)
  assert(!generateProofResult.proof.isEmpty, "Proof should not be empty")
  assert(!generateProofResult.inputs.isEmpty, "Inputs should not be empty")

  let isValid = try verifyPlonky2Proof(
    verifierDataPath: vkPath, proof: generateProofResult.proof, inputs: generateProofResult.inputs)
  assert(isValid, "Proof verification should succeed")


} catch let error as MoproError {
  print("MoproError: \(error)")
  throw error
} catch {
  print("Unexpected error: \(error)")
  throw error
}
