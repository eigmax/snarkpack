#[allow(dead_code)]
use ark_ff::One;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    Proof,
};
use ark_bn254::{Bn254, Fr, Fq, Fq2, G1Affine, G2Affine};
use ark_bn254::Fq6;
use snarkpack;
use snarkpack::transcript::Transcript;

mod constraints;
use crate::constraints::Benchmark;
use rand_core::SeedableRng;

#[macro_use]
extern crate serde_derive;

use serde::Deserialize;
use std::str::FromStr;

#[test]
fn groth16_aggregation() {
    let num_constraints = 1000;
    let nproofs = 8;
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1u64);
    let params = {
        let c = Benchmark::<Fr>::new(num_constraints);
        generate_random_parameters::<Bn254, _, _>(c, &mut rng).unwrap()
    };
    // prepare the verification key
    let pvk = prepare_verifying_key(&params.vk);
    // prepare the SRS needed for snarkpack - specialize after to the right
    // number of proofs
    let srs = snarkpack::srs::setup_fake_srs::<Bn254, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);
    // create all the proofs
    let proofs = (0..nproofs)
        .map(|_| {
            let c = Benchmark::new(num_constraints);
            create_random_proof(c, &params, &mut rng).expect("proof creation failed")
        })
        .collect::<Vec<_>>();
    // verify we can at least verify one
    let inputs: Vec<_> = [Fr::one(); 2].to_vec();
    let all_inputs = (0..nproofs).map(|_| inputs.clone()).collect::<Vec<_>>();
    let r = verify_proof(&pvk, &proofs[1], &inputs).unwrap();
    assert!(r);

    let mut prover_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof = snarkpack::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs)
        .expect("error in aggregation");

    let mut ver_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    snarkpack::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
    )
    .expect("error in verification");
}

#[test]
fn snarkjs_groth16_aggreagtion() {
    use std::fs::File;
    use snarkpack::{SnarkJSVK, SnarkJSProof, fr_from_str, get_prepared_verifying_key};

    let nproofs = 2;
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1u64);

    let srs = snarkpack::srs::setup_fake_srs::<Bn254, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);

    let mut proofs: Vec<ark_groth16::Proof<Bn254>> = vec![];
    let mut inputs: Vec<Vec<Fr>> = vec![];

    let mut vk_json: SnarkJSVK = SnarkJSVK::default();
    for i in 0..nproofs {
        let base_path = format!("tests/secret/{:03}", i);
        let file = File::open(format!("{}/proof.json", base_path)).unwrap();
        let proof_json: SnarkJSProof = serde_json::from_reader(file).unwrap();
        let file = File::open(format!("{}/verification_key.json", base_path)).unwrap();
        vk_json = serde_json::from_reader(file).unwrap();
        let file = File::open(format!("{}/public.json", base_path)).unwrap();
        let public_json: Vec<String> = serde_json::from_reader(file).unwrap();
        let pvk = get_prepared_verifying_key(vk_json.clone());
        let ark_pub_inputs: Vec<ark_bn254::Fr> = public_json.into_iter().map(fr_from_str).collect();
        let res = ark_groth16::verify_proof(&pvk.into(), &proof_json.clone().into(), &ark_pub_inputs[..]).unwrap();
        assert_eq!(res, true);
        proofs.push(proof_json.into());
        inputs.push(ark_pub_inputs);
    }

    // aggregate proof
    let mut prover_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &inputs);
    let aggregate_proof = snarkpack::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs)
        .expect("error in aggregation");

    let mut ver_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &inputs);

    let parse_vkey: ark_groth16::VerifyingKey<ark_bn254::Bn254> = vk_json.into();
    let pvk = ark_groth16::prepare_verifying_key(&parse_vkey);

    snarkpack::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
    )
    .expect("error in verification");
}

/*
#[test]
fn verify_proof_with_zkey_with_r1cs() {
    use super::*;
    use ark_bn254::{G1Projective, G2Projective};
    use ark_crypto_primitives::snark::SNARK;
    use num_bigint::BigUint;
    use serde_json::Value;
    use std::fs::File;

    use ark_groth16::Groth16;
    use ark_std::rand::thread_rng;
    use num_traits::{One, Zero};
    use std::str::FromStr;

    use std::convert::TryFrom;

    let path = "./tests/circuit_final.zkey";
    let mut file = File::open(path).unwrap();
    let (params, _matrices) = read_zkey(&mut file).unwrap(); // binfile.proving_key().unwrap();
}
*/
