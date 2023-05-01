use ark_bn254::Fq6;
use ark_bn254::G1Projective;
use ark_bn254::G2Projective;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
#[allow(dead_code)]
use ark_ff::One;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
};

use serde_json::Value;
use snarkpack;
use snarkpack::{fq_from_str, fr_from_str, read_zkey, LocalTranscript};
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
    // generate SRS: https://github.com/filecoin-project/taupipp/blob/master/src/powers.rs#L58
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

    let mut prover_transcript = snarkpack::transcript::new_keccak_transcript();
    prover_transcript.append(&all_inputs);
    let aggregate_proof = snarkpack::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs)
        .expect("error in aggregation");

    let mut ver_transcript = snarkpack::transcript::new_keccak_transcript();
    ver_transcript.append(&all_inputs);
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
    use snarkpack::{fr_from_str, get_prepared_verifying_key, SnarkJSProof, SnarkJSVK};
    use std::fs::File;

    let nproofs = 2;
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1u64);

    let srs = snarkpack::srs::setup_fake_srs::<Bn254, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);

    let mut proofs: Vec<ark_groth16::Proof<Bn254>> = vec![];
    let mut inputs: Vec<Vec<Fr>> = vec![];

    let mut vk_json: SnarkJSVK = SnarkJSVK::default();
    // another impl: https://github.com/howjmay/ark-circom-example/blob/master/read-from-snarkjs-prove-by-arkworks/src/main.rs#L7
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
        let res =
            ark_groth16::verify_proof(&pvk.into(), &proof_json.clone().into(), &ark_pub_inputs[..])
                .unwrap();
        assert_eq!(res, true);
        proofs.push(proof_json.into());
        inputs.push(ark_pub_inputs);
    }

    // aggregate proof
    let mut prover_transcript = snarkpack::transcript::new_keccak_transcript();
    prover_transcript.append(&inputs);
    let aggregate_proof = snarkpack::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs)
        .expect("error in aggregation");

    /*
    println!("aggregate_proof com_ab {} {}", aggregate_proof.com_ab.0, aggregate_proof.com_ab.1);
    println!("aggregate_proof com_c {} {}", aggregate_proof.com_c.0, aggregate_proof.com_c.1);
    println!("aggregate_proof ip_ab {}", aggregate_proof.ip_ab);
    println!("aggregate_proof agg_c {}", aggregate_proof.agg_c);
    let mut data = Vec::new();
    aggregate_proof.write(&mut data);
    println!("aggregate_proof tmipp {:?}", data);
    */

    let mut ver_transcript = snarkpack::transcript::new_keccak_transcript();
    ver_transcript.append(&inputs);

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

fn json_to_g1(json: &Value, key: &str) -> G1Affine {
    let els: Vec<String> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap().to_string())
        .collect();
    G1Affine::from(G1Projective::new(
        fq_from_str(&els[0]),
        fq_from_str(&els[1]),
        fq_from_str(&els[2]),
    ))
}

fn json_to_g1_vec(json: &Value, key: &str) -> Vec<G1Affine> {
    let els: Vec<Vec<String>> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    els.iter()
        .map(|coords| {
            G1Affine::from(G1Projective::new(
                fq_from_str(&coords[0]),
                fq_from_str(&coords[1]),
                fq_from_str(&coords[2]),
            ))
        })
        .collect()
}

fn json_to_g2(json: &Value, key: &str) -> G2Affine {
    let els: Vec<Vec<String>> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    let x = Fq2::new(fq_from_str(&els[0][0]), fq_from_str(&els[0][1]));
    let y = Fq2::new(fq_from_str(&els[1][0]), fq_from_str(&els[1][1]));
    let z = Fq2::new(fq_from_str(&els[2][0]), fq_from_str(&els[2][1]));
    G2Affine::from(G2Projective::new(x, y, z))
}

#[test]
fn verify_proof_with_zkey_with_r1cs() {
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
    let json = std::fs::read_to_string("./tests/secret/000/verification_key.json").unwrap();
    let json: Value = serde_json::from_str(&json).unwrap();

    assert_eq!(json_to_g1(&json, "vk_alpha_1"), params.vk.alpha_g1);
    assert_eq!(json_to_g2(&json, "vk_beta_2"), params.vk.beta_g2);
    assert_eq!(json_to_g2(&json, "vk_gamma_2"), params.vk.gamma_g2);
    assert_eq!(json_to_g2(&json, "vk_delta_2"), params.vk.delta_g2);
    assert_eq!(json_to_g1_vec(&json, "IC"), params.vk.gamma_abc_g1);
}
