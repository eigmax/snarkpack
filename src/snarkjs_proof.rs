use ark_bn254::Fq6;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::PairingEngine;
use ark_ff::One;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
};

use serde::Deserialize;
use std::str::FromStr;

pub fn fr_from_str(s: String) -> ark_bn254::Fr {
    ark_bn254::Fr::from_str(&s).unwrap()
}

pub fn fq_from_str(s: &String) -> ark_bn254::Fq {
    ark_bn254::Fq::from_str(&s).unwrap()
}

pub fn g1_from_str(g1: &[String]) -> ark_bn254::G1Affine {
    let x = fq_from_str(&g1[0]);
    let y = fq_from_str(&g1[1]);
    let z = fq_from_str(&g1[2]);
    ark_bn254::G1Affine::from(ark_bn254::G1Projective::new(x, y, z))
}

pub fn g2_from_str(g2: &[Vec<String>]) -> ark_bn254::G2Affine {
    let c0 = fq_from_str(&g2[0][0]);
    let c1 = fq_from_str(&g2[0][1]);
    let x = ark_bn254::Fq2::new(c0, c1);

    let c0 = fq_from_str(&g2[1][0]);
    let c1 = fq_from_str(&g2[1][1]);
    let y = ark_bn254::Fq2::new(c0, c1);

    let c0 = fq_from_str(&g2[2][0]);
    let c1 = fq_from_str(&g2[2][1]);
    let z = ark_bn254::Fq2::new(c0, c1);

    ark_bn254::G2Affine::from(ark_bn254::G2Projective::new(x, y, z))
}

#[derive(Debug, Deserialize, Clone)]
pub struct SnarkJSProof {
    pub curve: String,
    pub protocol: String,
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

impl From<SnarkJSProof> for ark_groth16::Proof<ark_bn254::Bn254> {
    fn from(src: SnarkJSProof) -> Self {
        ark_groth16::Proof {
            a: g1_from_str(&src.pi_a),
            b: g2_from_str(&src.pi_b),
            c: g1_from_str(&src.pi_c),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
pub struct SnarkJSVK {
    pub curve: String,
    pub protocol: String,
    #[serde(rename(deserialize = "nPublic"))]
    pub n_public: i32,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

impl From<SnarkJSVK> for ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    fn from(src: SnarkJSVK) -> Self {
        let alpha_g1_ = g1_from_str(&src.vk_alpha_1);
        let beta_g2_ = g2_from_str(&src.vk_beta_2);
        let gamma_g2_ = g2_from_str(&src.vk_gamma_2);
        let delta_g2_ = g2_from_str(&src.vk_delta_2);

        let gamma_abc_g1_: Vec<ark_bn254::G1Affine> =
            src.ic.iter().map(|x| g1_from_str(x)).collect();

        ark_groth16::VerifyingKey {
            alpha_g1: alpha_g1_,
            beta_g2: beta_g2_,
            gamma_g2: gamma_g2_,
            delta_g2: delta_g2_,
            gamma_abc_g1: gamma_abc_g1_,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct G2Prepared {
    pub ell_coeffs: Vec<(Fq2, Fq2, Fq2)>,
    pub infinity: bool,
}

impl G2Prepared {
    pub fn new(ell_coeffs_: Vec<(Fq2, Fq2, Fq2)>, inf: bool) -> Self {
        G2Prepared {
            ell_coeffs: ell_coeffs_,
            infinity: inf,
        }
    }
}

impl From<ark_ec::bn::G2Prepared<ark_bn254::Parameters>> for G2Prepared {
    fn from(src: ark_ec::bn::G2Prepared<ark_bn254::Parameters>) -> G2Prepared {
        let ark_ell_coeffs = src
            .ell_coeffs
            .into_iter()
            .map(|elem| (elem.0, elem.1, elem.2));
        let ell_coeffs: Vec<(Fq2, Fq2, Fq2)> = ark_ell_coeffs
            .map(|elem| (elem.0.into(), elem.1.into(), elem.2.into()))
            .collect();
        G2Prepared::new(ell_coeffs, src.infinity)
    }
}

impl From<G2Prepared> for ark_ec::bn::G2Prepared<ark_bn254::Parameters> {
    fn from(src: G2Prepared) -> ark_ec::bn::G2Prepared<ark_bn254::Parameters> {
        let ark_ell_coeffs = src
            .ell_coeffs
            .into_iter()
            .map(|elem| (elem.0.into(), elem.1.into(), elem.2.into()));
        ark_ec::bn::G2Prepared {
            ell_coeffs: ark_ell_coeffs
                .map(|elem| (elem.0, elem.1, elem.2))
                .collect(),
            infinity: src.infinity,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Fq12 {
    pub c0: Fq6,
    pub c1: Fq6,
}

impl Fq12 {
    pub fn new(c0_: Fq6, c1_: Fq6) -> Self {
        Fq12 { c0: c0_, c1: c1_ }
    }
}

impl From<Fq12> for ark_bn254::Fq12 {
    fn from(src: Fq12) -> ark_bn254::Fq12 {
        let c0: ark_bn254::Fq6 = src.c0.into();
        let c1: ark_bn254::Fq6 = src.c1.into();
        ark_bn254::Fq12::new(c0, c1)
    }
}

impl From<ark_bn254::Fq12> for Fq12 {
    fn from(src: ark_bn254::Fq12) -> Fq12 {
        let c0: ark_bn254::Fq6 = src.c0;
        let c1: ark_bn254::Fq6 = src.c1;
        Fq12::new(c0.into(), c1.into())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub gamma_abc_g1: Vec<G1Affine>,
}

impl From<VerifyingKey> for ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    fn from(src: VerifyingKey) -> ark_groth16::VerifyingKey<ark_bn254::Bn254> {
        ark_groth16::VerifyingKey {
            alpha_g1: src.alpha_g1.into(),
            beta_g2: src.beta_g2.into(),
            gamma_g2: src.gamma_g2.into(),
            delta_g2: src.delta_g2.into(),
            gamma_abc_g1: src
                .gamma_abc_g1
                .into_iter()
                .map(|elem| elem.into())
                .collect(),
        }
    }
}

impl From<ark_groth16::VerifyingKey<ark_bn254::Bn254>> for VerifyingKey {
    fn from(src: ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> VerifyingKey {
        VerifyingKey {
            alpha_g1: src.alpha_g1.into(),
            beta_g2: src.beta_g2.into(),
            gamma_g2: src.gamma_g2.into(),
            delta_g2: src.delta_g2.into(),
            gamma_abc_g1: src
                .gamma_abc_g1
                .into_iter()
                .map(|elem| elem.into())
                .collect(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PreparedVerifyingKey {
    pub vk: VerifyingKey,
    pub alpha_g1_beta_g2: Fq12,
    pub gamma_g2_neg_pc: G2Prepared,
    pub delta_g2_neg_pc: G2Prepared,
}

impl From<PreparedVerifyingKey> for ark_groth16::PreparedVerifyingKey<ark_bn254::Bn254> {
    fn from(src: PreparedVerifyingKey) -> ark_groth16::PreparedVerifyingKey<ark_bn254::Bn254> {
        ark_groth16::PreparedVerifyingKey {
            vk: src.vk.into(),
            alpha_g1_beta_g2: src.alpha_g1_beta_g2.into(),
            gamma_g2_neg_pc: src.gamma_g2_neg_pc.into(),
            delta_g2_neg_pc: src.delta_g2_neg_pc.into(),
        }
    }
}

impl From<ark_groth16::PreparedVerifyingKey<ark_bn254::Bn254>> for PreparedVerifyingKey {
    fn from(src: ark_groth16::PreparedVerifyingKey<ark_bn254::Bn254>) -> PreparedVerifyingKey {
        PreparedVerifyingKey {
            vk: src.vk.into(),
            alpha_g1_beta_g2: src.alpha_g1_beta_g2.into(),
            gamma_g2_neg_pc: src.gamma_g2_neg_pc.into(),
            delta_g2_neg_pc: src.delta_g2_neg_pc.into(),
        }
    }
}

pub fn get_prepared_verifying_key(vkey: SnarkJSVK) -> PreparedVerifyingKey {
    let parse_vkey: ark_groth16::VerifyingKey<ark_bn254::Bn254> = vkey.into();
    ark_groth16::prepare_verifying_key(&parse_vkey).into()
}
