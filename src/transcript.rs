use ark_serialize::CanonicalSerialize;
use ark_ff::fields::Field;

use bellman_ce::plonk::commitments::transcript:: {
    keccak_transcript::RollingKeccakTranscript,
    Transcript,
};
use bellman_ce::plonk::commitments::transcript::Prng;
use bellman_ce::{PrimeField, PrimeFieldRepr};
use bellman_ce::bn256::Bn256;
use bellman_ce::ScalarEngine;
/// must be specific to the application.
pub fn new_keccak_transcript() -> impl LocalTranscript {
    RollingKeccakTranscript::new()
}

/// Transcript is the application level transcript to derive the challenges
/// needed for Fiat Shamir during aggregation. It is given to the
/// prover/verifier so that the transcript can be fed with any other data first.
pub trait LocalTranscript {
    fn domain_sep(&mut self);
    fn append<S: CanonicalSerialize>(&mut self, point: &S);
    fn challenge_scalar<F: Field>(&mut self) -> F;
}

impl LocalTranscript for RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr> {
    fn domain_sep(&mut self) {
        //self.append_message(b"dom-sep", b"groth16-aggregation-snarkpack");
        //self.commit_bytes(b"dom-sep");
        //self.commit_bytes(b"groth16-aggregation-snarkpack");
    }

    fn append<S: CanonicalSerialize>(&mut self, element: &S) {
        let mut buff: Vec<u8> = vec![0; element.serialized_size()];
        element.serialize(&mut buff).expect("serialization failed");
        self.commit_bytes(&buff);
    }

    fn challenge_scalar<F: Field>(&mut self) -> F {
        // Reduce a double-width scalar to ensure a uniform distribution
        let el = self.get_challenge();
        //println!("el: {}", el);
        let repr = el.into_repr();
        let required_length = repr.as_ref().len() * 8;
        let mut buf: Vec<u8> = Vec::with_capacity(required_length);
        repr.write_le(&mut buf).unwrap();
        let t = F::from_random_bytes(&buf).unwrap();
        //println!("el t: {}", t);
        t
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::ProjectiveCurve;

    #[test]
    fn transcript() {
        let mut transcript = new_keccak_transcript();
        transcript.append(&G1Projective::prime_subgroup_generator());
        let f1 = transcript.challenge_scalar::<Fr>();
        let mut transcript2 = new_keccak_transcript();
        transcript2.append(&G1Projective::prime_subgroup_generator());
        let f2 = transcript2.challenge_scalar::<Fr>();
        assert_eq!(f1, f2);
    }
}
