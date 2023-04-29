use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_std::{rand::Rng, sync::Mutex, One, UniformRand, Zero};
use rayon::prelude::*;

use std::ops::MulAssign;

/// PairingCheck represents a check of the form e(A,B)e(C,D)... = T. Checks can
/// be aggregated together using random linear combination. The efficiency comes
/// from keeping the results from the miller loop output before proceding to a final
/// exponentiation when verifying if all checks are verified.
/// It is a tuple:
/// - a miller loop result that is to be multiplied by other miller loop results
/// before going into a final exponentiation result
/// - a right side result which is already in the right subgroup Gt which is to
/// be compared to the left side when "final_exponentiatiat"-ed
#[derive(Debug, Copy, Clone)]
pub struct PairingCheck<E: PairingEngine> {
    left: E::Fqk,
    right: E::Fqk,
    /// simple counter tracking number of non_randomized checks. If there are
    /// more than 1 non randomized check, it is invalid.
    non_randomized: u8,
}

impl<E> PairingCheck<E>
where
    E: PairingEngine,
{
    pub fn new() -> PairingCheck<E> {
        Self {
            left: E::Fqk::one(),
            right: E::Fqk::one(),
            // an fixed "1 = 1" check doesn't count
            non_randomized: 0,
        }
    }

    pub fn new_invalid() -> PairingCheck<E> {
        Self {
            left: E::Fqk::one(),
            right: E::Fqk::one() + E::Fqk::one(),
            non_randomized: 2,
        }
    }

    /// Returns a pairing check from the output of the miller pairs and the
    /// expected right hand side such that the following must hold:
    /// $$
    ///   finalExponentiation(res) = exp
    /// $$
    ///
    /// Note the check is NOT randomized and there must be only up to ONE check
    /// only that can not be randomized when merging.
    fn from_pair(result: E::Fqk, exp: E::Fqk) -> PairingCheck<E> {
        Self {
            left: result,
            right: exp,
            non_randomized: 1,
        }
    }

    /// Returns a pairing check from the output of the miller pairs and the
    /// expected right hand side such that the following must hold:
    /// $$
    ///   finalExponentiation(\Prod_i lefts[i]) = exp
    /// $$
    ///
    /// Note the check is NOT randomized and there must be only up to ONE check
    /// only that can not be randomized when merging.
    pub fn from_products(lefts: Vec<E::Fqk>, right: E::Fqk) -> PairingCheck<E> {
        let product = lefts.iter().fold(E::Fqk::one(), |mut acc, l| {
            acc *= l;
            acc
        });
        Self::from_pair(product, right)
    }

    /// returns a pairing tuple that is scaled by a random element.
    /// When aggregating pairing checks, this creates a random linear
    /// combination of all checks so that it is secure. Specifically
    /// we have e(A,B)e(C,D)... = out <=> e(g,h)^{ab + cd} = out
    /// We rescale using a random element $r$ to give
    /// e(rA,B)e(rC,D) ... = out^r <=>
    /// e(A,B)^r e(C,D)^r = out^r <=> e(g,h)^{abr + cdr} = out^r
    /// (e(g,h)^{ab + cd})^r = out^r
    pub fn rand<'a, R: Rng + Send>(
        rng: &Mutex<R>,
        it: &[(&'a E::G1Affine, &'a E::G2Affine)],
        out: &'a E::Fqk,
    ) -> PairingCheck<E> {
        let coeff = rand_fr::<E, R>(&rng);
        let miller_out = it
            .into_par_iter()
            .map(|(a, b)| {
                let na = a.mul(coeff).into_affine();
                (
                    E::G1Prepared::from(na.into()),
                    E::G2Prepared::from((**b).into()),
                )
            })
            .map(|(a, b)| E::miller_loop([&(a, b)]))
            .fold(
                || E::Fqk::one(),
                |mut acc, res| {
                    acc.mul_assign(&res);
                    acc
                },
            )
            .reduce(
                || E::Fqk::one(),
                |mut acc, res| {
                    acc.mul_assign(&res);
                    acc
                },
            );
        let mut outt = out.clone();
        if out != &E::Fqk::one() {
            // we only need to make this expensive operation is the output is
            // not one since 1^r = 1
            outt = outt.pow(&coeff.into_repr());
        }
        PairingCheck {
            left: miller_out,
            right: outt,
            non_randomized: 0,
        }
    }

    /// takes another pairing tuple and combine both sides together. Note the checks are not
    /// randomized when merged, the checks must have been randomized before.
    pub fn merge(&mut self, p2: &PairingCheck<E>) {
        mul_if_not_one::<E>(&mut self.left, &p2.left);
        mul_if_not_one::<E>(&mut self.right, &p2.right);
        // A merged PairingCheck is only randomized if both of its contributors are.
        self.non_randomized += p2.non_randomized;
    }

    /// Returns false if there is more than 1 non-random check and otherwise
    /// returns true if
    /// $$
    ///   FinalExponentiation(left) == right
    /// $$
    pub fn verify(&self) -> bool {
        if self.non_randomized > 1 {
            dbg!(format!(
                "Pairing checks have more than 1 non-random checks {}",
                self.non_randomized
            ));
            return false;
        }
        E::final_exponentiation(&self.left).unwrap() == self.right
    }
}

fn rand_fr<E: PairingEngine, R: Rng + Send>(r: &Mutex<R>) -> E::Fr {
    let rng: &mut R = &mut r.lock().unwrap();
    loop {
        let c = E::Fr::rand(rng);
        if c != E::Fr::zero() {
            return c;
        }
    }
}
fn mul_if_not_one<E: PairingEngine>(left: &mut E::Fqk, right: &E::Fqk) {
    let one = E::Fqk::one();
    if left == &one {
        *left = right.clone();
        return;
    } else if right == &one {
        // nothing to do here
        return;
    }
    left.mul_assign(right);
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{Bn254, G1Projective, G2Projective};
    use ark_std::{rand::Rng, UniformRand};
    use rand_core::SeedableRng;

    fn gen_pairing_check<R: Rng + Send>(r: &mut R) -> PairingCheck<Bn254> {
        let g1r = G1Projective::rand(r);
        let g2r = G2Projective::rand(r);
        let exp = Bn254::pairing(g1r.clone(), g2r.clone());
        let mr = Mutex::new(r);
        let tuple =
            PairingCheck::<Bn254>::rand(&mr, &[(&g1r.into_affine(), &g2r.into_affine())], &exp);
        assert!(tuple.verify());
        tuple
    }
    #[test]
    fn test_pairing_randomize() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(0u64);
        let tuples = (0..3)
            .map(|_| gen_pairing_check(&mut rng))
            .collect::<Vec<_>>();
        let final_tuple = tuples
            .iter()
            .fold(PairingCheck::<Bn254>::new(), |mut acc, tu| {
                acc.merge(&tu);
                acc
            });
        assert!(final_tuple.verify());
    }
}
