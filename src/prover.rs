use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use ark_groth16::Proof;
use ark_poly::polynomial::{univariate::DensePolynomial, UVPolynomial};
use ark_std::{cfg_iter, Zero};

use rayon::prelude::*;
use std::ops::{AddAssign, MulAssign, Neg};

use super::{
    commitment,
    commitment::{VKey, WKey},
    compress,
    errors::Error,
    ip,
    proof::{AggregateProof, GipaProof, KZGOpening, TippMippProof},
    srs::ProverSRS,
    structured_scalar_power,
    transcript::LocalTranscript,
};

/// Aggregate `n` zkSnark proofs, where `n` must be a power of two.
/// WARNING: transcript_include represents everything that should be included in
/// the transcript from outside the boundary of this function. This is especially
/// relevant for ALL public inputs of ALL individual proofs. In the regular case,
/// one should input ALL public inputs from ALL proofs aggregated. However, IF ALL the
/// public inputs are **fixed, and public before the aggregation time**, then there is
/// no need to hash those. The reason we specify this extra assumption is because hashing
/// the public inputs from the decoded form can take quite some time depending on the
/// number of proofs and public inputs (+100ms in our case). In the case of Filecoin, the only
/// non-fixed part of the public inputs are the challenges derived from a seed. Even though this
/// seed comes from a random beeacon, we are hashing this as a safety precaution.
pub fn aggregate_proofs<E: PairingEngine + std::fmt::Debug, T: LocalTranscript>(
    srs: &ProverSRS<E>,
    transcript: &mut T,
    proofs: &[Proof<E>],
) -> Result<AggregateProof<E>, Error> {
    if proofs.len() < 2 {
        return Err(Error::InvalidProof("invalid proof size < 2".to_string()));
    }
    if !proofs.len().is_power_of_two() {
        return Err(Error::InvalidProof(
            "invalid proof size: not power of two".to_string(),
        ));
    }

    if !srs.has_correct_len(proofs.len()) {
        return Err(Error::InvalidSRS("SRS len != proofs len".to_string()));
    }
    // We first commit to A B and C - these commitments are what the verifier
    // will use later to verify the TIPP and MIPP proofs
    par! {
        let a = proofs.iter().map(|proof| proof.a).collect::<Vec<_>>(),
        let b = proofs.iter().map(|proof| proof.b).collect::<Vec<_>>(),
        let c = proofs.iter().map(|proof| proof.c).collect::<Vec<_>>()
    };

    // A and B are committed together in this scheme
    // we need to take the reference so the macro doesn't consume the value
    // first
    let refa = &a;
    let refb = &b;
    let refc = &c;
    try_par! {
        let com_ab = commitment::pair::<E>(&srs.vkey, &srs.wkey, refa, refb),
        let com_c = commitment::single_g1::<E>(&srs.vkey, refc)
    };

    // Derive a random scalar to perform a linear combination of proofs
    transcript.append(&com_ab);
    transcript.append(&com_c);
    let r = transcript.challenge_scalar::<E::Fr>();

    // 1,r, r^2, r^3, r^4 ...
    let r_vec: Vec<E::Fr> = structured_scalar_power(proofs.len(), &r);
    // 1,r^-1, r^-2, r^-3
    let r_inv = r_vec
        .par_iter()
        .map(|ri| ri.inverse().unwrap())
        .collect::<Vec<_>>();

    // B^{r}
    let b_r = b
        .par_iter()
        .zip(r_vec.par_iter())
        .map(|(bi, ri)| mul!(bi.into_projective(), ri.clone()).into_affine())
        .collect::<Vec<_>>();

    let refb_r = &b_r;
    let refr_vec = &r_vec;
    try_par! {
        // compute A * B^r for the verifier
        let ip_ab = ip::pairing::<E>(&refa, &refb_r),
        // compute C^r for the verifier
        let agg_c = ip::multiexponentiation::<E::G1Affine>(&refc, &refr_vec)
    };
    let agg_c = agg_c.into_affine();
    // w^{r^{-1}}
    let wkey_r_inv = srs.wkey.scale(&r_inv)?;

    // we prove tipp and mipp using the same recursive loop
    let proof = prove_tipp_mipp(
        &srs,
        transcript,
        &a,
        &b_r,
        &c,
        &wkey_r_inv,
        &r_vec,
        &ip_ab,
        &agg_c,
    )?;
    debug_assert!({
        let computed_com_ab = commitment::pair::<E>(&srs.vkey, &wkey_r_inv, &a, &b_r).unwrap();
        com_ab == computed_com_ab
    });

    Ok(AggregateProof {
        com_ab,
        com_c,
        ip_ab,
        agg_c,
        tmipp: proof,
    })
}

/// Proves a TIPP relation between A and B as well as a MIPP relation with C and
/// r. Commitment keys must be of size of A, B and C. In the context of Groth16
/// aggregation, we have that B = B^r and wkey is scaled by r^{-1}. The
/// commitment key v is used to commit to A and C recursively in GIPA such that
/// only one KZG proof is needed for v. In the original paper version, since the
/// challenges of GIPA would be different, two KZG proofs would be needed.
fn prove_tipp_mipp<E: PairingEngine, T: LocalTranscript>(
    srs: &ProverSRS<E>,
    transcript: &mut T,
    a: &[E::G1Affine],
    b: &[E::G2Affine],
    c: &[E::G1Affine],
    wkey: &WKey<E>, // scaled key w^r^-1
    r_vec: &[E::Fr],
    ip_ab: &E::Fqk,
    agg_c: &E::G1Affine,
) -> Result<TippMippProof<E>, Error> {
    let r_shift = r_vec[1].clone();
    // Run GIPA
    let (proof, mut challenges, mut challenges_inv) =
        gipa_tipp_mipp(transcript, a, b, c, &srs.vkey, &wkey, r_vec, ip_ab, agg_c)?;

    // Prove final commitment keys are wellformed
    // we reverse the transcript so the polynomial in kzg opening is constructed
    // correctly - the formula indicates x_{l-j}. Also for deriving KZG
    // challenge point, input must be the last challenge.
    challenges.reverse();
    challenges_inv.reverse();
    let r_inverse = r_shift.inverse().unwrap();

    // KZG challenge point
    transcript.append(&challenges[0]);
    transcript.append(&proof.final_vkey.0);
    transcript.append(&proof.final_vkey.1);
    transcript.append(&proof.final_wkey.0);
    transcript.append(&proof.final_wkey.1);
    let z = transcript.challenge_scalar::<E::Fr>();
    // Complete KZG proofs
    par! {
        let vkey_opening = prove_commitment_v(
            &srs.h_alpha_powers_table,
            &srs.h_beta_powers_table,
            &challenges_inv,
            &z,
        ),
        let wkey_opening = prove_commitment_w(
            &srs.g_alpha_powers_table,
            &srs.g_beta_powers_table,
            &challenges,
            &r_inverse,
            &z,
        )
    };

    Ok(TippMippProof {
        gipa: proof,
        vkey_opening: vkey_opening?,
        wkey_opening: wkey_opening?,
    })
}

/// gipa_tipp_mipp peforms the recursion of the GIPA protocol for TIPP and MIPP.
/// It returns a proof containing all intermdiate committed values, as well as
/// the challenges generated necessary to do the polynomial commitment proof
/// later in TIPP.
fn gipa_tipp_mipp<E: PairingEngine>(
    transcript: &mut impl LocalTranscript,
    a: &[E::G1Affine],
    b: &[E::G2Affine],
    c: &[E::G1Affine],
    vkey: &VKey<E>,
    wkey: &WKey<E>, // scaled key w^r^-1
    r: &[E::Fr],
    ip_ab: &E::Fqk,
    agg_c: &E::G1Affine,
) -> Result<(GipaProof<E>, Vec<E::Fr>, Vec<E::Fr>), Error> {
    // the values of vectors A and B rescaled at each step of the loop
    let (mut m_a, mut m_b) = (a.to_vec(), b.to_vec());
    // the values of vectors C and r rescaled at each step of the loop
    let (mut m_c, mut m_r) = (c.to_vec(), r.to_vec());
    // the values of the commitment keys rescaled at each step of the loop
    let (mut vkey, mut wkey) = (vkey.clone(), wkey.clone());

    // storing the values for including in the proof
    let mut comms_ab = Vec::new();
    let mut comms_c = Vec::new();
    let mut z_ab = Vec::new();
    let mut z_c = Vec::new();
    let mut challenges: Vec<E::Fr> = Vec::new();
    let mut challenges_inv: Vec<E::Fr> = Vec::new();

    transcript.append(ip_ab);
    transcript.append(agg_c);
    let mut c_inv: E::Fr = transcript.challenge_scalar::<E::Fr>();
    let mut c = c_inv.inverse().unwrap();

    let mut i = 0;

    while m_a.len() > 1 {
        // recursive step
        // Recurse with problem of half size
        let split = m_a.len() / 2;

        // TIPP ///
        let (a_left, a_right) = m_a.split_at_mut(split);
        let (b_left, b_right) = m_b.split_at_mut(split);
        // MIPP ///
        // c[:n']   c[n':]
        let (c_left, c_right) = m_c.split_at_mut(split);
        // r[:n']   r[:n']
        let (r_left, r_right) = m_r.split_at_mut(split);

        let (vk_left, vk_right) = vkey.split(split);
        let (wk_left, wk_right) = wkey.split(split);

        // since we do this in parallel we take reference first so it can be
        // moved within the macro's rayon scope.
        let (rvk_left, rvk_right) = (&vk_left, &vk_right);
        let (rwk_left, rwk_right) = (&wk_left, &wk_right);
        let (ra_left, ra_right) = (&a_left, &a_right);
        let (rb_left, rb_right) = (&b_left, &b_right);
        let (rc_left, rc_right) = (&c_left, &c_right);
        let (rr_left, rr_right) = (&r_left, &r_right);
        // See section 3.3 for paper version with equivalent names
        try_par! {
            // TIPP part
            let tab_l = commitment::pair::<E>(&rvk_left, &rwk_right, &ra_right, &rb_left),
            let tab_r = commitment::pair::<E>(&rvk_right, &rwk_left, &ra_left, &rb_right),
            // \prod e(A_right,B_left)
            let zab_l = ip::pairing::<E>(&ra_right, &rb_left),
            let zab_r = ip::pairing::<E>(&ra_left, &rb_right),

            // MIPP part
            // z_l = c[n':] ^ r[:n']
            let zc_l = ip::multiexponentiation::<E::G1Affine>(rc_right, rr_left),
            // Z_r = c[:n'] ^ r[n':]
            let zc_r = ip::multiexponentiation::<E::G1Affine>(rc_left, rr_right),
            // u_l = c[n':] * v[:n']
            let tuc_l = commitment::single_g1::<E>(&rvk_left, rc_right),
            // u_r = c[:n'] * v[n':]
            let tuc_r = commitment::single_g1::<E>(&rvk_right, rc_left)
        };

        // Fiat-Shamir challenge
        // combine both TIPP and MIPP transcript
        if i == 0 {
            // already generated c_inv and c outside of the loop
        } else {
            transcript.append(&c_inv);
            transcript.append(&zab_l);
            transcript.append(&zab_r);
            transcript.append(&zc_l);
            transcript.append(&zc_r);
            transcript.append(&tab_l);
            transcript.append(&tab_r);
            transcript.append(&tuc_l);
            transcript.append(&tuc_r);
            c_inv = transcript.challenge_scalar::<E::Fr>();

            // Optimization for multiexponentiation to rescale G2 elements with
            // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
            // of c_inv
            c = c_inv.inverse().unwrap();
        }

        // Set up values for next step of recursion
        // A[:n'] + A[n':] ^ x
        compress(&mut m_a, split, &c);
        // B[:n'] + B[n':] ^ x^-1
        compress(&mut m_b, split, &c_inv);

        // c[:n'] + c[n':]^x
        compress(&mut m_c, split, &c);
        r_left
            .par_iter_mut()
            .zip(r_right.par_iter_mut())
            .for_each(|(r_l, r_r)| {
                // r[:n'] + r[n':]^x^-1
                r_r.mul_assign(&c_inv);
                r_l.add_assign(r_r.clone());
            });
        let len = r_left.len();
        m_r.resize(len, E::Fr::zero()); // shrink to new size

        // v_left + v_right^x^-1
        vkey = vk_left.compress(&vk_right, &c_inv)?;
        // w_left + w_right^x
        wkey = wk_left.compress(&wk_right, &c)?;

        comms_ab.push((tab_l, tab_r));
        comms_c.push((tuc_l, tuc_r));
        z_ab.push((zab_l, zab_r));
        z_c.push((zc_l.into_affine(), zc_r.into_affine()));
        challenges.push(c);
        challenges_inv.push(c_inv);

        i += 1;
    }

    assert!(m_a.len() == 1 && m_b.len() == 1);
    assert!(m_c.len() == 1 && m_r.len() == 1);
    assert!(vkey.a.len() == 1 && vkey.b.len() == 1);
    assert!(wkey.a.len() == 1 && wkey.b.len() == 1);

    let (final_a, final_b, final_c) = (m_a[0], m_b[0], m_c[0]);
    let (final_vkey, final_wkey) = (vkey.first(), wkey.first());

    Ok((
        GipaProof {
            nproofs: a.len() as u32, // TODO: ensure u32
            comms_ab,
            comms_c,
            z_ab,
            z_c,
            final_a,
            final_b,
            final_c,
            final_vkey,
            final_wkey,
        },
        challenges,
        challenges_inv,
    ))
}

fn prove_commitment_v<G: AffineCurve>(
    srs_powers_alpha_table: &[G],
    srs_powers_beta_table: &[G],
    transcript: &[G::ScalarField],
    kzg_challenge: &G::ScalarField,
) -> Result<KZGOpening<G>, Error> {
    // f_v
    let vkey_poly = DensePolynomial::from_coefficients_vec(
        polynomial_coefficients_from_transcript(transcript, &G::ScalarField::one()),
    );

    // f_v(z)
    let vkey_poly_z = polynomial_evaluation_product_form_from_transcript(
        &transcript,
        kzg_challenge,
        &G::ScalarField::one(),
    );
    create_kzg_opening(
        srs_powers_alpha_table,
        srs_powers_beta_table,
        vkey_poly,
        vkey_poly_z,
        kzg_challenge,
    )
}

fn prove_commitment_w<G: AffineCurve>(
    srs_powers_alpha_table: &[G],
    srs_powers_beta_table: &[G],
    transcript: &[G::ScalarField],
    r_shift: &G::ScalarField,
    kzg_challenge: &G::ScalarField,
) -> Result<KZGOpening<G>, Error> {
    let n = srs_powers_alpha_table.len();
    // this computes f(X) = \prod (1 + x (rX)^{2^j})
    let mut fcoeffs = polynomial_coefficients_from_transcript(transcript, r_shift);
    // this computes f_w(X) = X^n * f(X) - it simply shifts all coefficients to by n
    let mut fwcoeffs = vec![G::ScalarField::zero(); fcoeffs.len()];
    fwcoeffs.append(&mut fcoeffs);
    let fw = DensePolynomial::from_coefficients_vec(fwcoeffs);

    par! {
        // this computes f(z)
        let fz = polynomial_evaluation_product_form_from_transcript(&transcript, kzg_challenge, &r_shift),
        // this computes the "shift" z^n
        let zn = kzg_challenge.pow(&[n as u64])
    };
    // this computes f_w(z) by multiplying by zn
    let mut fwz = fz;
    fwz.mul_assign(&zn);

    create_kzg_opening(
        srs_powers_alpha_table,
        srs_powers_beta_table,
        fw,
        fwz,
        kzg_challenge,
    )
}

/// Returns the KZG opening proof for the given commitment key. Specifically, it
/// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
fn create_kzg_opening<G: AffineCurve>(
    srs_powers_alpha_table: &[G], // h^alpha^i
    srs_powers_beta_table: &[G],  // h^beta^i
    poly: DensePolynomial<G::ScalarField>,
    eval_poly: G::ScalarField,
    kzg_challenge: &G::ScalarField,
) -> Result<KZGOpening<G>, Error> {
    let mut neg_kzg_challenge = *kzg_challenge;
    neg_kzg_challenge = neg_kzg_challenge.neg();

    if poly.coeffs().len() != srs_powers_alpha_table.len() {
        return Err(Error::InvalidSRS(
            format!(
                "SRS len {} != coefficients len {}",
                srs_powers_alpha_table.len(),
                poly.coeffs().len(),
            )
            .to_string(),
        ));
    }

    // f_v(X) - f_v(z) / (X - z)
    let quotient_polynomial = &(&poly - &DensePolynomial::from_coefficients_vec(vec![eval_poly]))
        / &(DensePolynomial::from_coefficients_vec(vec![neg_kzg_challenge, G::ScalarField::one()]));

    let mut quotient_polynomial_coeffs = quotient_polynomial.coeffs;
    quotient_polynomial_coeffs.resize(srs_powers_alpha_table.len(), <G::ScalarField>::zero());
    let quotient_repr = cfg_iter!(quotient_polynomial_coeffs)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();

    assert_eq!(
        quotient_polynomial_coeffs.len(),
        srs_powers_alpha_table.len()
    );
    assert_eq!(
        quotient_polynomial_coeffs.len(),
        srs_powers_beta_table.len()
    );

    // we do one proof over h^a and one proof over h^b (or g^a and g^b depending
    // on the curve we are on). that's the extra cost of the commitment scheme
    // used which is compatible with Groth16 CRS insteaf of the original paper
    // of Bunz'19
    let (a, b) = rayon::join(
        || VariableBaseMSM::multi_scalar_mul(&srs_powers_alpha_table, &quotient_repr),
        || VariableBaseMSM::multi_scalar_mul(&srs_powers_beta_table, &quotient_repr),
    );
    Ok(KZGOpening::new_from_proj(a, b))
}

/// It returns the evaluation of the polynomial $\prod (1 + x_{l-j}(rX)^{2j}$ at
/// the point z, where transcript contains the reversed order of all challenges (the x).
/// THe challenges must be in reversed order for the correct evaluation of the
/// polynomial in O(logn)
pub(super) fn polynomial_evaluation_product_form_from_transcript<F: Field>(
    transcript: &[F],
    z: &F,
    r_shift: &F,
) -> F {
    // this is the term (rz) that will get squared at each step to produce the
    // $(rz)^{2j}$ of the formula
    let mut power_zr = *z;
    power_zr.mul_assign(r_shift);

    let one = F::one();

    let mut res = one + transcript[0] * &power_zr;
    for x in &transcript[1..] {
        power_zr = power_zr.square();
        res.mul_assign(one + *x * &power_zr);
    }

    res
}

// Compute the coefficients of the polynomial $\prod_{j=0}^{l-1} (1 + x_{l-j}(rX)^{2j})$
// It does this in logarithmic time directly; here is an example with 2
// challenges:
//
//     We wish to compute $(1+x_1ra)(1+x_0(ra)^2) = 1 +  x_1ra + x_0(ra)^2 + x_0x_1(ra)^3$
//     Algorithm: $c_{-1} = [1]$; $c_j = c_{i-1} \| (x_{l-j} * c_{i-1})$; $r = r*r$
//     $c_0 = c_{-1} \| (x_1 * r * c_{-1}) = [1] \| [rx_1] = [1, rx_1]$, $r = r^2$
//     $c_1 = c_0 \| (x_0 * r^2c_0) = [1, rx_1] \| [x_0r^2, x_0x_1r^3] = [1, x_1r, x_0r^2, x_0x_1r^3]$
//     which is equivalent to $f(a) = 1 + x_1ra + x_0(ra)^2 + x_0x_1r^2a^3$
//
// This method expects the coefficients in reverse order so transcript[i] =
// x_{l-j}.
// f(Y) = Y^n * \prod (1 + x_{l-j-1} (r_shiftY^{2^j}))
fn polynomial_coefficients_from_transcript<F: Field>(transcript: &[F], r_shift: &F) -> Vec<F> {
    let mut coefficients = vec![F::one()];
    let mut power_2_r = *r_shift;

    for (i, x) in transcript.iter().enumerate() {
        let n = coefficients.len();
        if i > 0 {
            power_2_r = power_2_r.square();
        }
        for j in 0..n {
            let coeff = coefficients[j] * &(*x * &power_2_r);
            coefficients.push(coeff);
        }
    }

    coefficients
}
