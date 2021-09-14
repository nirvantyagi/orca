use crate::error::{Error, SignatureError};
use algebra::{
    bytes::{ToBytes, FromBytes},
    curves::ProjectiveCurve,
    groups::Group,
    fields::PrimeField,
    to_bytes, UniformRand,
};
use digest::Digest;
use rand::Rng;
use std::{
    io::{Result as IoResult, Write, Read},
    marker::PhantomData,
    vec::Vec,
};

//TODO: switch generic type back to Group if able to fix serialization/hashing
pub struct GGM<G: ProjectiveCurve, D: Digest>(PhantomData<G>, PhantomData<D>);

pub struct PublicParams<G: ProjectiveCurve> {
    pub g: G,
    pub h: G,
}

//TODO: derive algebra::bytes::ToBytes from struct?
impl<G: ProjectiveCurve> ToBytes for PublicParams<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.g.write(&mut writer)?;
        self.h.write(&mut writer)
    }
}

// Public and private MAC key pair
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct PubKey<G: ProjectiveCurve> {
    pub CX0: G,
    pub X1: G,
}

#[allow(non_snake_case)]
impl<G: ProjectiveCurve> FromBytes for PubKey<G> {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let CX0 = G::read(&mut reader)?;
        let X1 = G::read(&mut reader)?;
        Ok(Self { CX0, X1 })
    }
}


impl<G: ProjectiveCurve> ToBytes for PubKey<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.CX0.write(&mut writer)?;
        self.X1.write(&mut writer)
    }
}


pub struct SecretKey<G: ProjectiveCurve> {
    pub x0: G::ScalarField,
    pub x1: G::ScalarField,
    pub xt: G::ScalarField,
    pub pk: PubKey<G>,
}

impl<G: ProjectiveCurve> FromBytes for SecretKey<G> {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let x0 = <G::ScalarField>::read(&mut reader)?;
        let x1 = <G::ScalarField>::read(&mut reader)?;
        let xt = <G::ScalarField>::read(&mut reader)?;
        let pk = PubKey::<G>::read(&mut reader)?;
        Ok(Self { x0, x1, xt, pk })
    }
}

impl<G: ProjectiveCurve> ToBytes for SecretKey<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.x0.write(&mut writer)?;
        self.x1.write(&mut writer)?;
        self.xt.write(&mut writer)?;
        self.pk.write(&mut writer)
    }
}

#[derive(Clone)]
pub struct Mac<G: ProjectiveCurve> {
    pub u0: G,
    pub u1: G,
}

impl<G: ProjectiveCurve> ToBytes for Mac<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.u0.write(&mut writer)?;
        self.u1.write(&mut writer)
    }
}

#[allow(non_snake_case)]
pub struct MacProof<G: ProjectiveCurve, D: Digest> {
    M_r: G,
    z0: G::ScalarField,
    z1: G::ScalarField,
    zt: G::ScalarField,
    zr: G::ScalarField,
    c: G::ScalarField,
    phantom: PhantomData<D>,
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct BlindMacInput<G: ProjectiveCurve> {
    pub D: G,
    pub ct1: G,
    pub ct2: G,
}

impl<G: ProjectiveCurve> ToBytes for BlindMacInput<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.D.write(&mut writer)?;
        self.ct1.write(&mut writer)?;
        self.ct2.write(&mut writer)
    }
}


pub struct BlindMacState<G: ProjectiveCurve> {
    pub delta: G::ScalarField,
    pub r: G::ScalarField,
    pub input: BlindMacInput<G>,
}

pub struct BlindMacOutput<G: ProjectiveCurve, D: Digest> {
    u0: G,
    ct1: G,
    ct2: G,
    proof: BlindMacProof<G, D>,
}

#[allow(non_snake_case)]
pub struct BlindMacProof<G: ProjectiveCurve, D: Digest> {
    X_b1: G,
    z_x0: G::ScalarField,
    z_x1: G::ScalarField,
    z_xt: G::ScalarField,
    z_r: G::ScalarField,
    z_b: G::ScalarField,
    z_b1: G::ScalarField,
    c: G::ScalarField,
    phantom: PhantomData<D>,
}

impl<G: ProjectiveCurve, D: Digest> GGM<G, D> {

    pub fn setup<R: Rng>(gen: &G, rng: &mut R) -> PublicParams<G> {
        PublicParams {
            g: gen.mul(&G::ScalarField::rand(rng)),
            h: gen.mul(&G::ScalarField::rand(rng)),
        }
    }

    pub fn keygen<R: Rng>(pp: &PublicParams<G>, rng: &mut R)
        -> (PubKey<G>, SecretKey<G>) {
        let x0 =  G::ScalarField::rand(rng);
        let x1 = G::ScalarField::rand(rng);
        let xt = G::ScalarField::rand(rng);
        let pk = PubKey {
            CX0: pp.g.mul(&x0) + pp.h.mul(&xt),
            X1: pp.h.mul(&x1),
        };
        let sk = SecretKey {
            x0: x0,
            x1: x1,
            xt: xt,
            pk: pk.clone(),
        };
        (pk, sk)
    }

    pub fn scalar_mac<R: Rng>(
        pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        m: &G::ScalarField,
        rng: &mut R,
    ) -> Mac<G> {
        Mac {
            u0: pp.g,
            u1: pp.g.mul(&(sk.x0 + &(sk.x1 * m))),
        }.rerandomize(&G::ScalarField::rand(rng))
    }

    // MACs "M" where "M" in G
    #[allow(non_snake_case)]
    pub fn group_elem_mac<R: Rng>(
        pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        M: &G,
        rng: &mut R,
    ) -> Mac<G> {
        Mac {
            u0: pp.g,
            u1: M.mul(&sk.x1) + pp.g.mul(&sk.x0),
        }.rerandomize(&G::ScalarField::rand(rng))
    }

    pub fn verify_mac(
        _pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        m: &G::ScalarField,
        t: &Mac<G>
    ) -> bool {
        t.u0.mul(&(*m * &sk.x1 + &sk.x0)) == t.u1
    }

    // MACs "M" where "M = g^m" and "m" is hidden
    #[allow(non_snake_case)]
    pub fn group_elem_mac_and_prove<R: Rng>(
        pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        M: &G,
        rng: &mut R,
    ) -> Result<(Mac<G>, MacProof<G, D>), Error>{
        // Create MAC with base g and rerandomize
        let r = G::ScalarField::rand(rng);
        let t = Mac {
            u0: pp.g,
            u1: M.mul(&sk.x1) + pp.g.mul(&sk.x0),
        }.rerandomize(&r);
        let M_r = M.mul(&r);

        // Generate random commitments
        let (r0, r1, rt, rr, c) = loop {
            let r0 = G::ScalarField::rand(rng);
            let r1 = G::ScalarField::rand(rng);
            let rt = G::ScalarField::rand(rng);
            let rr = G::ScalarField::rand(rng);
            let s_u0 = pp.g.mul(&rr);
            let s_mr = M.mul(&rr);
            let s_u1 = t.u0.mul(&r0) + M_r.mul(&(r1));
            let s_cx0 = pp.g.mul(&r0) + pp.h.mul(&rt);
            let s_x1 = pp.h.mul(&r1);

            // Hash statement and commitments to get challenge
            // TODO: Does hash function create random bytes that maps to full scalar field?
            let mut hash_input = Vec::new();
            let hash_bytes = to_bytes![
                pp,
                sk.pk,
                t,
                M, M_r,
                s_u0.into_affine(),
                s_mr.into_affine(),
                s_u1.into_affine(),
                s_cx0.into_affine(),
                s_x1.into_affine()
            ]?;
            hash_input.extend_from_slice(&hash_bytes);
            if let Some(c) = G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
                break (r0, r1, rt, rr, c);
            };
        };

        // Calculate prover response
        let proof = MacProof {
            M_r: M_r,
            z0: r0 + &(c * &sk.x0),
            z1: r1 + &(c * &sk.x1),
            zt : rt + &(c * &sk.xt),
            zr : rr + &(c * &r),
            c: c,
            phantom: PhantomData,
        };

        Ok((t, proof))
    }

    #[allow(non_snake_case)]
    pub fn verify_mac_proof(
        pp: &PublicParams<G>,
        pk: &PubKey<G>,
        M: &G,
        t: &Mac<G>,
        proof: &MacProof<G, D>
    ) -> Result<bool, Error> {
        let s_u0 = pp.g.mul(&proof.zr) - &t.u0.mul(&proof.c);
        let s_mr = M.mul(&proof.zr) - &proof.M_r.mul(&proof.c);
        let s_u1 = t.u0.mul(&proof.z0) + &proof.M_r.mul(&(proof.z1)) - &t.u1.mul(&proof.c);
        let s_cx0 = pp.g.mul(&proof.z0) + pp.h.mul(&proof.zt) - &pk.CX0.mul(&proof.c);
        let s_x1 = pp.h.mul(&proof.z1) - &pk.X1.mul(&proof.c);

        let mut hash_input = Vec::new();
        let hash_bytes = to_bytes![
            pp,
            pk,
            t,
            M, &proof.M_r,
            s_u0.into_affine(),
            s_mr.into_affine(),
            s_u1.into_affine(),
            s_cx0.into_affine(),
            s_x1.into_affine()
        ]?;
        hash_input.extend_from_slice(&hash_bytes);
        match G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
            None => Err(Box::new(SignatureError::ProofVerificationFailed)),
            Some(c) => {
                if c == proof.c {
                    Ok(true)
                } else {
                    Err(Box::new(SignatureError::ProofVerificationFailed))
                }
            },
        }
    }

    #[allow(non_snake_case)]
    pub fn blind_mac_input<R: Rng>(
        pp: &PublicParams<G>,
        m: &G::ScalarField,
        rng: &mut R,
    ) -> (BlindMacState<G>, BlindMacInput<G>) {
        let r = G::ScalarField::rand(rng);
        let delta = G::ScalarField::rand(rng);
        let D = pp.g.mul(&delta);
        let input = BlindMacInput{
            D: D,
            ct1: pp.g.mul(&r),
            ct2: pp.g.mul(m) + D.mul(&r),
        };
        (BlindMacState{delta: delta, r: r, input: input.clone()}, input)
    }

    #[allow(non_snake_case)]
    pub fn blind_mac_eval<R: Rng>(
        pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        inp: &BlindMacInput<G>,
        rng: &mut R,
    ) -> Result<BlindMacOutput<G, D>, Error> {
        let b = G::ScalarField::rand(rng);
        let r = G::ScalarField::rand(rng);

        // Homomorphically evaluate encryption of MAC
        let b1 = sk.x1 * &b;
        let u0 = pp.g.mul(&b);
        let ct1 = inp.ct1.mul(&b1) + pp.g.mul(&r);
        let ct2 = inp.ct2.mul(&b1) + u0.mul(&sk.x0) + inp.D.mul(&r);

        // Create auxiliary variable useful for proving discrete log products
        let X_b1 = pp.h.mul(&b1);

        // Generate random commitments and challenge for Sigma protocol
        let (r_x0, r_x1, r_xt, r_r, r_b, r_b1, c) = loop {
            let r_x0 = G::ScalarField::rand(rng);
            let r_x1 = G::ScalarField::rand(rng);
            let r_xt = G::ScalarField::rand(rng);
            let r_r = G::ScalarField::rand(rng);
            let r_b = G::ScalarField::rand(rng);
            let r_b1 = G::ScalarField::rand(rng);

            let s_x1 = pp.h.mul(&r_x1);
            let s_cx0 = pp.g.mul(&r_x0) + pp.h.mul(&r_xt);
            let s_xb1_a = sk.pk.X1.mul(&r_b);
            let s_xb1_b = pp.h.mul(&r_b1);
            let s_u0 = pp.g.mul(&r_b);
            let s_ct1 = inp.ct1.mul(&r_b1) + pp.g.mul(&r_r);
            let s_ct2 = inp.ct2.mul(&r_b1) + u0.mul(&r_x0) + inp.D.mul(&r_r);

            let mut hash_input = Vec::new();
            let hash_bytes = to_bytes![
                pp,
                sk.pk,
                inp,
                u0, X_b1,
                ct1, ct2,
                s_x1.into_affine(),
                s_cx0.into_affine(),
                s_xb1_a.into_affine(),
                s_xb1_b.into_affine(),
                s_u0.into_affine(),
                s_ct1.into_affine(),
                s_ct2.into_affine()
            ]?;
            hash_input.extend_from_slice(&hash_bytes);
            if let Some(c) = G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
                break (r_x0, r_x1, r_xt, r_r, r_b, r_b1, c);
            };
        };

        // Calculate prover response
        let proof = BlindMacProof {
            X_b1: X_b1,
            z_x0: r_x0 + &(c * &sk.x0),
            z_x1: r_x1 + &(c * &sk.x1),
            z_xt: r_xt + &(c * &sk.xt),
            z_r: r_r + &(c * &r),
            z_b: r_b + &(c * &b),
            z_b1: r_b1 + &(c * &b1),
            c: c,
            phantom: PhantomData,
        };
        let output = BlindMacOutput {
            u0: u0,
            ct1: ct1,
            ct2: ct2,
            proof: proof,
        };
        Ok(output)
    }

    pub fn blind_mac_verify_output(
        pp: &PublicParams<G>,
        pk: &PubKey<G>,
        st: &BlindMacState<G>,
        output: &BlindMacOutput<G, D>,
    ) -> Result<Mac<G>, Error> {
        let s_x1 = pp.h.mul(&output.proof.z_x1) - &pk.X1.mul(&output.proof.c);
        let s_cx0 = pp.g.mul(&output.proof.z_x0) + pp.h.mul(&output.proof.z_xt) - &pk.CX0.mul(&output.proof.c);
        let s_xb1_a = pk.X1.mul(&output.proof.z_b) - &output.proof.X_b1.mul(&output.proof.c);
        let s_xb1_b = pp.h.mul(&output.proof.z_b1) - &output.proof.X_b1.mul(&output.proof.c);
        let s_u0 = pp.g.mul(&output.proof.z_b) - &output.u0.mul(&output.proof.c);
        let s_ct1 = st.input.ct1.mul(&output.proof.z_b1) + pp.g.mul(&output.proof.z_r) - &output.ct1.mul(&output.proof.c);
        let s_ct2 = st.input.ct2.mul(&output.proof.z_b1) + output.u0.mul(&output.proof.z_x0) + st.input.D.mul(&output.proof.z_r) - &output.ct2.mul(&output.proof.c);

        let mut hash_input = Vec::new();
        let hash_bytes = to_bytes![
                pp,
                pk,
                st.input,
                output.u0, output.proof.X_b1,
                output.ct1, output.ct2,
                s_x1.into_affine(),
                s_cx0.into_affine(),
                s_xb1_a.into_affine(),
                s_xb1_b.into_affine(),
                s_u0.into_affine(),
                s_ct1.into_affine(),
                s_ct2.into_affine()
            ]?;
        hash_input.extend_from_slice(&hash_bytes);
        match G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
            None => Err(Box::new(SignatureError::ProofVerificationFailed)),
            Some(c) => {
                if c == output.proof.c {
                    let u1 = output.ct2 - &output.ct1.mul(&st.delta);
                    Ok(Mac{u0: output.u0, u1: u1})
                } else {
                    Err(Box::new(SignatureError::ProofVerificationFailed))
                }
            },
        }
    }

}

impl<G: ProjectiveCurve> Mac<G> {
    pub fn rerandomize(self: &Self, r: &G::ScalarField) -> Self {
        Mac {
            u0: self.u0.mul(&r),
            u1: self.u1.mul(&r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        curves::{
            bls12_381::G1Projective,
            ProjectiveCurve,
        },
        fields::bls12_381::Fr,
        UniformRand,
    };
    use rand::{
        SeedableRng,
        rngs::StdRng,
    };
    use sha3::Sha3_256;

    #[test]
    #[allow(non_snake_case)]
    fn mac_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = GGM<G1Projective, Sha3_256>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (_, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let M = pp.g.mul(&m);
        let t = AlgMacG1::group_elem_mac(&pp, &sk, &M, &mut rng);
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t));
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t.rerandomize(&Fr::rand(&mut rng))));
    }

    #[test]
    #[allow(non_snake_case)]
    fn mac_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = GGM<G1Projective, Sha3_256>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (pk, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let M = pp.g.mul(&m);
        let (t, proof) = AlgMacG1::group_elem_mac_and_prove(&pp, &sk, &M, &mut rng).unwrap();
        assert!(AlgMacG1::verify_mac_proof(&pp, &pk, &M, &t, &proof).unwrap());
    }

    #[test]
    fn blind_mac() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = GGM<G1Projective, Sha3_256>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (pk, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let (st, input) = AlgMacG1::blind_mac_input(&pp, &m, &mut rng);
        let output = AlgMacG1::blind_mac_eval(&pp, &sk, &input, &mut rng).unwrap();
        let t = AlgMacG1::blind_mac_verify_output(&pp, &pk, &st, &output).unwrap();
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t));
    }

}
