use crate::error::{Error, SignatureError};
use algebra::{
    bytes::ToBytes,
    curves::ProjectiveCurve,
    groups::Group,
    fields::PrimeField,
    to_bytes, UniformRand,
};
use digest::Digest;
use rand::Rng;
use std::{
    io::{Result as IoResult, Write},
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
pub struct PubKey<G: ProjectiveCurve> {
    pub CX0: G,
    pub X1: G,
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

pub struct MacProof<G: ProjectiveCurve, D: Digest> {
    z0: G::ScalarField,
    z1: G::ScalarField,
    zt: G::ScalarField,
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

    // MACs "M" where "M = g^m" and "m" is hidden
    pub fn blind_mac(
        pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        M: &G,
    ) -> Mac<G> {
        Mac {
            u0: pp.g,
            u1: M.mul(&sk.x1) + pp.g.mul(&sk.x0),
        }
    }

    pub fn verify_mac(
        pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        m: &G::ScalarField,
        t: &Mac<G>
    ) -> bool {
        t.u0.mul(&(*m * &sk.x1 + &sk.x0)) == t.u1
    }

    pub fn blind_mac_and_prove<R: Rng>(
        pp: &PublicParams<G>,
        sk: &SecretKey<G>,
        M: &G,
        rng: &mut R,
    ) -> Result<(Mac<G>, MacProof<G, D>), Error>{
        let t = Self::blind_mac(pp, sk, M);
        // Generate random commitments
        let (r0, r1, rt, c) = loop {
            let r0 = G::ScalarField::rand(rng);
            let r1 = G::ScalarField::rand(rng);
            let rt = G::ScalarField::rand(rng);
            let s_u1 = t.u0.mul(&r0) + M.mul(&r1);
            let s_cx0 = pp.g.mul(&r0) + pp.h.mul(&rt);
            let s_x1 = pp.h.mul(&r1);

            // Hash statement and commitments to get challenge
            // TODO: Does hash function create random bytes that maps to full scalar field?
            let mut hash_input = Vec::new();
            let hash_bytes = to_bytes![
                pp,
                sk.pk,
                t,
                M,
                s_u1.into_affine(),
                s_cx0.into_affine(),
                s_x1.into_affine()
            ]?;
            hash_input.extend_from_slice(&hash_bytes);
            if let Some(c) = G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
                break (r0, r1, rt, c);
            };
        };

        // Calculate prover response
        let proof = MacProof {
            z0: r0 + &(c * &sk.x0),
            z1: r1 + &(c * &sk.x1),
            zt : rt + &(c * &sk.xt),
            c: c,
            phantom: PhantomData,
        };

        Ok((t, proof))
    }

    pub fn verify_mac_proof(
        pp: &PublicParams<G>,
        pk: &PubKey<G>,
        M: &G,
        t: &Mac<G>,
        proof: &MacProof<G, D>
    ) -> Result<bool, Error> {
        let s_u1 = t.u0.mul(&proof.z0) + M.mul(&proof.z1) - &t.u1.mul(&proof.c);
        let s_cx0 = pp.g.mul(&proof.z0) + pp.h.mul(&proof.zt) - &pk.CX0.mul(&proof.c);
        let s_x1 = pp.h.mul(&proof.z1) - &pk.X1.mul(&proof.c);

        let mut hash_input = Vec::new();
        let hash_bytes = to_bytes![
            pp,
            pk,
            t,
            M,
            s_u1.into_affine(),
            s_cx0.into_affine(),
            s_x1.into_affine()
        ]?;
        hash_input.extend_from_slice(&hash_bytes);
        match G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
            None => Ok(false),
            Some(c) => {
                if c == proof.c {
                    Ok(true)
                } else {
                    Err(Box::new(SignatureError::ProofVerificationFailed))
                }
            },
        }
    }


}

impl<G: ProjectiveCurve> Mac<G> {
    pub fn rerandomize<R: Rng>(self: &Self, rng: &mut R) -> Self {
        let r = G::ScalarField::rand(rng);
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
    fn mac_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = GGM<G1Projective, Sha3_256>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (_, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let M = pp.g.mul(&m);
        let t = AlgMacG1::blind_mac(&pp, &sk, &M);
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t));
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t.rerandomize(&mut rng)));
    }

    #[test]
    fn mac_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = GGM<G1Projective, Sha3_256>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (pk, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let M = pp.g.mul(&m);
        let (t, proof) = AlgMacG1::blind_mac_and_prove(&pp, &sk, &M, &mut rng).unwrap();
        assert!(AlgMacG1::verify_mac_proof(&pp, &pk, &M, &t, &proof).unwrap());
    }

}
