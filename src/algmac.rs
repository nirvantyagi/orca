use crate::Error;
use algebra::{
    bytes::ToBytes,
    fields::PrimeField,
    groups::Group,
    to_bytes, UniformRand,
};
use digest::Digest;
use rand::Rng;
use std::{
    hash::Hash,
    io::{Result as IoResult, Write},
    marker::PhantomData,
    vec::Vec,
};

pub struct AlgMac<G: Group, D: Digest>(PhantomData<G>, PhantomData<D>);

pub struct PublicParams<G: Group> {
    g: G,
    h: G,
}

//TODO: derive algebra::bytes::ToBytes from struct?
impl<G: Group> ToBytes for PublicParams<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.g.write(&mut writer)?;
        self.h.write(&mut writer)
    }
}

// Public and private MAC key pair
#[derive(Clone)]
pub struct PubKey<G: Group> {
    CX0: G,
    X1: G,
}

impl<G: Group> ToBytes for PubKey<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.CX0.write(&mut writer)?;
        self.X1.write(&mut writer)
    }
}


pub struct SecretKey<G: Group> {
    x0: G::ScalarField,
    x1: G::ScalarField,
    xt: G::ScalarField,
    pk: PubKey<G>,
}

pub struct Mac<G: Group> {
    u0: G,
    u1: G,
}

impl<G: Group> ToBytes for Mac<G> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.u0.write(&mut writer)?;
        self.u1.write(&mut writer)
    }
}

pub struct MacProof<G: Group, D: Digest> {
    z0: G::ScalarField,
    z1: G::ScalarField,
    zt: G::ScalarField,
    c: G::ScalarField,
    phantom: PhantomData<D>,
}

impl<G: Group + Hash, D: Digest> AlgMac<G, D> {
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
        let (r0, r1, rt, c, s_u1) = loop {
            let r0 = G::ScalarField::rand(rng);
            let r1 = G::ScalarField::rand(rng);
            let rt = G::ScalarField::rand(rng);
            let s_u1 = t.u0.mul(&r0) + M.mul(&r1);
            let s_cx0 = pp.g.mul(&r0) + pp.h.mul(&rt);
            let s_x1 = pp.h.mul(&r1);

            // Hash statement and commitments to get challenge
            // TODO: Does hash function create random bytes that maps to full scalar field?
            let mut hash_input = Vec::new();
            //let hash_bytes = to_bytes![pp, sk.pk, t, M, s_u1, s_cx0, s_x1]?;
            let hash_bytes = to_bytes![s_u1]?;
            println!("P u1 commitment: {}", s_u1);
            println!("P hash bytes: {:x?}", hash_bytes);
            hash_input.extend_from_slice(&hash_bytes);
            if let Some(c) = G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
                break (r0, r1, rt, c, s_u1);
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

        let v_s_u1 = t.u0.mul(&proof.z0) + M.mul(&proof.z1) - &t.u1.mul(&proof.c);
        let hash_bytes = to_bytes![v_s_u1]?;
        println!("V u1 commitment: {}", v_s_u1);
        println!("V hash bytes: {:x?}", hash_bytes);
        println!("P == V? {}", s_u1 == v_s_u1);

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
        //let hash_bytes = to_bytes![pp, pk, t, M, s_u1, s_cx0, s_x1]?;
        let hash_bytes = to_bytes![s_u1]?;
        println!("C u1 commitment: {}", s_u1);
        println!("C hash bytes: {:x?}", hash_bytes);
        hash_input.extend_from_slice(&hash_bytes);
        match G::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
            None => Ok(false),
            Some(c) => {
                println!("Calculated challenge: {}", c);
                println!("Proof challenge: {}", proof.c);
                Ok(c == proof.c)
            },
        }
    }


}

impl<G: Group> Mac<G> {
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

    fn mac_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = AlgMac<G1Projective, Sha3_256>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (pk, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let M = pp.g.mul(&m);
        let t = AlgMacG1::blind_mac(&pp, &sk, &M);
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t));
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t.rerandomize(&mut rng)));
    }

    #[test]
    fn mac_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = AlgMac<G1Projective, Sha3_256>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (pk, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let M = pp.g.mul(&m);
        let (t, proof) = AlgMacG1::blind_mac_and_prove(&pp, &sk, &M, &mut rng).unwrap();
        println!("Output of verify: {}", AlgMacG1::verify_mac_proof(&pp, &pk, &M, &t, &proof).unwrap());
        assert!(AlgMacG1::verify_mac_proof(&pp, &pk, &M, &t, &proof).unwrap());
    }

}
