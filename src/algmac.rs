use algebra::{
    bytes::ToBytes,
    groups::Group,
    to_bytes, UniformRand,
};

use digest::Digest;
use rand::Rng;
use std::{
    error::Error,
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
    z: G,
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
        let r0 = G::ScalarField::rand(rng);
        let r1 = G::ScalarField::rand(rng);
        let rt = G::ScalarField::rand(rng);
        let s_u1 = t.u0.mul(&r0) + M.mul(&r1);
        let s_cx0 = pp.g.mul(&r0) + pp.h.mul(&rt);
        let s_x1 = pp.h.mul(&r1);

        // Hash statement and commitments to get challenge
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&to_bytes![pp]?);

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

    #[test]
    fn mac_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type AlgMacG1 = AlgMac<G1Projective>;
        let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (pk, sk) = AlgMacG1::keygen(&pp, &mut rng);
        let m = Fr::rand(&mut rng);
        let M = pp.g.mul(&m);
        let t = AlgMacG1::blind_mac(&pp, &sk, &M);
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t));
        assert!(AlgMacG1::verify_mac(&pp, &sk, &m, &t.rerandomize(&mut rng)));
    }
}
