use crate::{
    algmac::{GGM, Mac, MacProof},
    Error,
};
use algebra::{
    curves::PairingEngine,
    groups::Group,
    fields::PrimeField,
    UniformRand,
};
use digest::Digest;
use rand::Rng;
use std::marker::PhantomData;

pub struct GroupSig<E: PairingEngine, D: Digest>(PhantomData<E>, PhantomData<D>);

pub struct PublicParams<E: PairingEngine> {
    g1: E::G1Projective,
    h1: E::G1Projective,
    g2: E::G2Projective,
}

// Public and private key pair for group manager
pub struct GmPubKey<E: PairingEngine> =

pub struct GmSecretKey<E: PairingEngine> {
    x0: E::Fr,
    x1: E::Fr,
}

// Public and private key pair for group member
pub struct PubKey<E: PairingEngine> {
    X: E::G1Projective,
}

pub struct SecretKey<E: PairingEngine> {
    x: E::Fr,
    t: Mac<E>,
}

impl<E: PairingEngine, D: Digest> GroupSig<E, D> {
    pub fn setup<R: Rng>(rng: &mut R) -> PublicParams<E> {
        let gen1 = E::G1Projective::prime_subgroup_generator();
        let gen2 = E::G2Projective::prime_subgroup_generator();
        PublicParams {
            g1: gen1.mul(&E::Fr::rand(rng)),
            h1: gen1.mul(&E::Fr::rand(rng)),
            g2: gen2.mul(&E::Fr::rand(rng)),
        }
    }

    pub fn gm_keygen<R: Rng>(pp: &PublicParams<E>, rng: &mut R) -> (GmPubKey<E>, GmSecretKey<E>) {
        let sk = GmSecretKey {
            x0: E::Fr::rand(rng),
            x1: E::Fr::rand(rng),
        };
        let pk = GmPubKey {
            CX0: pp.h1.mul(&sk.x1),
            X1: pp.h1.mul(&sk.x1),
        };
        (pk, sk)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
