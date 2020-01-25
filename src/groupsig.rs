use algebra::curves::PairingEngine;

use rand;
use std::marker::PhantomData;

pub struct GroupSig<E: PairingEngine>(PhantomData<E>);

pub struct PublicParams<E: PairingEngine> {
    g1: E::G1Projective,
    h1: E::G1Projective,
    g2: E::G2Projective,
}

// Public and private key pair for group manager
pub struct GmPubKey<E: PairingEngine> {
    CX0: E::G1Projective,
    X1: E::G1Projective,
}

pub struct GmPrivKey<E: PairingEngine> {
    x0: E::Fr,
    x1: E::Fr,
}

// Public and private key pair for group member
pub struct PubKey<E: PairingEngine> {
    X: E::G1Projective,
}

pub struct PrivKey<E: PairingEngine> {
    x: E::Fr,
    t: (E::G1Projective, E::G1Projective),
}

impl<E: PairingEngine> GroupSig<E> {
    pub fn setup() -> PublicParams<E> {
        let gen1 = E::G1Projective::prime_subgroup_generator();
        let gen2 = E::G2Projective::prime_subgroup_generator();
        PublicParams {
            g1: gen1.mul(&rand::random()),
            h1: gen1.mul(&rand::random()),
            g2: gen2.mul(rand::random()),
        }
    }

    pub fn gm_keygen(pp: &PublicParams<E>) -> (GmPubKey<E>, GmPrivKey<E>) {
        let sk = GmPrivKey {
            x0: rand::random(),
            x1: rand::random(),
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
