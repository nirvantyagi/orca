use crate::{
    algmac::{
        GGM,
        PublicParams as MacPublicParams,
        PubKey as MacPubKey,
        SecretKey as MacSecretKey,
        Mac,
        MacProof,
    },
    error::{Error, SignatureError},
    Gat,
};
use algebra::{
    curves::{PairingEngine, ProjectiveCurve},
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

//TODO: Cloning params every time, better way to share struct data?
impl<E: PairingEngine> PublicParams<E> {
    fn mac_params(self: &Self) -> MacPublicParams<E::G1Projective> {
        MacPublicParams {g: self.g1.clone(), h: self.h1.clone()}
    }
}

// Public and private key pair for group manager
//TODO: Rust compiler error: "bounds on generic parameters are not enforced in type aliases"
pub type GmPubKey<E> = MacPubKey<<E as PairingEngine>::G1Projective>;

pub type GmSecretKey<E> = MacSecretKey<<E as PairingEngine>::G1Projective>;

// Public and private key pair for group member
pub struct PubKey<E: PairingEngine> {
    X: E::G1Projective,
}

pub struct SecretKey<E: PairingEngine> {
    x: E::Fr,
    t: Mac<E::G1Projective>,
}

// TODO: associated types not allowed in inherent impls - better way to keep GGM around?
impl<E: PairingEngine, D: Digest> Gat<GGM<E::G1Projective, D>> for GroupSig<E, D> {
    type Assoc = GGM<E::G1Projective, D>;
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

    pub fn keygen_gm<R: Rng>(pp: &PublicParams<E>, rng: &mut R) -> (GmPubKey<E>, GmSecretKey<E>) {
        <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::keygen(&pp.mac_params(), rng)
    }

    pub fn issue_s1_user<R: Rng>(pp: &PublicParams<E>, rng: &mut R) -> (E::Fr, E::G1Projective) {
        let x = E::Fr::rand(rng);
        (x, pp.g1.mul(&x))
    }

    pub fn issue_s2_gm<R: Rng>(
        pp: &PublicParams<E>,
        sk: &GmSecretKey<E>,
        X: &E::G1Projective,
        rng: &mut R,
    ) -> Result<(Mac<E::G1Projective>, MacProof<E::G1Projective, D>), Error> {
        <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::blind_mac_and_prove(
            &pp.mac_params(),
            sk,
            X,
            rng,
        )
    }

    pub fn issue_s3_user<R: Rng>(
        pp: &PublicParams<E>,
        pk: &GmPubKey<E>,
        x: &E::Fr,
        t: &Mac<E::G1Projective>,
        proof: &MacProof<E::G1Projective, D>,
    ) -> Result<SecretKey<E>, Error> {
        match <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::verify_mac_proof(
            &pp.mac_params(),
            pk,
            &pp.g1.mul(x),
            t,
            proof,
        ) {
            Ok(_) => Ok(SecretKey{x: x.clone(), t: t.clone()}),
            Err(e) => Err(e),
        }
    }

}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
