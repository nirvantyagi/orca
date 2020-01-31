use crate::{
    algmac::{
        GGM,
        PubKey as MacPubKey,
        SecretKey as MacSecretKey,
        Mac,
        MacProof,
    },
    error::{Error, SignatureError},
    groupsig::{
        GroupSig,
        PublicParams as GSPublicParams,
        GmPubKey, GmSecretKey,
        OaPubKey, OaSecretKey,
        UPubKey as GSUPubKey, USecretKey as GSUSecretKey,
        Signature, RevocationToken,
    },
    Gat,
};
use algebra::{
    bytes::ToBytes,
    curves::{PairingEngine, ProjectiveCurve},
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

pub struct TokenBL<E: PairingEngine, D: Digest>(PhantomData<E>, PhantomData<D>);

pub type PublicParams<E: PairingEngine> = GSPublicParams<E>;

pub type PltPubKey<E: PairingEngine> = GmPubKey<E>;

pub type PltSecretKey<E: PairingEngine> = GmSecretKey<E>;

pub struct RecPubKey<E: PairingEngine> {
    oapk: OaPubKey<E>,
    tokpk: MacPubKey<E::G1Projective>,
}

pub type RecSecretKey<E: PairingEngine> = OaSecretKey<E>;
pub type RecTokenSecretKey<E> = MacSecretKey<<E as PairingEngine>::G1Projective>;

pub type SndPubKey<E: PairingEngine> = GSUPubKey<E>;
pub type SndSecretKey<E: PairingEngine> = GSUSecretKey<E>;


pub struct TokenRequestS1<E: PairingEngine, D: Digest> {
    blinded_token: E::G1Projective,
    ct1: E::G1Projective,
    ct2: E::G1Projective,
    proof: TokenEnclosedProof<E, D>,
}

pub struct TokenEnclosedProof<E: PairingEngine, D: Digest> {
    c: E::Fr,
    phantom: PhantomData<D>,
}

pub struct TokenEvalProof<E: PairingEngine, D: Digest> {
    c: E::Fr,
    phantom: PhantomData<D>,
}

impl<E: PairingEngine, D: Digest> Gat<GroupSig<E, D>> for TokenBL<E, D> {
    type Assoc = GroupSig<E, D>;
}

impl<E: PairingEngine, D: Digest> Gat<AlgMac<E::G1Projective, D>> for TokenBL<E, D> {
    type Assoc = AlgMac<E::G1Projective, D>;
}

impl<E: PairingEngine, D: Digest> TokenBL<E, D> {

    pub fn setup<R: Rng>(rng: &mut R) -> PublicParams<E> {
        <Self as Gat<GroupSig<E, D>>>::Assoc::setup(rng)
    }

    pub fn keygen_plt<R: Rng>(pp: &PublicParams<E>, rng: &mut R) -> (PltPubKey<E>, PltSecretKey<E>) {
        <Self as Gat<GroupSig<E, D>>>::Assoc::keygen_gm(pp, rng)
    }

    pub fn keygen_rec<R: Rng>(
        pp: &PublicParams<E>, rng: &mut R
    ) -> (RecPubKey<E>, RecSecretKey<E>, RecTokenSecretKey<E>) {
        let (oapk, oask) = <Self as Gat<GroupSig<E, D>>>::Assoc::keygen_oa(pp, rng);
        let (tokpk, toksk) = <Self as Gat<AlgMac<E::G1Projective, D>>>::Assoc::keygen(&pp.mac_params(), rng);
        (
            RecPubKey{oapk: oapk, tokpk: tokpk},
            oask,
            toksk,
        )
    }

    // TODO: Refine registration with output/state structs and include generation of receiver keys
    pub fn register_s1_user<R: Rng>(
        pp: &PublicParams<E>, rng: &mut R) -> (E::G1Projective, E::Fr) {
        <Self as Gat<GroupSig<E, D>>>::Assoc::issue_s1_user(pp, rng)
    }

    pub fn register_s2_plt<R: Rng>(
        pp: &PublicParams<E>,
        sk: &PltSecretKey<E>,
        X: &E::G1Projective,
        rng: &mut R,
    ) -> Result<(Mac<E::G1Projective>, MacProof<E::G1Projective, D>, SndPubKey<E>), Error> {
        <Self as Gat<GroupSig<E, D>>>::Assoc::issue_s2_gm(pp, sk, X, rng)
    }

    pub fn register_s3_user(
        pp: &PublicParams<E>,
        pk: &PltPubKey<E>,
        x: &E::Fr,
        t: &Mac<E::G1Projective>,
        proof: &MacProof<E::G1Projective, D>,
    ) -> Result<SndSecretKey<E>, Error> {
        <Self as Gat<GroupSig<E, D>>>::Assoc::issue_s3_gm(pp, pk, x, t, proof)
    }

    fn request_token_s1_user<R: Rng>(
        pp: &PublicParams<E>,
        rpk: &RecPubKey<E>,
        input: E::Fr,
        rng: R
    ) -> (E::Fr, TokenRequestS1<E, D>) {
        let r = E::Fr::rand(rng);
        let blinded_token = hash_to_curve(&to_bytes![input].unwrap()).mul(&r);
    }

    fn eval_s2_plt<R: Rng>(
    ) {

    }

}

