use crate::{
    algmac::{
        GGM,
        PubKey as MacPubKey,
        SecretKey as MacSecretKey,
        Mac, MacProof,
        BlindMacInput, BlindMacState,
        BlindMacOutput,
    },
    error::{Error, SignatureError},
    groupsig::{
        GroupSig,
        PublicParams as GSPublicParams,
        GmPubKey, GmSecretKey,
        OaPubKey, OaSecretKey,
        UPubKey as GSUPubKey, USecretKey as GSUSecretKey,
    },
    Gat,
};
use algebra::{
    bytes::{ToBytes, FromBytes},
    curves::{PairingEngine, ProjectiveCurve},
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

pub struct TokenBL<E: PairingEngine, D: Digest>(PhantomData<E>, PhantomData<D>);

#[allow(type_alias_bounds)]
pub type PublicParams<E: PairingEngine> = GSPublicParams<E>;

#[allow(type_alias_bounds)]
pub type PltPubKey<E: PairingEngine> = GmPubKey<E>;

#[allow(type_alias_bounds)]
pub type PltSecretKey<E: PairingEngine> = GmSecretKey<E>;

pub struct RecPubKey<E: PairingEngine> {
    pub oapk: OaPubKey<E>,
    pub tokpk: MacPubKey<E::G1Projective>,
}

impl<E: PairingEngine> ToBytes for RecPubKey<E> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.oapk.write(&mut writer)?;
        self.tokpk.write(&mut writer)
    }
}

impl<E: PairingEngine> FromBytes for RecPubKey<E> {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let oapk = OaPubKey::<E>::read(&mut reader)?;
        let tokpk = MacPubKey::<E::G1Projective>::read(&mut reader)?;
        Ok(Self{ oapk, tokpk })
    }
}


#[allow(type_alias_bounds)]
pub type RecSecretKey<E: PairingEngine> = OaSecretKey<E>;
pub type RecTokenSecretKey<E> = MacSecretKey<<E as PairingEngine>::G1Projective>;

#[allow(type_alias_bounds)]
pub type SndPubKey<E: PairingEngine> = GSUPubKey<E>;
#[allow(type_alias_bounds)]
pub type SndSecretKey<E: PairingEngine> = GSUSecretKey<E>;


#[allow(dead_code)]
pub struct Token<E: PairingEngine> {
    x: E::Fr,
    t: E::G1Projective,
}

pub struct TokenRequest<E: PairingEngine, D: Digest> {
    blind: BlindMacInput<E::G1Projective>,
    ct: TokenCiphertext<E>,
    proof: TokenEnclosedProof<E, D>,
}

impl<E: PairingEngine, D: Digest> ToBytes for TokenRequest<E, D> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.blind.write(&mut writer)?;
        self.ct.write(&mut writer)?;
        self.proof.write(&mut writer)
    }
}

#[derive(Clone)]
pub struct TokenCiphertext<E: PairingEngine> {
    pub ct1: E::G1Projective,
    pub ct2: E::G1Projective,
}

impl<E: PairingEngine> ToBytes for TokenCiphertext<E> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.ct1.write(&mut writer)?;
        self.ct2.write(&mut writer)
    }
}

pub struct TokenEnclosedProof<E: PairingEngine, D: Digest> {
    z_x: E::Fr,
    z_r: E::Fr,
    z_rh: E::Fr,
    c: E::Fr,
    phantom: PhantomData<D>,
}

impl<E: PairingEngine, D: Digest> ToBytes for TokenEnclosedProof<E, D> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.z_x.write(&mut writer)?;
        self.z_r.write(&mut writer)?;
        self.z_rh.write(&mut writer)?;
        self.c.write(&mut writer)
    }
}


impl<E: PairingEngine, D: Digest> Gat<GroupSig<E, D>> for TokenBL<E, D> {
    type Assoc = GroupSig<E, D>;
}

impl<E: PairingEngine, D: Digest> Gat<GGM<E::G1Projective, D>> for TokenBL<E, D> {
    type Assoc = GGM<E::G1Projective, D>;
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
        let (tokpk, toksk) = <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::keygen(&pp.mac_params(), rng);
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

    #[allow(non_snake_case)]
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
        <Self as Gat<GroupSig<E, D>>>::Assoc::issue_s3_user(pp, pk, x, t, proof)
    }

    pub fn request_token_s1_user<R: Rng>(
        pp: &PublicParams<E>,
        rpk: &RecPubKey<E>,
        x: &E::Fr,
        rng: &mut R
    ) -> Result<(BlindMacState<E::G1Projective>, TokenRequest<E, D>), Error> {
        let (st, blind) = <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::blind_mac_input(&pp.mac_params(), x, rng);

        // Create ciphertext to recipient enclosing token input
        let rh = E::Fr::rand(rng);
        let ct1h = pp.g1.mul(&rh);
        let ct2h = pp.g1.mul(x) + rpk.oapk.Z.mul(&rh);

        // Prove ciphertext formed correctly
        // Generate random commitments and challenge for Sigma protocol
        let (r_x, r_r, r_rh, c) = loop {
            let r_x = E::Fr::rand(rng);
            let r_r = E::Fr::rand(rng);
            let r_rh = E::Fr::rand(rng);

            let s_ct1 = pp.g1.mul(&r_r);
            let s_ct2 = pp.g1.mul(&r_x) + st.input.D.mul(&r_r);
            let s_ct1h = pp.g1.mul(&r_rh);
            let s_ct2h = pp.g1.mul(&r_x) + rpk.oapk.Z.mul(&r_rh);

            let mut hash_input = Vec::new();
            let hash_bytes = to_bytes![
                pp,
                blind, rpk.oapk.Z,
                ct1h, ct2h,
                s_ct1.into_affine(),
                s_ct2.into_affine(),
                s_ct1h.into_affine(),
                s_ct2h.into_affine()
            ]?;
            hash_input.extend_from_slice(&hash_bytes);
            if let Some(c) = E::Fr::from_random_bytes(&D::digest(&hash_input)) {
                break (r_x, r_r, r_rh, c);
            };
        };

        // Calculate prover response
        let proof = TokenEnclosedProof {
            z_x: r_x + &(c * x),
            z_r: r_r + &(c * &st.r),
            z_rh: r_rh + &(c * &rh),
            c: c,
            phantom: PhantomData,
        };
        let req = TokenRequest {
            blind: blind,
            ct: TokenCiphertext {ct1: ct1h, ct2: ct2h},
            proof: proof,
        };

        Ok((st, req))
    }

    pub fn eval_blind_token_s2_plt<R: Rng>(
        pp: &PublicParams<E>,
        rpk: &RecPubKey<E>,
        rtoksk: &RecTokenSecretKey<E>,
        req: &TokenRequest<E, D>,
        rng: &mut R,
    ) -> Result<(BlindMacOutput<E::G1Projective, D>, TokenCiphertext<E>), Error>{
        // Verify ciphertext proof
        let s_ct1 = pp.g1.mul(&req.proof.z_r) - &req.blind.ct1.mul(&req.proof.c);
        let s_ct2 = pp.g1.mul(&req.proof.z_x) + req.blind.D.mul(&req.proof.z_r) - &req.blind.ct2.mul(&req.proof.c);
        let s_ct1h = pp.g1.mul(&req.proof.z_rh) - &req.ct.ct1.mul(&req.proof.c);
        let s_ct2h = pp.g1.mul(&req.proof.z_x) + rpk.oapk.Z.mul(&req.proof.z_rh) - &req.ct.ct2.mul(&req.proof.c);

        let mut hash_input = Vec::new();
        let hash_bytes = to_bytes![
                pp,
                req.blind, rpk.oapk.Z,
                req.ct.ct1, req.ct.ct2,
                s_ct1.into_affine(),
                s_ct2.into_affine(),
                s_ct1h.into_affine(),
                s_ct2h.into_affine()
            ]?;
        hash_input.extend_from_slice(&hash_bytes);
        match E::Fr::from_random_bytes(&D::digest(&hash_input)) {
            None => Err(Box::new(SignatureError::ProofVerificationFailed)),
            Some(c) => {
                if c == req.proof.c {
                    let output = <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::blind_mac_eval(&pp.mac_params(), rtoksk, &req.blind, rng)?;
                    Ok((output, req.ct.clone()))
                } else {
                    Err(Box::new(SignatureError::ProofVerificationFailed))
                }
            },
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        curves::{
            bls12_381::Bls12_381,
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
    fn token_generation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type TokenBLS = TokenBL<Bls12_381, Sha3_256>;
        let pp = TokenBLS::setup(&mut rng);
        let (rpk, _rsk, rtoksk) = TokenBLS::keygen_rec(&pp, &mut rng);
        // Request token
        let x = Fr::rand(&mut rng);
        let (_st, req) = TokenBLS::request_token_s1_user(&pp, &rpk, &x, &mut rng).unwrap();
        // Evaluate blind token
        assert!(TokenBLS::eval_blind_token_s2_plt(&pp, &rpk, &rtoksk, &req, &mut rng).is_ok());
    }

}
