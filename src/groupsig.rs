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
    bytes::ToBytes,
    curves::{PairingEngine, ProjectiveCurve},
    groups::Group,
    fields::{Field, PrimeField},
    to_bytes, UniformRand,
};
use digest::Digest;
use rand::Rng;
use std::{
    io::{Result as IoResult, Write},
    marker::PhantomData
};

pub struct GroupSig<E: PairingEngine, D: Digest>(PhantomData<E>, PhantomData<D>);

pub struct PublicParams<E: PairingEngine> {
    pub g1: E::G1Projective,
    pub h1: E::G1Projective,
    pub g2: E::G2Projective,
}

impl<E: PairingEngine> ToBytes for PublicParams<E> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.g1.write(&mut writer)?;
        self.h1.write(&mut writer)?;
        self.g2.write(&mut writer)
    }
}

//TODO: Cloning params every time, better way to share struct data?
impl<E: PairingEngine> PublicParams<E> {
    pub(crate) fn mac_params(self: &Self) -> MacPublicParams<E::G1Projective> {
        MacPublicParams {g: self.g1.clone(), h: self.h1.clone()}
    }
}

// Public and private key pair for group manager
//TODO: Rust compiler error: "bounds on generic parameters are not enforced in type aliases"
pub type GmPubKey<E> = MacPubKey<<E as PairingEngine>::G1Projective>;

pub type GmSecretKey<E> = MacSecretKey<<E as PairingEngine>::G1Projective>;

// Public and private key pair for group member
#[derive(Clone)]
pub struct UPubKey<E: PairingEngine> {
    X: E::G1Projective,
}

pub struct USecretKey<E: PairingEngine> {
    x: E::Fr,
    t: Mac<E::G1Projective>,
}

// Public and private key pair for opening authority
pub struct OaPubKey<E: PairingEngine> {
    pub X1: E::G1Projective,
    X2: E::G2Projective,
}

pub struct OaSecretKey<E: PairingEngine> {
    x: E::Fr,
}

pub struct Signature<E: PairingEngine, D: Digest> {
    u0: E::G1Projective,
    C_sk: E::G1Projective,
    C_u1: E::G1Projective,
    ct1: E::G1Projective,
    ct2: E::G1Projective,
    z_sk: E::Fr,
    z_ask: E::Fr,
    z_u1: E::Fr,
    z_ct: E::Fr,
    c: E::Fr,
    phantom: PhantomData<D>,
}

#[derive(Copy, Clone)]
pub struct RevocationToken<E: PairingEngine> {
    tok: E::G1Projective,
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

    pub fn keygen_oa<R: Rng>(pp: &PublicParams<E>, rng: &mut R) -> (OaPubKey<E>, OaSecretKey<E>) {
        let x = E::Fr::rand(rng);
        (OaPubKey{X1: pp.g1.mul(&x), X2: pp.g2.mul(&x)}, OaSecretKey{x: x})
    }

    pub fn issue_s1_user<R: Rng>(pp: &PublicParams<E>, rng: &mut R) -> (E::G1Projective, E::Fr) {
        let x = E::Fr::rand(rng);
        (pp.g1.mul(&x), x)
    }

    pub fn issue_s2_gm<R: Rng>(
        pp: &PublicParams<E>,
        sk: &GmSecretKey<E>,
        X: &E::G1Projective,
        rng: &mut R,
    ) -> Result<(Mac<E::G1Projective>, MacProof<E::G1Projective, D>, UPubKey<E>), Error> {
        match <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::group_elem_mac_and_prove(
            &pp.mac_params(),
            sk,
            X,
            rng,
        ) {
            Ok((t, proof)) => Ok((t, proof, UPubKey{X: X.clone()})),
            Err(e) => Err(e),
        }
    }

    pub fn issue_s3_user(
        pp: &PublicParams<E>,
        pk: &GmPubKey<E>,
        x: &E::Fr,
        t: &Mac<E::G1Projective>,
        proof: &MacProof<E::G1Projective, D>,
    ) -> Result<USecretKey<E>, Error> {
        match <Self as Gat<GGM<E::G1Projective, D>>>::Assoc::verify_mac_proof(
            &pp.mac_params(),
            pk,
            &pp.g1.mul(x),
            t,
            proof,
        ) {
            Ok(_) => Ok(USecretKey{x: x.clone(), t: t.clone()}),
            Err(e) => Err(e),
        }
    }

    pub fn sign<R: Rng>(
        pp: &PublicParams<E>,
        gmpk: &GmPubKey<E>,
        oapk: &OaPubKey<E>,
        sk: &USecretKey<E>,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Signature<E, D>, Error> {

        // Encrypt revocation token to opening authority
        let a_ct = E::Fr::rand(rng);
        let ct1 = pp.g1.mul(&a_ct);
        let ct2 = oapk.X1.mul(&(sk.x + &a_ct));

        // Prepare commitments for proof statement of algebraic MAC
        let a_sk = E::Fr::rand(rng);
        let a_u1 = E::Fr::rand(rng);
        let t_r = sk.t.rerandomize(&E::Fr::rand(rng));
        let C_u1 = t_r.u1 + pp.g1.mul(&a_u1);
        let C_sk = t_r.u0.mul(&sk.x) + pp.h1.mul(&a_sk);

        // Generate random commitments and challenge for Sigma protocol
        let (r_sk, r_ask, r_u1, r_ct, c) = loop {
            let r_sk = E::Fr::rand(rng);
            let r_ask = E::Fr::rand(rng);
            let r_u1 = E::Fr::rand(rng);
            let r_ct = E::Fr::rand(rng);
            let s_csk = t_r.u0.mul(&r_sk) + pp.h1.mul(&r_ask);
            let s_v = pp.g1.mul(&r_u1) + gmpk.X1.mul(&r_ask);
            let s_ct1 = pp.g1.mul(&r_ct);
            let s_ct2 = oapk.X1.mul(&(r_sk + &r_ct));

            // Hash statement and commitments to get challenge
            let mut hash_input = Vec::new();
            let hash_bytes = to_bytes![
                pp,
                gmpk,
                oapk.X1,
                t_r.u0,
                ct1, ct2,
                C_u1, C_sk,
                s_csk.into_affine(),
                s_v.into_affine(),
                s_ct1.into_affine(),
                s_ct2.into_affine()
            ]?;
            hash_input.extend_from_slice(&hash_bytes);
            hash_input.extend_from_slice(msg);
            if let Some(c) = E::Fr::from_random_bytes(&D::digest(&hash_input)) {
                break (r_sk, r_ask, r_u1, r_ct, c);
            };
        };

        // Calculate prover response
        let z_sk = r_sk + &(c * &sk.x);
        let z_ask = r_ask + &(c * &a_sk);
        let z_u1 = r_u1 - &(c * &a_u1);
        let z_ct = r_ct + &(c * &a_ct);

        Ok(Signature{
            u0: t_r.u0,
            C_sk: C_sk,
            C_u1: C_u1,
            ct1: ct1,
            ct2: ct2,
            z_sk: z_sk,
            z_ask: z_ask,
            z_u1: z_u1,
            z_ct: z_ct,
            c: c,
            phantom: PhantomData,
        })
    }

    pub fn verify(
        pp: &PublicParams<E>,
        gmsk: &GmSecretKey<E>,
        oapk: &OaPubKey<E>,
        rev_list: &Vec<RevocationToken<E>>,
        msg: &[u8],
        sig: &Signature<E, D>,
    ) -> Result<bool, Error> {
        // Check ciphertext against revocation list
        if rev_list.iter()
            .any(|&rt|
                E::pairing((sig.ct2 - &rt.tok).clone(), pp.g2.clone())
                    == E::pairing(sig.ct1.clone(), oapk.X2.clone())) {
            return Err(Box::new(SignatureError::RevocationTokenMatch));
        }

        // Verify proof
        let V = sig.u0.mul(&gmsk.x0) + sig.C_sk.mul(&gmsk.x1) - &sig.C_u1;
        let s_csk = sig.u0.mul(&sig.z_sk) + pp.h1.mul(&sig.z_ask) - &sig.C_sk.mul(&sig.c);
        let s_v = pp.g1.mul(&sig.z_u1) + gmsk.pk.X1.mul(&sig.z_ask) - &V.mul(&sig.c);
        let s_ct1 = pp.g1.mul(&sig.z_ct) - &sig.ct1.mul(&sig.c);
        let s_ct2 = oapk.X1.mul(&(sig.z_sk + &sig.z_ct)) - &sig.ct2.mul(&sig.c);

        let mut hash_input = Vec::new();
        let hash_bytes = to_bytes![
                pp,
                gmsk.pk,
                oapk.X1,
                sig.u0,
                sig.ct1, sig.ct2,
                sig.C_u1, sig.C_sk,
                s_csk.into_affine(),
                s_v.into_affine(),
                s_ct1.into_affine(),
                s_ct2.into_affine()
            ]?;
        hash_input.extend_from_slice(&hash_bytes);
        hash_input.extend_from_slice(msg);
        match E::Fr::from_random_bytes(&D::digest(&hash_input)) {
            None => Err(Box::new(SignatureError::ProofVerificationFailed)),
            Some(c) => {
                if c == sig.c {
                    Ok(true)
                } else {
                    Err(Box::new(SignatureError::ProofVerificationFailed))
                }
            },
        }
    }

    pub fn trace(
        pp: &PublicParams<E>,
        oask: &OaSecretKey<E>,
        sig: &Signature<E, D>,
    ) -> UPubKey<E> {
        UPubKey{
            X: (sig.ct2 - &sig.ct1.mul(&oask.x)).mul(&(oask.x.inverse().unwrap())).clone(),
        }
    }

    pub fn revoke(
        pp: &PublicParams<E>,
        oask:&OaSecretKey<E>,
        upk: &UPubKey<E>,
    ) -> RevocationToken<E> {
        RevocationToken{tok: upk.X.mul(&oask.x)}
    }

}



#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        curves::{
            bls12_381::Bls12_381,
        },
    };
    use rand::{
        SeedableRng,
        rngs::StdRng,
    };
    use sha3::Sha3_256;


    #[test]
    fn issue_user() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
        let pp = GroupSigBLS::setup(&mut rng);
        let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
        let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
        let (t, proof, _) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
        let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
        assert!(sk.x == sk_s1);
    }

    #[test]
    fn sign_and_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
        let pp = GroupSigBLS::setup(&mut rng);
        let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
        let (oapk, _) = GroupSigBLS::keygen_oa(&pp, &mut rng);
        let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
        let (t, proof, _) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
        let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
        // Sign message
        let m1 = "Plaintext".as_bytes();
        let sig = GroupSigBLS::sign(&pp, &gmpk, &oapk, &sk, m1, &mut rng).unwrap();
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk, &vec![], m1, &sig).is_ok());
        // Fails on different message
        let m2 = "Different Plaintext".as_bytes();
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk, &vec![], m2, &sig).is_err());
        // Fails on different keys
        let (_, gmsk2) = GroupSigBLS::keygen_gm(&pp, &mut rng);
        let (oapk2, _) = GroupSigBLS::keygen_oa(&pp, &mut rng);
        assert!(GroupSigBLS::verify(&pp, &gmsk2, &oapk, &vec![], m1, &sig).is_err());
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk2, &vec![], m1, &sig).is_err());
    }

    #[test]
    fn trace() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
        let pp = GroupSigBLS::setup(&mut rng);
        let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
        let (oapk, oask) = GroupSigBLS::keygen_oa(&pp, &mut rng);
        let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
        let (t, proof, pk) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
        let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
        // Sign message
        let m1 = "Plaintext".as_bytes();
        let sig = GroupSigBLS::sign(&pp, &gmpk, &oapk, &sk, m1, &mut rng).unwrap();
        // Trace message
        let upk = GroupSigBLS::trace(&pp, &oask, &sig);
        assert!(upk.X == pk.X);
    }

    #[test]
    fn revoke() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
        let pp = GroupSigBLS::setup(&mut rng);
        let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
        let (oapk, oask) = GroupSigBLS::keygen_oa(&pp, &mut rng);
        let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
        let (t, proof, pk) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
        let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
        // Sign message
        let m1 = "Plaintext".as_bytes();
        let sig = GroupSigBLS::sign(&pp, &gmpk, &oapk, &sk, m1, &mut rng).unwrap();
        // Revoke signer
        let rt = GroupSigBLS::revoke(&pp, &oask, &pk);
        // Verification
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk, &vec![rt.clone()], m1, &sig).is_err());
        let (oapk2, oask2) = GroupSigBLS::keygen_oa(&pp, &mut rng);
        let rt2 = GroupSigBLS::revoke(&pp, &oask2, &pk);
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk2, &vec![rt.clone()], m1, &sig).is_err());
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk, &vec![rt2.clone()], m1, &sig).is_ok());
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk2, &vec![rt2.clone()], m1, &sig).is_err());
        assert!(GroupSigBLS::verify(&pp, &gmsk, &oapk, &vec![rt.clone(), rt2.clone()], m1, &sig).is_err());
    }

}
