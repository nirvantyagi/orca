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
    bytes::{ToBytes, FromBytes},
    curves::{PairingEngine, ProjectiveCurve},
    groups::Group,
    fields::{PrimeField},
    to_bytes, UniformRand,
};
use digest::Digest;
use rand::Rng;
use std::{
    io::{Result as IoResult, Write, Read},
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
    pub fn mac_params(self: &Self) -> MacPublicParams<E::G1Projective> {
        MacPublicParams {g: self.g1.clone(), h: self.h1.clone()}
    }
}

// Public and private key pair for group manager
//TODO: Rust compiler error: "bounds on generic parameters are not enforced in type aliases"
pub type GmPubKey<E> = MacPubKey<<E as PairingEngine>::G1Projective>;

pub type GmSecretKey<E> = MacSecretKey<<E as PairingEngine>::G1Projective>;

// Public and private key pair for group member
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct UPubKey<E: PairingEngine> {
    pub X: E::G1Projective,
}

pub struct USecretKey<E: PairingEngine> {
    pub x: E::Fr,
    t: Mac<E::G1Projective>,
}

// Public and private key pair for opening authority
#[allow(non_snake_case)]
pub struct OaPubKey<E: PairingEngine> {
    pub W: E::G1Projective,
    pub Z: E::G1Projective,
}

#[allow(non_snake_case)]
impl<E: PairingEngine> FromBytes for OaPubKey<E> {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let W = E::G1Projective::read(&mut reader)?;
        let Z = E::G1Projective::read(&mut reader)?;
        Ok(Self { W, Z })
    }
}


impl<E: PairingEngine> ToBytes for OaPubKey<E> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.W.write(&mut writer)?;
        self.Z.write(&mut writer)
    }
}

pub struct OaSecretKey<E: PairingEngine> {
    pub w: E::Fr,
    pub z: E::Fr,
}

#[allow(non_snake_case)]
pub struct Signature<E: PairingEngine, D: Digest> {
    u0: E::G1Projective,
    C_sk: E::G1Projective,
    C_u1: E::G1Projective,
    V: E::G1Projective,
    ct1: E::G1Projective,
    ct2: E::G1Projective,
    M_1: E::G1Projective,
    pub M_2: E::G2Projective,
    N_1: E::G1Projective,
    pub N_2: E::G2Projective,
    pub T_1: E::G1Projective,
    pub T_2: E::G1Projective,
    z_sk: E::Fr,
    z_ask: E::Fr,
    z_u1: E::Fr,
    z_ct: E::Fr,
    z_T: E::Fr,
    z_rm: E::Fr,
    z_rn: E::Fr,
    c: E::Fr,
    phantom: PhantomData<D>,
}

#[derive(Copy, Clone)]
pub struct RevocationToken<E: PairingEngine> {
    pub tok: E::G1Projective,
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
        let w = E::Fr::rand(rng);
        let z = E::Fr::rand(rng);
        (OaPubKey{W: pp.g1.mul(&w), Z: pp.g1.mul(&z)}, OaSecretKey{w: w, z: z})
    }

    pub fn issue_s1_user<R: Rng>(pp: &PublicParams<E>, rng: &mut R) -> (E::G1Projective, E::Fr) {
        let x = E::Fr::rand(rng);
        (pp.g1.mul(&x), x)
    }

    #[allow(non_snake_case)]
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

    #[allow(non_snake_case)]
    pub fn sign<R: Rng>(
        pp: &PublicParams<E>,
        gmpk: &GmPubKey<E>,
        oapk: &OaPubKey<E>,
        sk: &USecretKey<E>,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Signature<E, D>, Error> {

        // Encrypt identity to opening authority
        let a_ct = E::Fr::rand(rng);
        let ct1 = pp.g1.mul(&a_ct);
        let ct2 = pp.g1.mul(&sk.x) + oapk.Z.mul(&a_ct);

        // Enclose revocation token in DLIN ciphertext
        let r_m = E::Fr::rand(rng);
        let r_n = E::Fr::rand(rng);
        let a_T = E::Fr::rand(rng);
        let M_1 = pp.g1.mul(&r_m);
        let M_2 = pp.g2.mul(&r_m);
        let N_1 = pp.g1.mul(&r_n);
        let N_2 = pp.g2.mul(&r_n);
        let T_1 = M_1.mul(&a_T);
        let T_2 = oapk.W.mul(&sk.x) + N_1.mul(&a_T);

        // Prepare commitments for proof statement of algebraic MAC
        let a_sk = E::Fr::rand(rng);
        let a_u1 = E::Fr::rand(rng);
        let t_r = sk.t.rerandomize(&E::Fr::rand(rng));
        let C_u1 = t_r.u1 + pp.g1.mul(&a_u1);
        let C_sk = t_r.u0.mul(&sk.x) + pp.h1.mul(&a_sk);
        let V = pp.g1.mul(&-a_u1) + gmpk.X1.mul(&a_sk);

        // Generate random commitments and challenge for Sigma protocol
        let (r_sk, r_ask, r_u1, r_ct, r_T, r_rm, r_rn, c) = loop {
            let r_sk = E::Fr::rand(rng);
            let r_ask = E::Fr::rand(rng);
            let r_u1 = E::Fr::rand(rng);
            let r_ct = E::Fr::rand(rng);
            let r_T = E::Fr::rand(rng);
            let r_rm = E::Fr::rand(rng);
            let r_rn = E::Fr::rand(rng);
            let s_csk = t_r.u0.mul(&r_sk) + pp.h1.mul(&r_ask);
            let s_v = pp.g1.mul(&r_u1) + gmpk.X1.mul(&r_ask);
            let s_ct1 = pp.g1.mul(&r_ct);
            let s_ct2 = pp.g1.mul(&r_sk) + oapk.Z.mul(&r_ct);
            let s_m1 = pp.g1.mul(&r_rm);
            let s_m2 = pp.g2.mul(&r_rm);
            let s_n1 = pp.g1.mul(&r_rn);
            let s_n2 = pp.g2.mul(&r_rn);
            let s_t1 = M_1.mul(&r_T);
            let s_t2 = oapk.W.mul(&r_sk) + N_1.mul(&r_T);

            // Hash statement and commitments to get challenge
            let mut hash_input = Vec::new();
            let hash_bytes = to_bytes![
                pp,
                gmpk,
                oapk,
                t_r.u0,
                ct1, ct2,
                M_1, M_2, N_1, N_2, T_1, T_2,
                C_u1, C_sk,
                s_csk.into_affine(),
                s_v.into_affine(),
                s_ct1.into_affine(),
                s_ct2.into_affine(),
                s_m1.into_affine(),
                s_m2.into_affine(),
                s_n1.into_affine(),
                s_n2.into_affine(),
                s_t1.into_affine(),
                s_t2.into_affine()
            ]?;
            hash_input.extend_from_slice(&hash_bytes);
            hash_input.extend_from_slice(msg);
            if let Some(c) = E::Fr::from_random_bytes(&D::digest(&hash_input)) {
                break (r_sk, r_ask, r_u1, r_ct, r_T, r_rm, r_rn, c);
            };
        };

        // Calculate prover response
        let z_sk = r_sk + &(c * &sk.x);
        let z_ask = r_ask + &(c * &a_sk);
        let z_u1 = r_u1 - &(c * &a_u1);
        let z_ct = r_ct + &(c * &a_ct);
        let z_T = r_T + &(c * &a_T);
        let z_rm = r_rm + &(c * &r_m);
        let z_rn = r_rn + &(c * &r_n);

        Ok(Signature{
            u0: t_r.u0,
            C_sk: C_sk,
            C_u1: C_u1,
            V: V,
            ct1: ct1,
            ct2: ct2,
            M_1: M_1, M_2: M_2, N_1: N_1, N_2: N_2,
            T_1: T_1, T_2: T_2,
            z_sk: z_sk,
            z_ask: z_ask,
            z_u1: z_u1,
            z_ct: z_ct,
            z_T: z_T, z_rm: z_rm, z_rn: z_rn,
            c: c,
            phantom: PhantomData,
        })
    }

    #[allow(non_snake_case)]
    pub fn verify(
        pp: &PublicParams<E>,
        gmsk: &GmSecretKey<E>,
        oapk: &OaPubKey<E>,
        rev_list: &Vec<RevocationToken<E>>,
        msg: &[u8],
        sig: &Signature<E, D>,
    ) -> Result<bool, Error> {
        let pair_test = E::pairing(sig.T_1.clone(), sig.N_2.clone());
        // Check ciphertext against revocation list
        if rev_list.iter()
            .any(|&rt|
                E::pairing((sig.T_2 - &rt.tok).clone(), sig.M_2.clone()) == pair_test) {
            return Err(Box::new(SignatureError::RevocationTokenMatch));
        }

        // Verify proof
        let V = sig.u0.mul(&gmsk.x0) + sig.C_sk.mul(&gmsk.x1) - &sig.C_u1;
        let s_csk = sig.u0.mul(&sig.z_sk) + pp.h1.mul(&sig.z_ask) - &sig.C_sk.mul(&sig.c);
        let s_v = pp.g1.mul(&sig.z_u1) + gmsk.pk.X1.mul(&sig.z_ask) - &V.mul(&sig.c);
        let s_ct1 = pp.g1.mul(&sig.z_ct) - &sig.ct1.mul(&sig.c);
        let s_ct2 = pp.g1.mul(&sig.z_sk) + oapk.Z.mul(&sig.z_ct) - &sig.ct2.mul(&sig.c);
        let s_m1 = pp.g1.mul(&sig.z_rm) - &sig.M_1.mul(&sig.c);
        let s_m2 = pp.g2.mul(&sig.z_rm) - &sig.M_2.mul(&sig.c);
        let s_n1 = pp.g1.mul(&sig.z_rn) - &sig.N_1.mul(&sig.c);
        let s_n2 = pp.g2.mul(&sig.z_rn) - &sig.N_2.mul(&sig.c);
        let s_t1 = sig.M_1.mul(&sig.z_T) - &sig.T_1.mul(&sig.c);
        let s_t2 = oapk.W.mul(&sig.z_sk) + sig.N_1.mul(&sig.z_T) - &sig.T_2.mul(&sig.c);

        let mut hash_input = Vec::new();
        let hash_bytes = to_bytes![
                pp,
                gmsk.pk,
                oapk,
                sig.u0,
                sig.ct1, sig.ct2,
                sig.M_1, sig.M_2, sig.N_1, sig.N_2, sig.T_1, sig.T_2,
                sig.C_u1, sig.C_sk,
                s_csk.into_affine(),
                s_v.into_affine(),
                s_ct1.into_affine(),
                s_ct2.into_affine(),
                s_m1.into_affine(),
                s_m2.into_affine(),
                s_n1.into_affine(),
                s_n2.into_affine(),
                s_t1.into_affine(),
                s_t2.into_affine()
            ]?;
        hash_input.extend_from_slice(&hash_bytes);
        hash_input.extend_from_slice(msg);
        match E::Fr::from_random_bytes(&D::digest(&hash_input)) {
            None => Err(Box::new(SignatureError::ProofVerificationFailed)),
            Some(c) => {
                if c == sig.c && V.into_affine() == sig.V.into_affine() {
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
        gmpk: &GmPubKey<E>,
        msg: &[u8],
        sig: &Signature<E, D>,
    ) -> Result<UPubKey<E>, Error> {

        let oapk: OaPubKey<E> = OaPubKey{W: pp.g1.mul(&oask.w), Z: pp.g1.mul(&oask.z)};
        // Verify proof
        let s_csk = sig.u0.mul(&sig.z_sk) + pp.h1.mul(&sig.z_ask) - &sig.C_sk.mul(&sig.c);
        let s_v = pp.g1.mul(&sig.z_u1) + gmpk.X1.mul(&sig.z_ask) - &sig.V.mul(&sig.c);
        let s_ct1 = pp.g1.mul(&sig.z_ct) - &sig.ct1.mul(&sig.c);
        let s_ct2 = pp.g1.mul(&sig.z_sk) + oapk.Z.mul(&sig.z_ct) - &sig.ct2.mul(&sig.c);
        let s_m1 = pp.g1.mul(&sig.z_rm) - &sig.M_1.mul(&sig.c);
        let s_m2 = pp.g2.mul(&sig.z_rm) - &sig.M_2.mul(&sig.c);
        let s_n1 = pp.g1.mul(&sig.z_rn) - &sig.N_1.mul(&sig.c);
        let s_n2 = pp.g2.mul(&sig.z_rn) - &sig.N_2.mul(&sig.c);
        let s_t1 = sig.M_1.mul(&sig.z_T) - &sig.T_1.mul(&sig.c);
        let s_t2 = oapk.W.mul(&sig.z_sk) + sig.N_1.mul(&sig.z_T) - &sig.T_2.mul(&sig.c);

        let mut hash_input = Vec::new();
        let hash_bytes = to_bytes![
                pp,
                gmpk,
                oapk,
                sig.u0,
                sig.ct1, sig.ct2,
                sig.M_1, sig.M_2, sig.N_1, sig.N_2, sig.T_1, sig.T_2,
                sig.C_u1, sig.C_sk,
                s_csk.into_affine(),
                s_v.into_affine(),
                s_ct1.into_affine(),
                s_ct2.into_affine(),
                s_m1.into_affine(),
                s_m2.into_affine(),
                s_n1.into_affine(),
                s_n2.into_affine(),
                s_t1.into_affine(),
                s_t2.into_affine()
            ]?;
        hash_input.extend_from_slice(&hash_bytes);
        hash_input.extend_from_slice(msg);
        match E::Fr::from_random_bytes(&D::digest(&hash_input)) {
            None => Err(Box::new(SignatureError::ProofVerificationFailed)),
            Some(c) => {
                if c == sig.c {
                    Ok(UPubKey{
                        X: sig.ct2 - &sig.ct1.mul(&oask.z),
                    })
                } else {
                    Err(Box::new(SignatureError::ProofVerificationFailed))
                }
            },
        }
    }

    pub fn revoke(
        _pp: &PublicParams<E>,
        oask:&OaSecretKey<E>,
        upk: &UPubKey<E>,
    ) -> RevocationToken<E> {
        RevocationToken{tok: upk.X.mul(&oask.w)}
    }

}



#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        curves::{
            bls12_381::Bls12_381,
            bls12_381::G1Affine,
            bls12_381::G2Affine,
        },
        fields::bls12_381::Fr,
    };
    use rand::{
        SeedableRng,
        rngs::StdRng,
    };
    use sha3::Sha3_256;
    use std::mem;


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
        let upk = GroupSigBLS::trace(&pp, &oask, &gmpk, m1, &sig).unwrap();
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

    #[test]
    fn bandwidth() {
        assert_eq!(104, mem::size_of::<G1Affine>());
        assert_eq!(200, mem::size_of::<G2Affine>());
        assert_eq!(32, mem::size_of::<Fr>());

    }
}
