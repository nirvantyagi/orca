#![feature(test)]

extern crate test;
use test::bench::Bencher;
use orca::{
    algmac::GGM,
    groupsig::{GroupSig, RevocationToken},
    token::TokenBL,
    Gat,
};

use algebra::{
    curves::{
        bls12_381::{Bls12_381, G1Projective},
        ProjectiveCurve,
    },
    fields::bls12_381::Fr,
    groups::Group,
    UniformRand,
};
use rand::{
    SeedableRng,
    rngs::StdRng,
};
use sha3::Sha3_256;


#[bench]
fn bench_sign_group_signature(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    let pp = GroupSigBLS::setup(&mut rng);
    let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
    let (oapk, _) = GroupSigBLS::keygen_oa(&pp, &mut rng);
    let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
    let (t, proof, _) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
    let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
    let m1 = "Plaintext".as_bytes();
    // Sign message
    b.iter(|| GroupSigBLS::sign(&pp, &gmpk, &oapk, &sk, m1, &mut rng));
}

#[bench]
fn bench_request_token(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type TokenBLS = TokenBL<Bls12_381, Sha3_256>;
    let pp = TokenBLS::setup(&mut rng);
    let (rpk, rsk, rtoksk) = TokenBLS::keygen_rec(&pp, &mut rng);
    let x = Fr::rand(&mut rng);
    // Prepare token request
    b.iter(|| TokenBLS::request_token_s1_user(&pp, &rpk, &x, &mut rng));
}

#[bench]
fn bench_verify_issue_token(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type TokenBLS = TokenBL<Bls12_381, Sha3_256>;
    let pp = TokenBLS::setup(&mut rng);
    let (rpk, rsk, rtoksk) = TokenBLS::keygen_rec(&pp, &mut rng);
    let x = Fr::rand(&mut rng);
    let (st, req) = TokenBLS::request_token_s1_user(&pp, &rpk, &x, &mut rng).unwrap();
    let (out, ct) = TokenBLS::eval_blind_token_s2_plt(&pp, &rpk, &rtoksk, &req, &mut rng).unwrap();
    // Verify issued token
    b.iter(|| <TokenBLS as Gat<GGM<G1Projective, Sha3_256>>>::Assoc::blind_mac_verify_output(&pp.mac_params(), &rpk.tokpk, &st, &out));
}


#[bench]
fn bench_issue_token(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type TokenBLS = TokenBL<Bls12_381, Sha3_256>;
    let pp = TokenBLS::setup(&mut rng);
    let (rpk, rsk, rtoksk) = TokenBLS::keygen_rec(&pp, &mut rng);
    let x = Fr::rand(&mut rng);
    let (st, req) = TokenBLS::request_token_s1_user(&pp, &rpk, &x, &mut rng).unwrap();
    // Issue token from request
    b.iter(|| TokenBLS::eval_blind_token_s2_plt(&pp, &rpk, &rtoksk, &req, &mut rng));
}

#[bench]
fn bench_verify_spend_token(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type AlgMacG1 = GGM<G1Projective, Sha3_256>;
    let pp = AlgMacG1::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
    let (_, sk) = AlgMacG1::keygen(&pp, &mut rng);
    let m = Fr::rand(&mut rng);
    let M = pp.g.mul(&m);
    let t = AlgMacG1::group_elem_mac(&pp, &sk, &M, &mut rng);
    b.iter(|| AlgMacG1::verify_mac(&pp, &sk, &m, &t));
}


fn bench_verify_group_signature(b: &mut Bencher, l: i8) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    let pp = GroupSigBLS::setup(&mut rng);
    let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
    let (oapk, _) = GroupSigBLS::keygen_oa(&pp, &mut rng);
    let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
    let (t, proof, _) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
    let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
    let m1 = "Plaintext".as_bytes();
    let sig = GroupSigBLS::sign(&pp, &gmpk, &oapk, &sk, m1, &mut rng).unwrap();
    // Create revocation list of input length
    let rlist = (0..l).map(|_| RevocationToken{tok: G1Projective::rand(&mut rng)}).collect();
    // Verify group signature
    b.iter(|| GroupSigBLS::verify(&pp, &gmsk, &oapk, &rlist, m1, &sig));
}

#[bench]
fn bench_verify_group_signature_list_0(b: &mut Bencher) {
    bench_verify_group_signature(b, 0);
}

#[bench]
fn bench_verify_group_signature_list_1(b: &mut Bencher) {
    bench_verify_group_signature(b, 1);
}

#[bench]
fn bench_verify_group_signature_list_5(b: &mut Bencher) {
    bench_verify_group_signature(b, 5);
}

#[bench]
fn bench_trace_group_signature(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    let pp = GroupSigBLS::setup(&mut rng);
    let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
    let (oapk, oask) = GroupSigBLS::keygen_oa(&pp, &mut rng);
    let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
    let (t, proof, _) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
    let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
    let m1 = "Plaintext".as_bytes();
    let sig = GroupSigBLS::sign(&pp, &gmpk, &oapk, &sk, m1, &mut rng).unwrap();
    b.iter(|| GroupSigBLS::trace(&pp, &oask, &sig));
}

#[bench]
fn bench_send_sealed_sender(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    let pp = GroupSigBLS::setup(&mut rng);
    let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
    let (oapk, _) = GroupSigBLS::keygen_oa(&pp, &mut rng);
    let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
    let (t, proof, _) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
    let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
    // Encapsulate sender identity
    b.iter(|| {
        let e_sk = Fr::rand(&mut rng);
        let e_dh = oapk.Z.mul(&e_sk);
        let shared_dh = oapk.Z.mul(&sk.x);
    });
}

#[bench]
fn bench_receive_sealed_sender(b: &mut Bencher) {
    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    let pp = GroupSigBLS::setup(&mut rng);
    let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
    let (oapk, oask) = GroupSigBLS::keygen_oa(&pp, &mut rng);
    let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
    let (t, proof, pk) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
    let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
    let e_pk = G1Projective::prime_subgroup_generator().mul(&Fr::rand(&mut rng));
    // Decapsulate sender identity
    b.iter(|| {
        let e_dh = e_pk.mul(&oask.z);
        let shared_dh = pk.X.mul(&oask.z);
    });
}

