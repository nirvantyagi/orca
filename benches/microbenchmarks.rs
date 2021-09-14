#![feature(test)]
extern crate test;

use orca::{
    algmac::GGM,
    groupsig::{GroupSig},
    token::TokenBL,
    Gat,
};

use algebra::{
    curves::{
        bls12_381::{Bls12_381, G1Projective},
        ProjectiveCurve,
        PairingEngine,
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
use std::{
    time::Instant,
};
use test::stats::*;

#[allow(unused_must_use)]
fn main() {
    const NUM_TRIALS: usize = 10;
    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    type TokenBLS = TokenBL<Bls12_381, Sha3_256>;
    type MACBLS = GGM<G1Projective, Sha3_256>;

    // Group signature benchmarks
    let mut sign_times = Vec::new();
    let mut verify_times = Vec::new();
    let mut verify_revocation_token_times = Vec::new();
    let mut open_times = Vec::new();

    let mut start: Instant;
    for _ in 0..NUM_TRIALS {
        let pp = GroupSigBLS::setup(&mut rng);
        let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
        let (oapk, oask) = GroupSigBLS::keygen_oa(&pp, &mut rng);
        let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
        let (t, proof, _) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
        let sk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();
        let m1 = vec![0; 64];

        // Sign message
        start = Instant::now();
        let sig = GroupSigBLS::sign(&pp, &gmpk, &oapk, &sk, &m1, &mut rng).unwrap();
        sign_times.push(start.elapsed().as_micros());

        // Verify signature with no revocation list
        start = Instant::now();
        GroupSigBLS::verify(&pp, &gmsk, &oapk, &Vec::new(), &m1, &sig).unwrap();
        verify_times.push(start.elapsed().as_micros());

        // Open signature
        start = Instant::now();
        GroupSigBLS::trace(&pp, &oask, &gmpk, &m1, &sig).unwrap();
        open_times.push(start.elapsed().as_micros());

        // Each revocation token in list incurs one pairing cost
        let pair_test = <Bls12_381 as PairingEngine>::pairing(sig.T_1.clone(), sig.N_2.clone());
        let tok = G1Projective::rand(&mut rng);
        start = Instant::now();
        <Bls12_381 as PairingEngine>::pairing((sig.T_2 - &tok).clone(), sig.M_2.clone()) == pair_test;
        verify_revocation_token_times.push(start.elapsed().as_micros());
    }

    println!("===================================");
    println!("GROUP SIGNATURE MICROBENCHMARKS...");
    println!("===================================");
    println!("Group signature sign (sender cost)");
    print_benchmark_statistics(&sign_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());
    println!("Group signature verify (platform cost)");
    print_benchmark_statistics(&verify_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());
    println!("Group signature check revocation token (additional platform cost)");
    print_benchmark_statistics(&verify_revocation_token_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());
    println!("Group signature open (recipient cost)");
    print_benchmark_statistics(&open_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());

    // Token minting benchmarks
    let mut sender_times = Vec::new();
    let mut platform_times = Vec::new();
    let mut recipient_times = Vec::new();

    for i in 0..NUM_TRIALS {
        let pp = TokenBLS::setup(&mut rng);
        let (rpk, rsk, rtoksk) = TokenBLS::keygen_rec(&pp, &mut rng);
        // Request token
        start = Instant::now();
        let x = Fr::rand(&mut rng);
        let (st, req) = TokenBLS::request_token_s1_user(&pp, &rpk, &x, &mut rng).unwrap();
        sender_times.push(start.elapsed().as_micros());
        // Mint blind token
        start = Instant::now();
        let (out, tokct) = TokenBLS::eval_blind_token_s2_plt(&pp, &rpk, &rtoksk, &req, &mut rng).unwrap();
        platform_times.push(start.elapsed().as_micros());
        // Verify token generation
        start = Instant::now();
        <TokenBLS as Gat<GGM<<Bls12_381 as PairingEngine>::G1Projective, Sha3_256>>>::Assoc::blind_mac_verify_output(&pp.mac_params(), &rpk.tokpk, &st, &out).unwrap();
        sender_times[i] += start.elapsed().as_micros();
        // Open token ciphertext
        start = Instant::now();
        tokct.ct2 - &tokct.ct1.mul(&rsk.z);
        recipient_times.push(start.elapsed().as_micros());
    }
    println!("===================================");
    println!("TOKEN MINTING MICROBENCHMARKS...");
    println!("===================================");
    println!("Token proposal and verification (sender cost)");
    print_benchmark_statistics(&sender_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());
    println!("Token minting (platform cost)");
    print_benchmark_statistics(&platform_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());
    println!("Token ciphertext open (recipient cost)");
    print_benchmark_statistics(&recipient_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());


    // Sending with token benchmarks
    sender_times = Vec::new();
    platform_times = Vec::new();

    for _ in 0..NUM_TRIALS {
        let pp = MACBLS::setup(&G1Projective::prime_subgroup_generator(), &mut rng);
        let (_pk, sk) = MACBLS::keygen(&pp, &mut rng);
        // Generate new token (sender cost)
        start = Instant::now();
        let x = Fr::rand(&mut rng);
        let t = MACBLS::scalar_mac(&pp, &sk, &x, &mut rng);
        sender_times.push(start.elapsed().as_micros());
        // Verify token (platform cost)
        start = Instant::now();
        MACBLS::verify_mac(&pp, &sk, &x, &t);
        platform_times.push(start.elapsed().as_micros());
    }
    println!("===================================");
    println!("SENDING WITH TOKEN MICROBENCHMARKS...");
    println!("===================================");
    println!("Token replenish (sender cost)");
    print_benchmark_statistics(&sender_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());
    println!("Token verify (platform cost)");
    print_benchmark_statistics(&platform_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());

    // Sealed sender
    sender_times = Vec::new();
    recipient_times = Vec::new();
    for _ in 0..NUM_TRIALS {
        let sk_s = Fr::rand(&mut rng);
        let pk_r = G1Projective::rand(&mut rng);
        // Sealed sender send
        start = Instant::now();
        let sk_e = Fr::rand(&mut rng);
        pk_r.mul(&sk_e);
        pk_r.mul(&sk_s);
        sender_times.push(start.elapsed().as_micros());
        // Sealed sender receive
        start = Instant::now();
        pk_r.mul(&sk_e);
        pk_r.mul(&sk_s);
        recipient_times.push(start.elapsed().as_micros());
    }
    println!("===================================");
    println!("SEALED SENDER MICROBENCHMARKS...");
    println!("===================================");
    println!("Encapsulate (sender cost)");
    print_benchmark_statistics(&sender_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());
    println!("Decapsulate (platform cost)");
    print_benchmark_statistics(&recipient_times.iter().map(|x| *x as f64).collect::<Vec<f64>>());

}


fn print_benchmark_statistics(times: &[f64]) {
    println!("   {} trials -- median: {}\tmean: {}\tmin: {}\tmax: {}\tstddev: {}",
    times.len(), times.median(), times.mean(), times.min(), times.max(), times.std_dev());
}

