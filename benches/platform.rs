#![feature(test)]
extern crate test;

use orca::{
    algmac::GGM,
    groupsig::{GroupSig, RevocationToken},
    token::{RecPubKey, RecTokenSecretKey, TokenBL},
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
    bytes::{ToBytes, FromBytes}, to_bytes,
};
use rand::{
    SeedableRng,
    rngs::StdRng,
};
use sha3::Sha3_256;
use redis::Commands;
use r2d2::Pool;
use rayon::prelude::*;
use std::{
    default::Default,
    time::Instant,
};
use num_cpus;

const BLACKLIST_SIZE: usize = 100;
const STRIKELIST_SIZE: usize = 1000;
const NUM_INITIAL_TOKENS: usize = 10;

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    assert!(args.pop().unwrap() == "--bench");
    let (num_threads, num_requests): (usize, usize) = if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        println!("Usage: ``cargo bench --bench platform -- <num_threads> <num_requests>``");
        return
    } else {
        (
            String::from(args[1].clone()).parse().expect("<num_threads> should be integer"),
            String::from(args[2].clone()).parse().expect("<num_requests> should be integer"),
        )
    };
    println!("Setting up platform benchmark with {} requests over {} threads...", num_requests, num_threads);
    rayon::ThreadPoolBuilder::new().num_threads(num_threads).build_global().unwrap();
    println!("Physical CPUs: {}, Virtual CPUs: {}", num_cpus::get_physical(), num_cpus::get());

    let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
    let pool = r2d2::Pool::builder()
        .max_size(100)
        .build(client)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    type TokenBLS = TokenBL<Bls12_381, Sha3_256>;
    type MACBLS = GGM<G1Projective, Sha3_256>;

    // Setup benchmarks
    let mut mint_requests = Vec::new();
    let mut send_requests = Vec::new();
    let pp = GroupSigBLS::setup(&mut rng);
    let mac_pp = pp.mac_params();
    let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
    for i in 0..num_requests {
        let mut conn = pool.clone().get().unwrap();
        let (rpk, rsk, toksk) = TokenBLS::keygen_rec(&pp, &mut rng);
        let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
        let (t, proof, upk) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
        let usk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();

        // Store recipient keys (Redis key 4i and 4i+1)
        conn.set::<usize, Vec<u8>, ()>(4*i, to_bytes![&rpk].unwrap()).unwrap();
        conn.set::<usize, Vec<u8>, ()>(4*i + 1, to_bytes![&toksk].unwrap()).unwrap();

        // Create blacklist for user (Redis key 4i+2)
        let mut revocation_tokens = Vec::new();
        for _ in 0..BLACKLIST_SIZE {
            revocation_tokens.push(to_bytes![<Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng)].unwrap());
        }
        conn.sadd::<usize, Vec<Vec<u8>>, ()>(4*i + 2, revocation_tokens).unwrap();

        // Create token strikelist for user (Redis key 4i+3)
        let mut used_tokens = Vec::new();
        for _ in 0..STRIKELIST_SIZE {
            used_tokens.push(to_bytes![<Bls12_381 as PairingEngine>::Fr::rand(&mut rng)].unwrap());
        }
        conn.sadd::<usize, Vec<Vec<u8>>, ()>(4*i + 3, used_tokens).unwrap();

        // Create mint request
        let mut token_requests = Vec::new();
        for _ in 0..NUM_INITIAL_TOKENS {
            let x = Fr::rand(&mut rng);
            let (_, req) = TokenBLS::request_token_s1_user(&pp, &rpk, &x, &mut rng).unwrap();
            token_requests.push(req);
        }
        let sig = GroupSigBLS::sign(&pp, &gmpk, &rpk.oapk, &usk, &to_bytes![&token_requests].unwrap(), &mut rng).unwrap();
        mint_requests.push((token_requests, sig));

        // Create send request
        let x = Fr::rand(&mut rng);
        let t = MACBLS::scalar_mac(&mac_pp, &toksk, &x, &mut rng);
        send_requests.push((x, t));
    }

    // Platform minting benchmark
    println!("Running platform minting benchmark...");
    let mint_start = Instant::now();
    mint_requests.par_iter()
        .enumerate()
        .for_each(|(i, (token_requests, sig))| {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let mut conn = pool.clone().get().unwrap();
            let rpk = RecPubKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4*i).unwrap()[..]).unwrap();
            let rtoksk = RecTokenSecretKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4*i + 1).unwrap()[..]).unwrap();
            let revocation_tokens = conn.smembers::<usize, Vec<Vec<u8>>>(4*i + 2).unwrap().iter()
                .map(|token_in_bytes| {
                    let tok = <Bls12_381 as PairingEngine>::G1Projective::read(&token_in_bytes[..]).unwrap();
                    RevocationToken { tok }
                })
                .collect::<Vec<RevocationToken<Bls12_381>>>();
            assert!(GroupSigBLS::verify(&pp, &gmsk, &rpk.oapk, &revocation_tokens, &to_bytes![&token_requests].unwrap(), &sig).unwrap());
            let minted_tokens = token_requests.iter()
                .map(|tok_req| TokenBLS::eval_blind_token_s2_plt(&pp, &rpk, &rtoksk, tok_req, &mut rng).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(minted_tokens.len(), NUM_INITIAL_TOKENS);
        });
    let mint_time = mint_start.elapsed().as_secs();
    println!("{} s", mint_time);


    // Platform forwarding benchmark
    println!("Running platform sending benchmark...");
    let send_start = Instant::now();
    send_requests.par_iter()
        .enumerate()
        .for_each(|(i, (x, t))| {
            let mut conn = pool.clone().get().unwrap();
            let rtoksk = RecTokenSecretKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4*i + 1).unwrap()[..]).unwrap();
            let token_to_bytes = to_bytes![&x].unwrap();
            assert!(!conn.sismember::<usize, Vec<u8>, bool>(4*i + 3, token_to_bytes.clone()).unwrap());
            conn.sadd::<usize, Vec<u8>, ()>(4*i + 3, token_to_bytes).unwrap();
            assert!(MACBLS::verify_mac(&mac_pp, &rtoksk, &x, &t));
        });
    let send_time = send_start.elapsed().as_millis();
    println!("{} ms", send_time);


    let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
    let mut conn = client.get_connection().unwrap();
    let _: () = redis::cmd("FLUSHDB").query(&mut conn).unwrap();

}
