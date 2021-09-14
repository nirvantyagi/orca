#![feature(test)]
extern crate test;

use orca::{
    algmac::{GGM, Mac},
    groupsig::{GroupSig, RevocationToken, Signature},
    token::{RecPubKey, RecTokenSecretKey, TokenBL, TokenRequest},
};

use algebra::{
    curves::{
        bls12_381::{Bls12_381, G1Projective},
        PairingEngine,
    },
    fields::bls12_381::Fr,
    UniformRand,
    bytes::{ToBytes, FromBytes}, to_bytes,
};
use rand::{SeedableRng, rngs::StdRng, Rng};
use sha3::Sha3_256;
use redis::Commands;
use rayon::prelude::*;
use std::{
    time::Instant,
};
use num_cpus;
use r2d2;

//const BLACKLIST_SIZE: usize = 100;
//const STRIKELIST_SIZE: usize = 1000;
const NUM_INITIAL_TOKENS: usize = 10;
/*
Benchmark 1 million users and 10 million requests
Blacklist size of 100
Strikelist size of 100*14 = 1400 (100 messages/day over 2 weeks)
 */

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.last().unwrap() == "--bench" {
        args.pop();
    }
    let (num_cores, num_requests, blacklist_size, strikelist_size, num_users): (usize, usize, usize, usize, usize) = if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        println!("Usage: ``cargo bench --bench platform -- <num_cores> <num_requests> <size_blacklist> <size_strikelist> <num_users>``");
        return
    } else {
        (
            String::from(args[1].clone()).parse().expect("<num_cores> should be integer"),
            String::from(args[2].clone()).parse().expect("<num_requests> should be integer"),
            String::from(args[3].clone()).parse().expect("<size_blacklist> should be integer"),
            String::from(args[4].clone()).parse().expect("<size_strikelist> should be integer"),
            String::from(args[5].clone()).parse().expect("<num_users> should be integer"),
        )
    };
    println!("Physical CPUs: {}, Virtual CPUs: {}", num_cpus::get_physical(), num_cpus::get());
    println!("Setting up platform benchmark with {} requests over all {} cores...", num_requests, num_cpus::get_physical());
    let setup_pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get_physical()).build().unwrap();

    let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
    let pool = r2d2::Pool::builder()
        .max_size(num_cpus::get_physical() as u32)
        .build(client)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(0u64);
    type GroupSigBLS = GroupSig<Bls12_381, Sha3_256>;
    type TokenBLS = TokenBL<Bls12_381, Sha3_256>;
    type MACBLS = GGM<G1Projective, Sha3_256>;

    // Setup benchmarks
    let setup_start = Instant::now();
    let pp = GroupSigBLS::setup(&mut rng);
    let mac_pp = pp.mac_params();
    let (gmpk, gmsk) = GroupSigBLS::keygen_gm(&pp, &mut rng);
    println!("Creating users...");
    setup_pool.install(|| {
        (0..num_users).into_par_iter()
            .for_each(|i| {
                let mut rng = StdRng::seed_from_u64(i as u64);
                let mut conn = pool.clone().get().unwrap();
                let (rpk, _rsk, toksk) = TokenBLS::keygen_rec(&pp, &mut rng);

                // Store recipient keys (Redis key 4i and 4i+1)
                conn.set::<usize, Vec<u8>, ()>(4 * i, to_bytes![&rpk].unwrap()).unwrap();
                conn.set::<usize, Vec<u8>, ()>(4 * i + 1, to_bytes![&toksk].unwrap()).unwrap();

                // Create blacklist for user (Redis key 4i+2)
                let mut revocation_tokens = Vec::new();
                for _ in 0..blacklist_size {
                    revocation_tokens.push(to_bytes![<Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng)].unwrap());
                }
                conn.sadd::<usize, Vec<Vec<u8>>, ()>(4 * i + 2, revocation_tokens).unwrap();

                // Create token strikelist for user (Redis key 4i+3)
                let mut used_tokens = Vec::new();
                for _ in 0..strikelist_size {
                    used_tokens.push(to_bytes![<Bls12_381 as PairingEngine>::Fr::rand(&mut rng)].unwrap());
                }
                conn.sadd::<usize, Vec<Vec<u8>>, ()>(4 * i + 3, used_tokens).unwrap();
            });
    });
    println!("Creating requests...");
    let mut mint_requests: Vec<(usize, Vec<TokenRequest<Bls12_381, Sha3_256>>, Signature<Bls12_381, Sha3_256>)> = vec![];
    let mut send_requests: Vec<(usize, <Bls12_381 as PairingEngine>::Fr, Mac<<Bls12_381 as PairingEngine>::G1Projective>)> = vec![];
    setup_pool.install(|| {
        let requests = (0..num_requests).into_par_iter()
            .map(|i| {
                let mut rng = StdRng::seed_from_u64((num_users + i) as u64);
                let mut conn = pool.clone().get().unwrap();
                let (pk_s1, sk_s1) = GroupSigBLS::issue_s1_user(&pp, &mut rng);
                let (t, proof, _upk) = GroupSigBLS::issue_s2_gm(&pp, &gmsk, &pk_s1, &mut rng).unwrap();
                let usk = GroupSigBLS::issue_s3_user(&pp, &gmpk, &sk_s1, &t, &proof).unwrap();

                let j = rng.gen_range(0, num_users);
                let rpk = RecPubKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4 * j).unwrap()[..]).unwrap();
                let toksk = RecTokenSecretKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4 * j + 1).unwrap()[..]).unwrap();

                // Create mint request
                let mut token_requests = Vec::new();
                for _ in 0..NUM_INITIAL_TOKENS {
                    let x = Fr::rand(&mut rng);
                    let (_, req) = TokenBLS::request_token_s1_user(&pp, &rpk, &x, &mut rng).unwrap();
                    token_requests.push(req);
                }
                let sig = GroupSigBLS::sign(&pp, &gmpk, &rpk.oapk, &usk, &to_bytes![&token_requests].unwrap(), &mut rng).unwrap();
                let mint_request = (j, token_requests, sig);

                // Create send request
                let x = Fr::rand(&mut rng);
                let t = MACBLS::scalar_mac(&mac_pp, &toksk, &x, &mut rng);
                let send_request = (j, x, t);

                (mint_request, send_request)
            }).unzip::<_, _, Vec<(usize, Vec<TokenRequest<Bls12_381, Sha3_256>>, Signature<Bls12_381, Sha3_256>)>, Vec<(usize, <Bls12_381 as PairingEngine>::Fr, Mac<<Bls12_381 as PairingEngine>::G1Projective>)>>();
        mint_requests = requests.0;
        send_requests = requests.1;
    });
    let setup_time = setup_start.elapsed().as_secs();
    println!("{} s", setup_time);

    // Set cores to benchmark
    println!("Switching to {} cores for benchmark.", num_cores);
    std::mem::drop(setup_pool);
    let benchmark_pool = rayon::ThreadPoolBuilder::new().num_threads(num_cores).build().unwrap();

    // Platform minting benchmark
    println!("Running platform minting benchmark...");
    let mint_start = Instant::now();
    benchmark_pool.install(|| {
        mint_requests.par_iter()
            .for_each(|(i, token_requests, sig)| {
                let mut rng = StdRng::seed_from_u64((num_requests + i) as u64);
                let mut conn = pool.clone().get().unwrap();
                let rpk = RecPubKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4 * i).unwrap()[..]).unwrap();
                let rtoksk = RecTokenSecretKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4 * i + 1).unwrap()[..]).unwrap();
                let revocation_tokens = conn.smembers::<usize, Vec<Vec<u8>>>(4 * i + 2).unwrap().iter()
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
    });
    let mint_time = mint_start.elapsed().as_secs();
    println!("{} s", mint_time);


    // Platform forwarding benchmark
    println!("Running platform sending benchmark...");
    let send_start = Instant::now();
    benchmark_pool.install(|| {
        send_requests.par_iter()
            .for_each(|(i, x, t)| {
                let mut conn = pool.clone().get().unwrap();
                let rtoksk = RecTokenSecretKey::<Bls12_381>::read(&conn.get::<usize, Vec<u8>>(4 * i + 1).unwrap()[..]).unwrap();
                let token_to_bytes = to_bytes![&x].unwrap();
                assert!(!conn.sismember::<usize, Vec<u8>, bool>(4 * i + 3, token_to_bytes.clone()).unwrap());
                conn.sadd::<usize, Vec<u8>, ()>(4 * i + 3, token_to_bytes).unwrap();
                assert!(MACBLS::verify_mac(&mac_pp, &rtoksk, &x, &t));
            });
    });
    let send_time = send_start.elapsed().as_millis();
    println!("{} ms", send_time);


    let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
    let mut conn = client.get_connection().unwrap();
    let _: () = redis::cmd("FLUSHDB").query(&mut conn).unwrap();

}
