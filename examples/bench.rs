extern crate agora_key_share_proofs;

use agora_key_share_proofs::{
    DecryptionKeys, EncryptionKeys, KZG10CommonReferenceParams, Signature, SigningKey,
    VerificationKey,
};
use blsful::inner_types::{Field, G2Projective, Scalar};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::{num::NonZeroUsize, time::Duration};

pub fn usage() {
    println!("Usage: cargo run --example [example name] -- [threshold] [num parties] [samples]");
}
pub fn parse_config(args: &[String]) -> Result<(usize, usize, usize), &'static str> {
    // default values
    let mut threshold: usize = 3;
    let mut num_parties = 5;
    let mut samples_num = 1000;
    if args.len() != 1 && args.len() != 4 {
        return Err("improper number of arguments");
    }
    if args.len() == 4 {
        let threshold_arg = &args[1];
        threshold = match threshold_arg.parse() {
            Ok(n) => n,
            Err(_) => {
                return Err("first argument must be an integer");
            }
        };
        let parties_arg = &args[2];
        num_parties = match parties_arg.parse() {
            Ok(n) => {
                if threshold > n {
                    return Err("threshold must be less than number of parties");
                } else {
                    n
                }
            }
            Err(_) => {
                return Err("second argument must be an integer");
            }
        };
        let samples = &args[3];
        samples_num = match samples.parse() {
            // options should be 5, 10
            Ok(n) => n,
            Err(_) => {
                return Err("third argument must be an integer");
            }
        };
    }

    Ok((threshold, num_parties, samples_num))
}

fn main() {
    use std::time::Instant;
    use std::{env, process};

    /***** Process command-line arguments *****/
    let args: Vec<String> = env::args().collect();
    let (threshold, num_parties, samples) = parse_config(&args).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        usage();
        process::exit(1);
    });

    /***** Open the benchmark file *****/
    use std::fs::OpenOptions;
    use std::io::prelude::*;

    // open file in write-only append mode, and create it if it doesn't exist
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("bench.txt")
        .unwrap_or_else(|err| {
            eprintln!("Problem opening benchmarking file: {err}");
            process::exit(1);
        });
    writeln!(
        file,
        "Throback benchmarks for (t,n) = ({}, {}) over {} iterations\n{}",
        threshold,
        num_parties,
        samples,
        "--------------------------------------------------------------"
    )
    .unwrap_or_else(|err| {
        eprintln!("Problem writing to benchmarking file: {err}");
        process::exit(1);
    });

    /***** Setup system parameters *****/
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    // let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(num_parties + 1).unwrap(), &mut rng);
    let crs =
        KZG10CommonReferenceParams::setup(NonZeroUsize::new(num_parties - 1).unwrap(), &mut rng);

    /***** Begin benchmarking *****/
    // ColdRegister
    println!("Registering {} cold parties", num_parties);
    let start = Instant::now();
    let dks_set = (0..num_parties)
        .map(|_| DecryptionKeys::random(&mut rng))
        .collect::<Vec<_>>();
    let eks_set = dks_set
        .iter()
        .map(|dk| EncryptionKeys::from(dk))
        .collect::<Vec<_>>();
    let cold_reg_time = start.elapsed();
    println!("done in {:?}", cold_reg_time);

    let cold_reg_avg = cold_reg_time / num_parties as u32;
    println!("average time per cold reg: {:?}", cold_reg_avg);
    writeln!(file, "cold reg:\t\t\t{:?}", cold_reg_avg).unwrap_or_else(|err| {
        eprintln!("Problem writing cold reg avg to file: {err}");
        process::exit(1);
    });
    println!();

    // ClientRegister
    println!("Registering {} new clients (new backups)", samples);
    let start = Instant::now();
    for _ in 0..samples {
        let sk = SigningKey(Scalar::random(&mut rng));
        let shares = sk.create_shares(threshold, num_parties, &mut rng).unwrap();
        let reconstructed = SigningKey::from_shares(&shares.0).unwrap();
        assert_eq!(sk, reconstructed);

        let payloads_res = sk.generate_register_payloads(threshold, &crs, &mut rng, &eks_set);
        assert!(payloads_res.is_ok());
    }
    let client_reg_time = start.elapsed();
    println!("done in {:?}", client_reg_time);
    let client_reg_avg = client_reg_time / samples as u32;
    println!("average time per client reg: {:?}", client_reg_avg);
    writeln!(file, "client reg:\t\t\t{:?}", client_reg_avg).unwrap_or_else(|err| {
        eprintln!("Problem writing client reg avg to file: {err}");
        process::exit(1);
    });
    println!();

    // generate vk, hot/cold shares to use for the next benchmarks
    let sk = SigningKey(Scalar::random(&mut rng));
    let vk = VerificationKey::from(&sk);
    let _ = sk.create_shares(threshold, num_parties, &mut rng).unwrap();
    let payloads_res = sk.generate_register_payloads(threshold, &crs, &mut rng, &eks_set);
    let payloads = payloads_res.unwrap();

    // TSign
    let message = b"dummy message";
    println!("Producing {} threshold signatures", num_parties);
    let start = Instant::now();

    let cold_sigs = dks_set
        .iter()
        .map(|dk| dk.sign(vk, message))
        .collect::<Vec<_>>();
    // let cold_sig_time = start.elapsed();
    // println!("done in {:?}", cold_sig_time);

    let hot_sigs = payloads
        .iter()
        .zip(eks_set.iter())
        .map(|(payload, eks)| eks.sign(payload.encrypted_share, message))
        .collect::<Vec<_>>();
    // let hot_sig_time = start.elapsed();
    // println!("done in {:?}", hot_sig_time);

    let tsigs = hot_sigs
        .iter()
        .zip(cold_sigs.iter())
        .map(|(hot, cold)| Signature(hot.0 - cold.0))
        .collect::<Vec<_>>();
    let tsig_time = start.elapsed();
    println!("done in {:?}", tsig_time);

    let tsig_avg = tsig_time / num_parties as u32;
    println!("average time per threshold sig: {:?}", tsig_avg);
    writeln!(file, "tsig:\t\t\t\t{:?}", tsig_avg).unwrap_or_else(|err| {
        eprintln!("Problem writing tsig avg to file: {err}");
        process::exit(1);
    });
    println!();

    // Share Refresh

    // Cold Proof
    println!("Creating and verifying {} cold proofs", num_parties);
    let mut cold_prove_time = Duration::new(0, 0);
    let mut cold_vrfy_time = Duration::new(0, 0);
    for (dks, eks) in dks_set.iter().zip(eks_set.iter()).collect::<Vec<_>>() {
        let start = Instant::now();
        let cold_proof = dks.prove(0);
        cold_prove_time += start.elapsed();
        let start = Instant::now();
        let _ = cold_proof.verify(eks);
        cold_vrfy_time += start.elapsed();
    }
    println!("done");
    let cold_prove_avg = cold_prove_time / num_parties as u32;
    println!("average time per cold prove: {:?}", cold_prove_avg);
    writeln!(file, "cold prove:\t\t\t{:?}", cold_prove_avg).unwrap_or_else(|err| {
        eprintln!("Problem writing cold prove avg to file: {err}");
        process::exit(1);
    });
    let cold_vrfy_avg = cold_vrfy_time / num_parties as u32;
    println!("average time per cold vrfy: {:?}", cold_vrfy_avg);
    writeln!(file, "cold vrfy:\t\t\t{:?}", cold_vrfy_avg).unwrap_or_else(|err| {
        eprintln!("Problem writing cold vrfy avg to file: {err}");
        process::exit(1);
    });
    println!();

    // Hot Proof
    println!("Creating and verifying {} hot proofs", num_parties);
    let mut hot_prove_time = Duration::new(0, 0);
    let mut hot_vrfy_time = Duration::new(0, 0);
    for (payload, eks) in payloads.iter().zip(eks_set.iter()) {
        let start = Instant::now();
        let hot_proof = eks.prove(&crs, payload.encrypted_share, payload.commitment, 0);
        hot_prove_time += start.elapsed();
        let start = Instant::now();
        let _ = hot_proof.verify(&crs, 0);
        hot_vrfy_time += start.elapsed();
    }
    println!("done");
    let hot_prove_avg = hot_prove_time / num_parties as u32;
    println!("average time per hot prove: {:?}", hot_prove_avg);
    writeln!(file, "hot prove:\t\t\t{:?}", hot_prove_avg).unwrap_or_else(|err| {
        eprintln!("Problem writing hot prove avg to file: {err}");
        process::exit(1);
    });
    let hot_vrfy_avg = hot_vrfy_time / num_parties as u32;
    println!("average time per hot vrfy: {:?}", hot_vrfy_avg);
    writeln!(file, "hot vrfy:\t\t\t{:?}", hot_vrfy_avg).unwrap_or_else(|err| {
        eprintln!("Problem writing hot vrfy avg to file: {err}");
        process::exit(1);
    });
    println!();
}
