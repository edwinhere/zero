extern crate curve25519_dalek;
extern crate rand_core;
extern crate sha2;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};

fn main() {
    basic();
    schnorr();
    schnorr_leak_private_key();
    schnorr_forge();
    fiat_shamir_schnorr();
    alternative_schnorr();
    eddsa();
    prove_knowledge_of_discreet_logarithm_in_multiple_bases();
    multiple_private_keys_in_one_proof();
    sag();
    blsag();
    mlsag();
    clsag();
    one_time_addresses();
    println!("Hello!");
}

fn basic() {
    let one: Scalar = Scalar::one();
    let one_point: RistrettoPoint = one * constants::RISTRETTO_BASEPOINT_POINT;
    let two: Scalar = Scalar::one() + Scalar::one();
    let two_point: RistrettoPoint = two * constants::RISTRETTO_BASEPOINT_POINT;
    assert_eq!(one + one, two);
    assert_eq!(one_point + one_point, two_point);
}

fn schnorr() {
    let mut csprng = OsRng;

    //Prover has a private key
    let k: Scalar = Scalar::random(&mut csprng);

    //Prover shares his public key with the world
    let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

    // Prover generates a random a
    let a: Scalar = Scalar::random(&mut csprng);

    // Prover sends random point corresponding to a to verifier
    let a_point: RistrettoPoint = a * constants::RISTRETTO_BASEPOINT_POINT;

    //Verifier sends random challenge to prover
    let c: Scalar = Scalar::random(&mut csprng);

    //Prover obfuscates his private key using a and c and sends it to verifier
    let r: Scalar = a + (c * k);

    //Verifier checks that prover knows the private key without knowing the private key
    //Verifier finds point corresponding to r
    let r_point: RistrettoPoint = r * constants::RISTRETTO_BASEPOINT_POINT;
    //Verifier finds this point (a + (c * k)) * base_point without knowing k i.e. like this a * base_point + c * k_point
    let r_point_another_way: RistrettoPoint = a_point + (c * k_point);
    // If these different ways of calculating r_point lead to the same point then the verifier can
    // be sure prover knows his private key
    assert_eq!(r_point, r_point_another_way);
}

// If prover reuses a, his private key is leaked
fn schnorr_leak_private_key() {
    let mut csprng = OsRng;

    //Prover has a private key
    let k: Scalar = Scalar::random(&mut csprng);

    //Prover shares his public key with the world
    let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

    // Prover generates a random a
    let a: Scalar = Scalar::random(&mut csprng);

    // Prover sends random point corresponding to a to verifier
    let a_point: RistrettoPoint = a * constants::RISTRETTO_BASEPOINT_POINT;

    //Verifier sends random challenge to prover
    let c: Scalar = Scalar::random(&mut csprng);

    //Prover obfuscates his private key using a and c and sends it to verifier
    let r: Scalar = a + (c * k);

    //Verifier checks that prover knows the private key without knowing the private key
    //Verifier finds point corresponding to r
    let r_point: RistrettoPoint = r * constants::RISTRETTO_BASEPOINT_POINT;
    //Verifier finds this point (a + (c * k)) * base_point without knowing k i.e. like this a * base_point + c * k_point
    let r_point_another_way: RistrettoPoint = a_point + (c * k_point);
    // If these different ways of calculating r_point lead to the same point then the verifier can
    // be sure prover knows his private key
    assert_eq!(r_point, r_point_another_way);

    //Verifier sends another random challenge to prover
    let another_c: Scalar = Scalar::random(&mut csprng);

    //Prover obfuscates his private key reusing same a and another_c and sends it to verifier
    let another_r: Scalar = a + (another_c * k);

    //Verifier can now reverse engineer the private key of the prover
    let leaked_k = (r - another_r) * (c - another_c).invert();
    assert_eq!(k, leaked_k);
}

// If prover knows the challenge before hand he can fake knowledge of private key
fn schnorr_forge() {
    let mut csprng = OsRng;

    //Someone shared their public key with the world
    let k_point: RistrettoPoint =
        Scalar::random(&mut csprng) * constants::RISTRETTO_BASEPOINT_POINT;

    //Prover and verifier knows the challenge before hand. May be the prover stole it. May be the
    //hash function or RNG used to generate the challenge is not random enough.
    let c: Scalar = Scalar::random(&mut csprng);

    //Prover generates a fake response without knowing the private key
    let r: Scalar = Scalar::random(&mut csprng);

    //Prover sends the point, which ought to have been random, to the verifier based on the fake
    //response the prover generated without knowing the private key
    let a_point = (r * constants::RISTRETTO_BASEPOINT_POINT) - (c * k_point);

    //Verifier sends the challenge to the prover not knowing they already know it
    //Prover sends the point corresponding to the fake response they generated above without knowing the private key
    let r_point: RistrettoPoint = r * constants::RISTRETTO_BASEPOINT_POINT;
    //Verifier finds this point (a + (c * k)) * base_point without knowing k i.e. like this a * base_point + c * k_point
    let r_point_another_way: RistrettoPoint = a_point + (c * k_point);
    // If these different ways of calculating r_point lead to the same point then the verifier can
    // be sure prover knows his private key. But of course in this case verifier is wrong. The
    // prover impersonated the public key owner without knowing the private key
    assert_eq!(r_point, r_point_another_way);
}

fn fiat_shamir_schnorr() {
    let mut csprng = OsRng;

    //Prover has a private key
    let k: Scalar = Scalar::random(&mut csprng);

    //Prover shares his public key with the world
    let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

    //Prover generates a random a
    let a: Scalar = Scalar::random(&mut csprng);

    //Prover calculates random point corresponding to a and sends it to the verifier
    let a_point: RistrettoPoint = a * constants::RISTRETTO_BASEPOINT_POINT;

    //Prover creates a provably new challenge for himself by hashing a_point
    let c: Scalar = Scalar::hash_from_bytes::<Sha512>(a_point.compress().as_bytes());

    //Prover obfuscates his private key using a and c and sends it to verifier with the challenge
    let r: Scalar = a + (c * k);

    //Verifier checks that prover knows the private key without knowing the private key
    //Verifier finds point corresponding to r
    let r_point: RistrettoPoint = r * constants::RISTRETTO_BASEPOINT_POINT;
    //Verifier finds this point (a + (c * k)) * base_point without knowing k i.e. like this a * base_point + c * k_point
    let r_point_another_way: RistrettoPoint = a_point + (c * k_point);
    // If these different ways of calculating r_point lead to the same point then the verifier can
    // be sure prover knows his private key
    assert_eq!(r_point, r_point_another_way);
}

fn alternative_schnorr() {
    let mut csprng = OsRng;

    //Prover has a private key
    let k: Scalar = Scalar::random(&mut csprng);

    //Prover shares his public key with the world
    let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

    //Prover generates a random a
    let a: Scalar = Scalar::random(&mut csprng);

    //Prover calculates random point corresponding to a
    let a_point: RistrettoPoint = a * constants::RISTRETTO_BASEPOINT_POINT;

    //Prover creates a provably new challenge for himself by hashing the message and the a_point
    let h = Sha512::new()
        .chain("This is the message the prover wants to sign")
        .chain(a_point.compress().as_bytes());

    let c: Scalar = Scalar::from_hash(h);

    //Prover obfuscates his private key using a and c and sends it to verifier with the challenge
    let r: Scalar = a - (c * k);

    //Verifier checks that prover knows the private key without knowing the private key
    let reconstructed_c: Scalar = Scalar::from_hash(
        Sha512::new()
            .chain("This is the message the prover wants to sign")
            .chain(
                ((r * constants::RISTRETTO_BASEPOINT_POINT) + (c * k_point))
                    .compress()
                    .as_bytes(),
            ),
    );
    // If reconstructed challenge same as the shared challenge then the verifier can
    // be sure prover knows his private key
    assert_eq!(c, reconstructed_c);
}

fn eddsa() {
    let mut csprng = OsRng;

    //Prover has a private key
    let k: Scalar = Scalar::random(&mut csprng);

    //Prover shares his public key with the world
    let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

    //Prover generates a random a without using random number generator
    let a: Scalar = Scalar::from_hash(
        Sha512::new()
            .chain(k.as_bytes())
            .chain("This is the message the prover wants to sign"),
    );

    //Prover calculates random point corresponding to a and sends it to the verifier
    let a_point: RistrettoPoint = a * constants::RISTRETTO_BASEPOINT_POINT;

    let c: Scalar = Scalar::from_hash(
        Sha512::new()
            .chain(a_point.compress().as_bytes())
            .chain(k_point.compress().as_bytes())
            .chain("This is the message the prover wants to sign"),
    );

    //Prover obfuscates his private key using a and c and sends it to verifier
    let r: Scalar = a + (c * k);

    //Verifier checks that prover knows the private key without knowing the private key
    //Verifier finds point corresponding to r
    let r_point: RistrettoPoint = r * constants::RISTRETTO_BASEPOINT_POINT;
    //Verifier finds this point (a + (c * k)) * base_point without knowing k i.e. like this a * base_point + c * k_point
    let r_point_another_way: RistrettoPoint = a_point + (c * k_point);
    // If these different ways of calculating r_point lead to the same point then the verifier can
    // be sure prover knows his private key
    assert_eq!(r_point, r_point_another_way);
}

fn prove_knowledge_of_discreet_logarithm_in_multiple_bases() {
    let mut csprng = OsRng;

    //Prover has a private key
    let k: Scalar = Scalar::random(&mut csprng);

    let base_points: &Vec<RistrettoPoint> = &(0..32)
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();

    let public_keys: &Vec<RistrettoPoint> =
        &base_points.into_iter().map(|j_point| k * j_point).collect();

    let a: Scalar = Scalar::random(&mut csprng);

    let a_points: &Vec<RistrettoPoint> =
        &base_points.into_iter().map(|j_point| a * j_point).collect();

    let mut hash = Sha512::new();

    for j_point in base_points {
        hash.input(j_point.compress().as_bytes());
    }

    for k_point in public_keys {
        hash.input(k_point.compress().as_bytes());
    }

    for a_point in a_points {
        hash.input(a_point.compress().as_bytes());
    }

    let c: Scalar = Scalar::from_hash(hash);
    let r: Scalar = a - (c * k);

    //Verifier has a public key
    let mut verifiers_hash = Sha512::new();

    for j_point in base_points {
        verifiers_hash.input(j_point.compress().as_bytes());
    }

    for k_point in public_keys {
        verifiers_hash.input(k_point.compress().as_bytes());
    }

    for (i, j_point) in base_points.into_iter().enumerate() {
        let point: RistrettoPoint = (r * j_point) + (c * public_keys[i]);
        verifiers_hash.input(point.compress().as_bytes());
    }

    let c_another_way: Scalar = Scalar::from_hash(verifiers_hash);

    assert_eq!(c, c_another_way);
}

fn multiple_private_keys_in_one_proof() {
    let mut csprng = OsRng;

    //Prover has many private keys
    let ks: &Vec<Scalar> = &(0..32).map(|_| Scalar::random(&mut csprng)).collect();

    let base_points: &Vec<RistrettoPoint> = &(0..32)
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();

    let public_keys: &Vec<RistrettoPoint> = &base_points
        .into_iter()
        .enumerate()
        .map(|(i, j_point)| ks[i] * j_point)
        .collect();

    let _as: &Vec<Scalar> = &(0..32).map(|_| Scalar::random(&mut csprng)).collect();

    let a_points: &Vec<RistrettoPoint> = &base_points
        .into_iter()
        .enumerate()
        .map(|(i, j_point)| _as[i] * j_point)
        .collect();

    let mut hash = Sha512::new();

    for j_point in base_points {
        hash.input(j_point.compress().as_bytes());
    }

    for k_point in public_keys {
        hash.input(k_point.compress().as_bytes());
    }

    for a_point in a_points {
        hash.input(a_point.compress().as_bytes());
    }

    let c: Scalar = Scalar::from_hash(hash);
    let rs: &Vec<Scalar> = &ks
        .into_iter()
        .enumerate()
        .map(|(i, k)| _as[i] - (c * k))
        .collect();

    // Verification
    let mut verifiers_hash = Sha512::new();

    for j_point in base_points {
        verifiers_hash.input(j_point.compress().as_bytes());
    }

    for k_point in public_keys {
        verifiers_hash.input(k_point.compress().as_bytes());
    }

    for (i, j_point) in base_points.into_iter().enumerate() {
        let point: RistrettoPoint = (rs[i] * j_point) + (c * public_keys[i]);
        verifiers_hash.input(point.compress().as_bytes());
    }

    let c_another_way: Scalar = Scalar::from_hash(verifiers_hash);

    assert_eq!(c, c_another_way);
}

// non-linkable, spontaneous, anonymous, group signatures
fn sag() {
    let mut csprng = OsRng;

    // Provers private key
    let k: Scalar = Scalar::random(&mut csprng);

    // Provers public key
    let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

    // Ring size (at least 4 but maximum 32)
    let n = (OsRng.next_u32() % 29 + 4) as usize;

    // Simulate randomly chosen Public keys (Prover will insert her public key here later)
    let mut public_keys: Vec<RistrettoPoint> =
        (0..(n - 1)) // Prover is going to add our key into this mix
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();

    // This is the index where we hide our key
    let secret_index = (OsRng.next_u32() % n as u32) as usize;

    public_keys.insert(secret_index, k_point);

    let a: Scalar = Scalar::random(&mut csprng);

    let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();

    let mut cs: Vec<Scalar> = (0..n).map(|_| Scalar::zero()).collect();

    // Hash of ring and message is shared by all challenges H_n(R, m, ....)
    let mut group_and_message_hash = Sha512::new();

    for k_point in &public_keys {
        group_and_message_hash.input(k_point.compress().as_bytes());
    }

    group_and_message_hash.input("This is the message the prover wants to sign");

    let mut hashes: Vec<Sha512> = (0..n).map(|_| group_and_message_hash.clone()).collect();

    hashes[(secret_index + 1) % n].input(
        (a * constants::RISTRETTO_BASEPOINT_POINT)
            .compress()
            .as_bytes(),
    );
    cs[(secret_index + 1) % n] = Scalar::from_hash(hashes[(secret_index + 1) % n].clone());

    let mut i = (secret_index + 1) % n;

    loop {
        hashes[(i + 1) % n].input(
            ((rs[i % n] * constants::RISTRETTO_BASEPOINT_POINT) + (cs[i % n] * public_keys[i % n]))
                .compress()
                .as_bytes(),
        );
        cs[(i + 1) % n] = Scalar::from_hash(hashes[(i + 1) % n].clone());

        if secret_index >= 1 && i % n == (secret_index - 1) % n {
            break;
        } else if secret_index == 0 && i % n == n - 1 {
            break;
        } else {
            i = (i + 1) % n;
        }
    }

    rs[secret_index] = a - (cs[secret_index] * k);

    //Verification

    let mut reconstructed_c: Scalar = cs[0];
    for j in 0..n {
        let mut h: Sha512 = group_and_message_hash.clone();
        h.input(
            ((rs[j] * constants::RISTRETTO_BASEPOINT_POINT) + (reconstructed_c * public_keys[j]))
                .compress()
                .as_bytes(),
        );
        reconstructed_c = Scalar::from_hash(h);
    }

    assert_eq!(cs[0], reconstructed_c);
}

fn blsag() {
    let mut csprng = OsRng;

    // Provers private key
    let k: Scalar = Scalar::random(&mut csprng);

    // Provers public key
    let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

    let key_image: RistrettoPoint =
        k * RistrettoPoint::from_hash(Sha512::new().chain(k_point.compress().as_bytes()));

    // Ring size (at least 4 but maximum 32)
    let n = (OsRng.next_u32() % 29 + 4) as usize;

    // Simulate randomly chosen Public keys (Prover will insert her public key here later)
    let mut public_keys: Vec<RistrettoPoint> =
        (0..(n - 1)) // Prover is going to add her key into this mix
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();

    // This is the index where the prover hides key
    let secret_index = (OsRng.next_u32() % n as u32) as usize;

    public_keys.insert(secret_index, k_point);

    let a: Scalar = Scalar::random(&mut csprng);

    let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();

    let mut cs: Vec<Scalar> = (0..n).map(|_| Scalar::zero()).collect();

    // Hash of message is shared by all challenges H_n(m, ....)
    let mut message_hash = Sha512::new();

    message_hash.input("This is the message the prover wants to sign");

    let mut hashes: Vec<Sha512> = (0..n).map(|_| message_hash.clone()).collect();

    hashes[(secret_index + 1) % n].input(
        (a * constants::RISTRETTO_BASEPOINT_POINT)
            .compress()
            .as_bytes(),
    );
    hashes[(secret_index + 1) % n].input(
        (a * RistrettoPoint::from_hash(Sha512::new().chain(k_point.compress().as_bytes())))
            .compress()
            .as_bytes(),
    );
    cs[(secret_index + 1) % n] = Scalar::from_hash(hashes[(secret_index + 1) % n].clone());

    let mut i = (secret_index + 1) % n;

    loop {
        hashes[(i + 1) % n].input(
            ((rs[i % n] * constants::RISTRETTO_BASEPOINT_POINT) + (cs[i % n] * public_keys[i % n]))
                .compress()
                .as_bytes(),
        );
        hashes[(i + 1) % n].input(
            ((rs[i % n]
                * RistrettoPoint::from_hash(
                    Sha512::new().chain(public_keys[i % n].compress().as_bytes()),
                ))
                + (cs[i % n] * key_image))
                .compress()
                .as_bytes(),
        );
        cs[(i + 1) % n] = Scalar::from_hash(hashes[(i + 1) % n].clone());

        if secret_index >= 1 && i % n == (secret_index - 1) % n {
            break;
        } else if secret_index == 0 && i % n == n - 1 {
            break;
        } else {
            i = (i + 1) % n;
        }
    }

    rs[secret_index] = a - (cs[secret_index] * k);

    //Verification

    let mut reconstructed_c: Scalar = cs[0];
    for j in 0..n {
        let mut h: Sha512 = message_hash.clone();
        h.input(
            ((rs[j] * constants::RISTRETTO_BASEPOINT_POINT) + (reconstructed_c * public_keys[j]))
                .compress()
                .as_bytes(),
        );

        h.input(
            (rs[j]
                * RistrettoPoint::from_hash(
                    Sha512::new().chain(public_keys[j].compress().as_bytes()),
                )
                + (reconstructed_c * key_image))
                .compress()
                .as_bytes(),
        );
        reconstructed_c = Scalar::from_hash(h);
    }

    assert_eq!(cs[0], reconstructed_c);
}

// Multilayer Linkable Spontaneous Anonymous Group (MLSAG) signatures
fn mlsag() {
    let mut csprng = OsRng;

    // Row count of matrix (minimum 4 maximum 32)
    let nr = (OsRng.next_u32() % 29 + 4) as usize;
    // Column count of matrix (minimum 4 maximum 32)
    let nc = (OsRng.next_u32() % 29 + 4) as usize;

    //Provers private keys
    let ks: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();

    //Provers public keys
    let k_points: Vec<RistrettoPoint> = ks
        .iter()
        .map(|k| k * constants::RISTRETTO_BASEPOINT_POINT)
        .collect();

    let key_images: Vec<RistrettoPoint> = (0..nc)
        .map(|j| {
            ks[j]
                * RistrettoPoint::from_hash(Sha512::new().chain(k_points[j].compress().as_bytes()))
        })
        .collect();

    // Simulate randomly chosen Public keys (Prover will insert her public keys here later)
    let mut public_keys: Vec<Vec<RistrettoPoint>> = (0..(nr - 1)) // Prover is going to add her key into this mix
        .map(|_| {
            (0..nc)
                .map(|_| RistrettoPoint::random(&mut csprng))
                .collect()
        })
        .collect();

    // This is the index where we hide our keys
    let secret_index = (OsRng.next_u32() % nr as u32) as usize;

    public_keys.insert(secret_index, k_points.clone());

    let a: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();

    let mut rs: Vec<Vec<Scalar>> = (0..nr)
        .map(|_| (0..nc).map(|_| Scalar::random(&mut csprng)).collect())
        .collect();

    let mut cs: Vec<Scalar> = (0..nr).map(|_| Scalar::zero()).collect();

    // Hash of message is shared by all challenges H_n(m, ....)
    let mut message_hash = Sha512::new();

    message_hash.input("This is the message the prover wants to sign");

    let mut hashes: Vec<Sha512> = (0..nr).map(|_| message_hash.clone()).collect();

    for j in 0..nc {
        hashes[(secret_index + 1) % nr].input(
            (a[j] * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        hashes[(secret_index + 1) % nr].input(
            (a[j]
                * RistrettoPoint::from_hash(
                    Sha512::new().chain(k_points[j].compress().as_bytes()),
                ))
            .compress()
            .as_bytes(),
        );
    }
    cs[(secret_index + 1) % nr] = Scalar::from_hash(hashes[(secret_index + 1) % nr].clone());

    let mut i = (secret_index + 1) % nr;

    loop {
        for j in 0..nc {
            hashes[(i + 1) % nr].input(
                ((rs[i % nr][j] * constants::RISTRETTO_BASEPOINT_POINT)
                    + (cs[i % nr] * public_keys[i % nr][j]))
                    .compress()
                    .as_bytes(),
            );
            hashes[(i + 1) % nr].input(
                ((rs[i % nr][j]
                    * RistrettoPoint::from_hash(
                        Sha512::new().chain(public_keys[i % nr][j].compress().as_bytes()),
                    ))
                    + (cs[i % nr] * key_images[j]))
                    .compress()
                    .as_bytes(),
            );
        }
        cs[(i + 1) % nr] = Scalar::from_hash(hashes[(i + 1) % nr].clone());

        if secret_index >= 1 && i % nr == (secret_index - 1) % nr {
            break;
        } else if secret_index == 0 && i % nr == nr - 1 {
            break;
        } else {
            i = (i + 1) % nr;
        }
    }

    for j in 0..nc {
        rs[secret_index][j] = a[j] - (cs[secret_index] * ks[j]);
    }

    //Verification
    let mut reconstructed_c: Scalar = cs[0];
    for _i in 0..nr {
        let mut h: Sha512 = message_hash.clone();

        for j in 0..nc {
            h.input(
                ((rs[_i][j] * constants::RISTRETTO_BASEPOINT_POINT)
                    + (reconstructed_c * public_keys[_i][j]))
                    .compress()
                    .as_bytes(),
            );

            h.input(
                (rs[_i][j]
                    * RistrettoPoint::from_hash(
                        Sha512::new().chain(public_keys[_i][j].compress().as_bytes()),
                    )
                    + (reconstructed_c * key_images[j]))
                    .compress()
                    .as_bytes(),
            );
        }
        reconstructed_c = Scalar::from_hash(h);
    }

    assert_eq!(cs[0], reconstructed_c);
}

// Concise Linkable Spontaneous Anonymous Group (CLSAG) signatures
fn clsag() {
    let mut csprng = OsRng;

    // Row count of matrix (minimum 4 maximum 32)
    let nr = (OsRng.next_u32() % 29 + 4) as usize;
    // Column count of matrix (minimum 4 maximum 32)
    let nc = (OsRng.next_u32() % 29 + 4) as usize;

    //Provers private keys
    let ks: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();

    //Provers public keys
    let k_points: Vec<RistrettoPoint> = ks
        .iter()
        .map(|k| k * constants::RISTRETTO_BASEPOINT_POINT)
        .collect();

    // This is the base key
    // i.e. the first public key for which the prover has the private key
    let base_key_hashed_to_point: RistrettoPoint =
        RistrettoPoint::from_hash(Sha512::new().chain(k_points[0].compress().as_bytes()));

    let key_images: Vec<RistrettoPoint> = ks.iter().map(|k| k * base_key_hashed_to_point).collect();

    // Simulate randomly chosen Public keys (Prover will insert her public keys here later)
    let mut public_keys: Vec<Vec<RistrettoPoint>> = (0..(nr - 1)) // Prover is going to add her key into this mix
        .map(|_| {
            (0..nc)
                .map(|_| RistrettoPoint::random(&mut csprng))
                .collect()
        })
        .collect();

    // This is the index where we hide our keys
    let secret_index = (OsRng.next_u32() % nr as u32) as usize;

    public_keys.insert(secret_index, k_points.clone());

    let a: Scalar = Scalar::random(&mut csprng);

    let mut rs: Vec<Scalar> = (0..nr).map(|_| Scalar::random(&mut csprng)).collect();

    let mut cs: Vec<Scalar> = (0..nr).map(|_| Scalar::zero()).collect();

    // Domain separated hashes as required by CSLAG paper
    // The hash functions have a label, and the ring members fed into it
    let prefixed_hashes: Vec<Sha512> = (0..nc)
        .map(|index| {
            let mut h: Sha512 = Sha512::new();
            h.input(format!("CSLAG_{}", index));
            for i in 0..nr {
                for j in 0..nc {
                    h.input(public_keys[i][j].compress().as_bytes());
                }
            }
            return h;
        })
        .collect();

    // These prefixed hash functions have a label,
    // and the ring members, and key images fed into it
    let prefixed_hashes_with_key_images: Vec<Sha512> = (0..nc)
        .map(|index| {
            let mut h: Sha512 = prefixed_hashes[index].clone();
            for j in 0..nc {
                h.input(key_images[j].compress().as_bytes());
            }
            return h;
        })
        .collect();

    let aggregate_private_key: Scalar = (0..nc)
        .map(|j| {
            let h: Sha512 = prefixed_hashes_with_key_images[j].clone();
            return Scalar::from_hash(h) * ks[j];
        })
        .sum();

    let aggregate_public_keys: Vec<RistrettoPoint> = (0..nr)
        .map(|i| {
            return (0..nc)
                .map(|j| {
                    let h: Sha512 = prefixed_hashes_with_key_images[j].clone();
                    return Scalar::from_hash(h.clone()) * public_keys[i][j];
                })
                .sum();
        })
        .collect();

    let aggregate_key_image: RistrettoPoint = (0..nc)
        .map(|j| {
            let h: Sha512 = prefixed_hashes_with_key_images[j].clone();
            return Scalar::from_hash(h.clone()) * key_images[j];
        })
        .sum();

    let mut hashes: Vec<Sha512> = (0..nr)
        .map(|_| {
            let mut h: Sha512 = Sha512::new();
            h.input(format!("CSLAG_c"));
            for i in 0..nr {
                for j in 0..nc {
                    h.input(public_keys[i][j].compress().as_bytes());
                }
            }
            h.input("This is the message the prover wants to sign");
            return h;
        })
        .collect();

    hashes[(secret_index + 1) % nr].input(
        (a * constants::RISTRETTO_BASEPOINT_POINT)
            .compress()
            .as_bytes(),
    );
    hashes[(secret_index + 1) % nr].input((a * base_key_hashed_to_point).compress().as_bytes());
    cs[(secret_index + 1) % nr] = Scalar::from_hash(hashes[(secret_index + 1) % nr].clone());

    let mut i = (secret_index + 1) % nr;

    loop {
        hashes[(i + 1) % nr].input(
            ((rs[i % nr] * constants::RISTRETTO_BASEPOINT_POINT)
                + (cs[i % nr] * aggregate_public_keys[i % nr]))
                .compress()
                .as_bytes(),
        );
        hashes[(i + 1) % nr].input(
            ((rs[i % nr]
                * RistrettoPoint::from_hash(
                    Sha512::new().chain(public_keys[i % nr][0].compress().as_bytes()),
                ))
                + (cs[i % nr] * aggregate_key_image))
                .compress()
                .as_bytes(),
        );
        cs[(i + 1) % nr] = Scalar::from_hash(hashes[(i + 1) % nr].clone());

        if secret_index >= 1 && i % nr == (secret_index - 1) % nr {
            break;
        } else if secret_index == 0 && i % nr == nr - 1 {
            break;
        } else {
            i = (i + 1) % nr;
        }
    }

    rs[secret_index] = a - (cs[secret_index] * aggregate_private_key);

    //Verification
    let mut reconstructed_c: Scalar = cs[0];
    for _i in 0..nr {
        let mut h: Sha512 = Sha512::new();
        h.input(format!("CSLAG_c"));
        for i in 0..nr {
            for j in 0..nc {
                h.input(public_keys[i][j].compress().as_bytes());
            }
        }
        h.input("This is the message the prover wants to sign");
        h.input(
            ((rs[_i] * constants::RISTRETTO_BASEPOINT_POINT)
                + (reconstructed_c * aggregate_public_keys[_i]))
                .compress()
                .as_bytes(),
        );

        h.input(
            (rs[_i]
                * RistrettoPoint::from_hash(
                    Sha512::new().chain(public_keys[_i][0].compress().as_bytes()),
                )
                + (reconstructed_c * aggregate_key_image))
                .compress()
                .as_bytes(),
        );
        reconstructed_c = Scalar::from_hash(h);
    }

    assert_eq!(cs[0], reconstructed_c);
}

fn one_time_addresses() {
    let mut csprng = OsRng;

    // Bob's Private keys
    let view: Scalar = Scalar::random(&mut csprng);
    let spend: Scalar = Scalar::random(&mut csprng);

    // Bob's Public keys
    let view_pub: RistrettoPoint = view * constants::RISTRETTO_BASEPOINT_POINT;
    let spend_pub: RistrettoPoint = spend * constants::RISTRETTO_BASEPOINT_POINT;

    let r: Scalar = Scalar::random(&mut csprng);
    let r_point: RistrettoPoint = r * constants::RISTRETTO_BASEPOINT_POINT;

    // Alice uses this one time address to send money to Bob
    let one_time_address: RistrettoPoint =
        (Scalar::from_hash(Sha512::new().chain((r * view_pub).compress().as_bytes()))
            * constants::RISTRETTO_BASEPOINT_POINT)
            + spend_pub;

    // Bob reconstructs the spend public key to be sure this address belongs to him
    let reconstructed_spend_pub: RistrettoPoint = one_time_address
        - (Scalar::from_hash(Sha512::new().chain((view * r_point).compress().as_bytes()))
            * constants::RISTRETTO_BASEPOINT_POINT);

    assert_eq!(spend_pub, reconstructed_spend_pub);

    // Bob signs with this private key to prove ownership of the one-time-address.
    let one_time_private_key =
        Scalar::from_hash(Sha512::new().chain((view * r_point).compress().as_bytes())) + spend;

    assert_eq!(
        one_time_private_key * constants::RISTRETTO_BASEPOINT_POINT,
        one_time_address
    );

    // Multi-output transactions
    let many_one_time_addresses: Vec<(Scalar, RistrettoPoint)> = (0..10) // Output indices
        .map(|t| {
            let pk: RistrettoPoint = (Scalar::from_hash(
                Sha512::new()
                    .chain((r * view_pub).compress().as_bytes())
                    .chain((t as u64).to_be_bytes()),
            ) * constants::RISTRETTO_BASEPOINT_POINT)
                + spend_pub;
            let sk: Scalar = Scalar::from_hash(
                Sha512::new()
                    .chain((view * r_point).compress().as_bytes())
                    .chain((t as u64).to_be_bytes()),
            ) + spend;

            return (sk, pk);
        })
        .collect();

    for (t, (_, pk)) in many_one_time_addresses.iter().enumerate() {
        let reconstructed: RistrettoPoint = pk
            - (Scalar::from_hash(
                Sha512::new()
                    .chain((view * r_point).compress().as_bytes())
                    .chain((t as u64).to_be_bytes()),
            ) * constants::RISTRETTO_BASEPOINT_POINT);
        assert_eq!(spend_pub, reconstructed);
    }
}
