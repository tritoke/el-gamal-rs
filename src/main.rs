#![feature(test)]
extern crate test;

#[allow(unused_imports)]

use num_bigint::{BigUint,BigInt,ToBigUint,ToBigInt,RandBigInt,Sign};
use num_traits::{Zero,One};

#[allow(unused_macros)]
macro_rules! uint {
    ($num:expr) => {
        $num.to_biguint().unwrap()
    };
}

#[allow(unused_macros)]
macro_rules! int {
    ($num:expr) => {
        $num.to_bigint().unwrap()
    };
}

const USE_FASTEXP: bool = true;
const PRINT_EGCD: bool = false;

fn main() {
    let pubkey = PubKey {
        p: uint!(13),
        g: uint!(2),
        y: uint!(6),
    };

    let privkey = PrivKey {
        x: uint!(5),
    };

    let message = EncMessage {
        a: uint!(11),
        b: uint!(5),
    };

    let decrypted = decrypt(&message, (&privkey, &pubkey));

    println!("{}", decrypted);
}

#[derive(Debug,Clone,Eq,PartialEq)]
struct PubKey {
    p: BigUint,
    g: BigUint,
    y: BigUint,
}

#[derive(Debug,Clone,Eq,PartialEq)]
struct PrivKey{
    x: BigUint,
}

#[derive(Debug,Clone,Eq,PartialEq)]
struct EncMessage {
    a: BigUint,
    b: BigUint,
}

fn encrypt(message: &BigUint, pubkey: &PubKey) -> EncMessage {
    let k = {
        let mut rng = rand::thread_rng();

        let max = pubkey.p.clone() - BigUint::one();
        loop {
            let k_proposed = rng.gen_biguint_below(&max);

            if gcd(k_proposed.clone(), max.clone()) == One::one() {
                break k_proposed
            }
        }
    };

    if USE_FASTEXP {
        EncMessage {
            a: fast_exponentiation(&pubkey.g, &k, &pubkey.p),
            b: message * fast_exponentiation(&pubkey.y, &k, &pubkey.p) % &pubkey.p,
        }
    } else {
        EncMessage {
            a: pubkey.g.modpow(&k, &pubkey.p),
            b: message * (pubkey.y.modpow(&k, &pubkey.p)) % &pubkey.p,
        }
    }
}

fn decrypt(enc_message: &EncMessage, key_pair: (&PrivKey, &PubKey)) -> BigUint {
    let EncMessage { a, b } = enc_message.clone();
    let PrivKey { x } = key_pair.0.clone();
    let PubKey { p, g, y } = key_pair.1.clone();


    let a_pow_x = if USE_FASTEXP {
        fast_exponentiation(&a, &x, &p)
    } else {
        a.modpow(&x, &p)
    };

    let inverse = mul_inverse_egcd(a_pow_x, p.clone());

    b * inverse % p
}

fn gen_keypair(g: BigUint, p: BigUint) -> (PrivKey, PubKey) {
    let mut rng = rand::thread_rng();

    let one = One::one();
    let x = rng.gen_biguint_range(&one, &p);

    let y = if USE_FASTEXP {
        fast_exponentiation(&g, &x, &p)
    } else {
        g.modpow(&x, &p)
    };

    (PrivKey { x }, PubKey { p, g, y })
}

fn mul_inverse_egcd(a: BigUint, b: BigUint) -> BigUint {
    let (aa, i, bb) = e_gcd(a.clone().to_bigint().unwrap(), b.clone().to_bigint().unwrap());

    if i.sign() == Sign::Minus {
        (i + b.to_bigint().unwrap()).to_biguint().unwrap() % b
    } else {
        i.to_biguint().unwrap() % b
    }
}

fn mul_inverse_fexp(a: BigUint, b: BigUint) -> BigUint {
    if USE_FASTEXP {
        fast_exponentiation(&a, &(b.clone() - uint!(2)), &b)
    } else {
        a.modpow(&(b.clone() - uint!(2)), &b)
    }
}

fn e_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b == BigInt::zero() {
        if PRINT_EGCD {
            println!("A\tB\tQ\tR\tD\tI\tJ");
            println!("{}\t{}\t\t\t{}\t{}\t{}", &a, &b, &a, BigInt::one(), BigInt::zero());
        }
        (a, BigInt::one(), BigInt::zero())
    } else {
        let q = &a % &b;
        let r = (&a - &q) / &b;

        let (d, i, j) = e_gcd(b.clone(), a.clone() % b.clone());

        if PRINT_EGCD {
            println!("{}\t{}\t{}\t{}\t{}\t{}\t{}", &a, &b, &q, &r, &d, &i, &j);
        }
        (d, j.clone(), i - j * r)
    }
}

fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
    let mut t: BigUint;

    while b != Zero::zero() {
        t = a % &b;
        a = std::mem::replace(&mut b, t);
    }

    a
}

fn fast_exponentiation(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut d = BigUint::one();

    for i in (0..exponent.bits()).rev() {
        d = d.pow(2) % modulus;

        if exponent.bit(i) {
            d = (d * base) % modulus;
        }
    }

    d
}

#[bench]
fn test_inv_egcd(bench: &mut test::Bencher) {
    let a = uint!(3);
    let b = uint!(7);

    bench.iter(|| mul_inverse_egcd(a.clone(), b.clone()));
}

#[bench]
fn test_inv_fexp(bench: &mut test::Bencher) {
    let a = uint!(3);
    let b = uint!(7);

    bench.iter(|| mul_inverse_fexp(a.clone(), b.clone()));
}

#[bench]
fn test_modpow_small(bench: &mut test::Bencher) {
    let b = uint!(7);
    let e = uint!(11);
    let m = uint!(10);

    bench.iter(|| b.modpow(&e, &m));
}

#[bench]
fn test_fastexp_small(bench: &mut test::Bencher) {
    let b = uint!(7);
    let e = uint!(11);
    let m = uint!(10);

    bench.iter(|| fast_exponentiation(&b, &e, &m));
}

#[bench]
fn test_modpow_medium(bench: &mut test::Bencher) {
    let b = uint!(114061);
    let e = uint!(390408);
    let m = uint!(596285319);

    bench.iter(|| b.modpow(&e, &m));
}

#[bench]
fn test_fastexp_medium(bench: &mut test::Bencher) {
    let b = uint!(114061);
    let e = uint!(390408);
    let m = uint!(596285317);

    bench.iter(|| fast_exponentiation(&b, &e, &m));
}

#[bench]
fn test_modpow_large(bench: &mut test::Bencher) {
    let b = BigUint::parse_bytes(b"76727818501", 10).unwrap();
    let e = BigUint::parse_bytes(b"106948672164858467323842478486344512140628822172463601347842324964936520145639901642821908261724504683618751363874949545139990110064417783767473869257871093303098840444322431427570430352264727924670616830528275979816029411238857420891573585682960002884504066641798943069373340119349252841947298920088426950893", 10).unwrap();
    let m = BigUint::parse_bytes(b"399045063227866996400389593645364265805011358667837421927058679531912011440909075280213147545679253677071931083545093451532450895335932585573143368671151298437438314862781621291946994983160410726615015361148214210477404879070051130885082501350241587055513711403918147906615053626709430302419062328556707332970670637699312092538518169052166475959099520659592169629425483668444672328079799649270633289851499805022378100769513405595839211151933534273490702038972519013616808605331455973977495450236149673197883501363649941883028595345848844196328437123731061733914601883934838860766218373017537982376145541650524575938509831694529079421156491064044377148695294662943300850976810272418739562495276160531541946543983453486130506098730295045887875546893013915109354757875239747354959814221983628288659215047109576406994918917089338761516292989104524827750614745880630652798337961090982765074485639712341998930956169425319855788655384081362454064316434775120652211254103065473770318024330056280436694610311012159877794980115317154533606630955244939299931716859635604898938612816247185355604803250100917636028851195335614988098706297207483188738636095155332666193621406587658375941966020516911900607102655252804739425021184596472342490056055", 10).unwrap();

    bench.iter(|| b.modpow(&e, &m));
}

#[bench]
fn test_fastexp_large(bench: &mut test::Bencher) {
    let b = BigUint::parse_bytes(b"76727818501", 10).unwrap();
    let e = BigUint::parse_bytes(b"106948672164858467323842478486344512140628822172463601347842324964936520145639901642821908261724504683618751363874949545139990110064417783767473869257871093303098840444322431427570430352264727924670616830528275979816029411238857420891573585682960002884504066641798943069373340119349252841947298920088426950893", 10).unwrap();
    let m = BigUint::parse_bytes(b"399045063227866996400389593645364265805011358667837421927058679531912011440909075280213147545679253677071931083545093451532450895335932585573143368671151298437438314862781621291946994983160410726615015361148214210477404879070051130885082501350241587055513711403918147906615053626709430302419062328556707332970670637699312092538518169052166475959099520659592169629425483668444672328079799649270633289851499805022378100769513405595839211151933534273490702038972519013616808605331455973977495450236149673197883501363649941883028595345848844196328437123731061733914601883934838860766218373017537982376145541650524575938509831694529079421156491064044377148695294662943300850976810272418739562495276160531541946543983453486130506098730295045887875546893013915109354757875239747354959814221983628288659215047109576406994918917089338761516292989104524827750614745880630652798337961090982765074485639712341998930956169425319855788655384081362454064316434775120652211254103065473770318024330056280436694610311012159877794980115317154533606630955244939299931716859635604898938612816247185355604803250100917636028851195335614988098706297207483188738636095155332666193621406587658375941966020516911900607102655252804739425021184596472342490056055", 10).unwrap();

    bench.iter(|| fast_exponentiation(&b, &e, &m));
}

#[bench]
fn test_gcd_small(bench: &mut test::Bencher) {
    let a = uint!(1071);
    let b = uint!(462);

    bench.iter(|| gcd(a.clone(), b.clone()));
}

#[bench]
fn test_gcd_medium(bench: &mut test::Bencher) {
    let a = BigUint::parse_bytes(b"1234567890123456789", 10).unwrap();
    let b = uint!(1420502457);

    bench.iter(|| gcd(a.clone(), b.clone()));
}

#[bench]
fn test_gcd_large(bench: &mut test::Bencher) {
    let a = BigUint::parse_bytes(b"63967963964995270387124440304488742834605391433909941415046917378743503974225", 10).unwrap();
    let b = BigUint::parse_bytes(b"7496360375963812137869", 10).unwrap();

    bench.iter(|| gcd(a.clone(), b.clone()));
}
