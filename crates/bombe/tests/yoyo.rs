//! The yoyo game: first the published AES results (Rønjom, Bardeh,
//! Helleseth, ASIACRYPT 2017), then what it finds on Turing.

use bombe::aes::{Aes, Shape};
use bombe::keyedsquare::plaintext_for;
use bombe::yoyo::{bytes, columns, diagonals, pair_game, single_game};
use bombe::{fast, rng::Rng};
use turing::structure::Layer;
use turing::{Block, Turing};

const TRIALS: usize = 200;

// Their Algorithm 3: 4 rounds (first round without ShiftRows, last without
// ShiftRows and MixColumns) are super-box, linear layer, super-box on
// columns, so the game keeps the columns where the plaintexts agree, every
// time.
#[test]
fn aes_4_rounds_always_return_the_pattern() {
    let aes = Aes::new(&Rng::new("yoyo aes 4").bytes());
    let g = pair_game(|p| aes.encrypt(p, 4, Shape::Yoyo), |c| aes.decrypt(c, 4, Shape::Yoyo), &columns(), &columns(), TRIALS, "aes 4");
    assert!(g.always(), "{} of {}", g.kept, g.trials);
}

// Their Algorithm 2: 3 rounds, one new ciphertext.
#[test]
fn aes_3_rounds_with_one_new_ciphertext() {
    let aes = Aes::new(&Rng::new("yoyo aes 3").bytes());
    let g = single_game(|p| aes.encrypt(p, 3, Shape::Yoyo), |c| aes.decrypt(c, 3, Shape::Yoyo), &columns(), &columns(), TRIALS, "aes 3");
    assert!(g.always(), "{} of {}", g.kept, g.trials);
    // The one-ciphertext trick is a 3-round property: on 4 rounds it fails.
    let g = single_game(|p| aes.encrypt(p, 4, Shape::Yoyo), |c| aes.decrypt(c, 4, Shape::Yoyo), &columns(), &columns(), TRIALS, "aes 3 on 4");
    assert_eq!(g.kept, 0);
}

// Five rounds are not of the form S ∘ L ∘ S: the plain game never returns
// the pattern (their 5-round distinguisher needs 2^25.8 texts and another
// test). A random pair keeps 3 zero columns with probability 2^-96.
#[test]
fn aes_5_rounds_do_not() {
    let aes = Aes::new(&Rng::new("yoyo aes 5").bytes());
    let g = pair_game(|p| aes.encrypt(p, 5, Shape::Yoyo), |c| aes.decrypt(c, 5, Shape::Yoyo), &columns(), &columns(), TRIALS, "aes 5");
    assert_eq!(g.kept, 0);
}

fn turing_game(t: &Turing, rounds: usize, plain: &bombe::yoyo::Words, cipher: &bombe::yoyo::Words) -> bombe::yoyo::Game {
    pair_game(
        |p| {
            let mut c = *p;
            t.encrypt_rounds(&mut c, rounds);
            c
        },
        |c| {
            let mut p = *c;
            t.decrypt_rounds(&mut p, rounds);
            p
        },
        plain,
        cipher,
        TRIALS,
        &format!("turing {rounds}"),
    )
}

// Rounds 1-2 are S ∘ MixState ∘ S on bytes; rounds 1-3 are S on bytes, a
// linear layer, then super-boxes on columns (round 2's MixColumns joins
// the S-box layers of rounds 2 and 3). Both fall to the game every time.
#[test]
fn turing_2_and_3_rounds_always_return_the_pattern() {
    let t = Turing::new(&Rng::new("yoyo turing").bytes());
    let g = turing_game(&t, 2, &bytes(), &bytes());
    assert!(g.always(), "2 rounds: {} of {}", g.kept, g.trials);
    let g = turing_game(&t, 3, &bytes(), &columns());
    assert!(g.always(), "3 rounds: {} of {}", g.kept, g.trials);
}

// Four rounds from round 1 put MixState on both sides of a super-box layer:
// no swap of ciphertext words, bytes or columns, returns the pattern.
#[test]
fn turing_4_rounds_do_not() {
    let t = Turing::new(&Rng::new("yoyo turing 4").bytes());
    for cipher in [bytes(), columns(), diagonals()] {
        assert_eq!(turing_game(&t, 4, &bytes(), &cipher).kept, 0);
    }
}

/// The game on rounds 2-5 as an attacker plays it with a guess of round key
/// 0: plaintexts built so that round 2's S-box input differs in chosen
/// diagonals (keyedsquare::plaintext_for), and returned plaintexts carried
/// back through round 1 with the same guess.
fn keyed_game(t: &Turing, rk0: &Block, rounds: usize) -> bombe::yoyo::Game {
    let rk0 = fast::to_u128(rk0);
    pair_game(
        |u| {
            let mut c = fast::to_block(plaintext_for(fast::to_u128(u), rk0));
            t.encrypt_rounds(&mut c, rounds);
            c
        },
        |c| {
            let mut p = *c;
            t.decrypt_rounds(&mut p, rounds);
            let x = fast::to_block(fast::to_u128(&p) ^ rk0);
            let mut s = x;
            turing::sbox::sub_bytes(&mut s);
            turing::linear::apply_layer(Layer::MixState, &s)
        },
        &diagonals(),
        &columns(),
        TRIALS,
        &format!("keyed yoyo {rounds}"),
    )
}

// Rounds 2-5 are super-box ∘ ShiftRows ∘ MixState ∘ super-box: with round
// key 0 right, the game on 5 rounds holds every time; with it one byte
// wrong, never. That is the test each of the 2^128 guesses faces.
#[test]
fn turing_5_rounds_fall_once_round_key_0_is_known() {
    let t = Turing::new(&Rng::new("yoyo turing keyed").bytes());
    let rk0 = *t.round_key(0);
    let g = keyed_game(&t, &rk0, 5);
    assert!(g.always(), "{} of {}", g.kept, g.trials);
    let mut wrong = rk0;
    wrong[7] ^= 1;
    assert_eq!(keyed_game(&t, &wrong, 5).kept, 0);
    // One round more is out of reach even with round key 0.
    assert_eq!(keyed_game(&t, &rk0, 6).kept, 0);
}
