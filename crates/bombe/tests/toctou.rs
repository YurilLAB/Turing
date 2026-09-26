//! Time of check to time of use, and concurrent use (toctou.rs).

use bombe::toctou;

#[test]
fn a_key_flip_between_check_and_use_is_caught_and_the_control_shows_why() {
    let (caught, released, trials) = toctou::plain_flip_in_window(200, "toctou test");
    assert_eq!(caught, trials, "every flip caught by the second check");
    assert_eq!(released, trials, "control: decrypt-and-compare alone releases every one");
}

#[test]
fn a_share_flip_between_check_and_use_is_caught() {
    let (caught, trials) = toctou::masked_flip_in_window(40, "toctou masked test");
    assert_eq!(caught, trials);
}

#[test]
fn one_cipher_shared_by_eight_threads_gives_the_single_threaded_results() {
    let (bad, total) = toctou::shared_across_threads(8, 2000, "toctou threads test");
    assert_eq!((bad, total), (0, 16000));
}

#[test]
#[cfg(unix)]
fn a_fork_child_draws_its_own_masks() {
    assert_eq!(toctou::fork_draws_fresh_masks(), Some(true));
}
