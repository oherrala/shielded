use shielded::Shielded;
use quickcheck::quickcheck;

#[test]
fn test_shielded_unshield() {
    let buf = vec![0xAA; 5 * 1789 /* Yep, strange numbers */];

    let original = buf.clone();
    let mut shielded = Shielded::new(buf);

    let unshielded = shielded.unshield();
    assert_eq!(original, unshielded.as_ref());
}

quickcheck! {
    fn prop_shield_unshield(xs: Vec<u8>) -> bool {
        let original = xs.clone();
        let mut shielded = Shielded::new(xs);
        let unshielded = shielded.unshield();
        original == unshielded.as_ref()
    }
}
