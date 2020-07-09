use quickcheck::quickcheck;
use shielded::Shielded;

#[test]
fn test_shielded_unshield() {
    let buf = vec![0xAA; 5 * 1789 /* Yep, strange numbers */];

    let original = buf.clone();
    let mut shielded = Shielded::new(buf);

    let unshielded = shielded.unshield();
    assert_eq!(original, unshielded.as_ref());
}

#[test]
fn test_from_vec() {
    let buf = b"hello world".to_vec();

    let original = buf.clone();
    let mut shielded = Shielded::from(buf);

    let unshielded = shielded.unshield();
    assert_eq!(original, unshielded.as_ref());
}

#[test]
fn test_unshielded_as_mut() {
    let buf: Vec<u8> = b"hello".to_vec();
    let mut shielded = Shielded::from(buf);

    {
        let mut unshielded = shielded.unshield();
        let buf: &mut [u8] = unshielded.as_mut();
        buf[0] = b'b';
    }

    let unshielded = shielded.unshield();
    assert_eq!(b"bello", unshielded.as_ref());
}

quickcheck! {
    fn prop_shield_unshield(xs: Vec<u8>) -> bool {
        let original = xs.clone();
        let mut shielded = Shielded::new(xs);
        let unshielded = shielded.unshield();
        original == unshielded.as_ref()
    }

    fn prop_shield_unshield_shield_unshield(xs: Vec<u8>) -> bool {
        let original = xs.clone();
        let mut shielded = Shielded::new(xs);

        {
            let unshielded = shielded.unshield();
            assert_eq!(original, unshielded.as_ref());
        }

        let unshielded = shielded.unshield();
        original == unshielded.as_ref()
    }
}
