fn main() {
    let buf: Vec<u8> = b"Hello World!".to_vec();
    let mut shielded = shielded::Shielded::new(buf);

    {
        let unshielded = shielded.unshield();
        let hello = std::str::from_utf8(unshielded.as_ref()).unwrap();
        println!("{}", hello);
    }

    println!("poof");
}
