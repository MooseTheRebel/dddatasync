use dddatasync::greet;

#[test]
fn test_hello_world() {
    assert_eq!(greet(None), "hello world");
}

#[test]
fn test_hello_with_name() {
    assert_eq!(greet(Some("Alice")), "hello Alice");
}
