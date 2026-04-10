use dddatasync::fizzbuzz;

#[test]
fn test_fizzbuzz_3() {
    assert_eq!(fizzbuzz(3), "fizz");
}

#[test]
fn test_fizzbuzz_15() {
    assert_eq!(fizzbuzz(15), "fizzbuzz");
}
