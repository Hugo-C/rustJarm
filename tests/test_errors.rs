#[cfg(test)]
mod tests {
    use std::fs;
    use rust_jarm::error::JarmError;

    #[test]
    fn test_io_error_to_jarm_error() {
        let base_error = fs::read_to_string("/non_existing_path").err().unwrap();
        let error = JarmError::from(base_error);
        assert_eq!(
            format!("{error:?}"),
            r###"Io(DetailedError { underlying_error: Some(Os { code: 2, kind: NotFound, message: "No such file or directory" }) })"###
        );
        let underlying_error = match error {
            JarmError::Io(detailed_error) => detailed_error.underlying_error.unwrap(),
            _ => panic!("Should be IO")
        };
        let expected_error = "No such file or directory (os error 2)";
        assert_eq!(underlying_error.to_string(), expected_error);
    }
}