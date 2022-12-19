use std::error::Error;

#[derive(Debug)]
pub enum JarmError {
    DnsResolve(DetailedError),
    Connection(DetailedError),
    Io(DetailedError),
}


#[derive(Debug, Default)]
pub struct DetailedError {
    pub underlying_error: Option<Box<dyn Error>>,
}

impl From<std::io::Error> for JarmError {
    fn from(error: std::io::Error) -> Self {
        JarmError::Io(
            DetailedError { underlying_error: Some(Box::from(error)) }
        )
    }
}


impl From<Box<dyn Error>> for DetailedError {
    fn from(error: Box<dyn Error>) -> Self {
        DetailedError { underlying_error: Some(error) }
    }
}
