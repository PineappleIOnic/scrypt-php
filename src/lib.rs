use ext_php_rs::prelude::*;
use scrypt::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, Salt, SaltString,
    },
    Scrypt,
};

/// Creates a scrypt password hash.
///
/// @param string password The clear text password
/// @param string salt     The salt to use, or null to generate a random one
/// @param u8     log_n    The CPU difficultly (must be a power of 2, > 1) [default=15]
/// @param u32    r        The memory difficultly [default=8]
/// @param u32    p        The parallel difficultly [default=1]
/// @param u23    len      The length of the generated hash [default=8]
///
/// @return string The hashed password
#[php_function]
pub fn scrypt(
    password: &str,
    salt: Option<&str>,
    log_n: Option<u8>,
    r: Option<u32>,
    p: Option<u32>,
    len: Option<usize>,
) -> Result<String, String> {
    let salt = match salt {
        Some(salt) => SaltString::b64_encode(salt.as_bytes()).map_err(|e| format!("{}", e))?,
        None => SaltString::generate(&mut OsRng),
    };

    let password_bytes = password.as_bytes();

    let params = scrypt::Params::new(
        match log_n {
            Some(data) => data,
            None => 15,
        },
        match r {
            Some(data) => data,
            None => 8,
        },
        match p {
            Some(data) => data,
            None => 1,
        },

    )
    .map_err(|e| format!("{}", e))?;

    let mut password_hash: Vec<u8> = vec![0; match len { Some(data) => data, None => 8 }];

    match scrypt::scrypt(
        password_bytes,
        salt.as_bytes(),
        &params,
        &mut password_hash,
    ) {
        Ok(_) => (),
        Err(e) => return Err(format!("{}", e)),
    }

    // let parsed_hash = match PasswordHash::new(&password_hash) {
    //     Ok(data) => data,
    //     Err(err) => {
    //         return Err(err.to_string());
    //     }
    // };
    // assert!(Scrypt.verify_password(password_bytes, &parsed_hash).is_ok());

    return Ok(hex::encode(password_hash));
}

// Required to register the extension with PHP.
#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrypt_without_salt() {
        let hash = scrypt("hunter42", None, None, None, None, None).unwrap();

        // let parsed_hash = PasswordHash::new(&hash).unwrap();

        println!("{:?}", hash);

        // assert!(Scrypt.verify_password(b"hunter42", &parsed_hash).is_ok());
    }

    #[test]
    fn test_scrypt_with_salt() {
        let hash = scrypt("hunter42", Some("salt"), None, None, None, None).unwrap();

        let parsed_hash = PasswordHash::new(&hash).unwrap();

        assert!(Scrypt.verify_password(b"hunter42", &parsed_hash).is_ok());
    }

    #[test]
    fn test_scrypt_with_custom_params() {
        let hash = scrypt("some-scrypt-password", None, Some(2), Some(16), Some(1), Some(64)).unwrap();

        println!("{:?}", hash);

        let parsed_hash = PasswordHash::new(&hash).unwrap();

        assert!(Scrypt.verify_password(b"hunter42", &parsed_hash).is_ok());
    }

    #[test]
    fn test_scrypt_with_invalid_params() {
        assert!(scrypt("hunter42", None, Some(0), Some(0), Some(0), Some(0)).is_err());
    }
}