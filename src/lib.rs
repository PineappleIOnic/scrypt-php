use ext_php_rs::prelude::*;

/// Creates a scrypt password hash.
///
/// @param string password The clear text password
/// @param string salt     The salt to use, or null to generate a random one
/// @param u8     n        The CPU difficultly [default=15]
/// @param u32    r        The memory difficultly [default=8]
/// @param u32    p        The parallel difficultly [default=1]
/// @param u23    len      The length of the generated hash [default=8]
///
/// @return string The hashed password
#[php_function]
pub fn scrypt(
    password: &str,
    salt: &str,
    n: Option<u32>,
    r: Option<u32>,
    p: Option<u32>,
    len: Option<usize>,
) -> Result<String, String> {
    let password_bytes = password.as_bytes();

    let params = scrypt::Params::new(
        match n {
            Some(data) => fast_math::log2(data as f32) as u8,
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
        let hash = scrypt("hunter42", "test", None, None, None, None).unwrap();

        println!("{:?}", hash);

        // assert!(Scrypt.verify_password(b"hunter42", &parsed_hash).is_ok());
    }

    #[test]
    fn test_scrypt_with_salt() {
        let _hash = scrypt("hunter42", "salt", None, None, None, None).unwrap();

        // assert!(Scrypt.verify_password(b"hunter42", &parsed_hash).is_ok());
    }

    #[test]
    fn test_scrypt_with_custom_params() {
        let hash = scrypt("some-scrypt-password", "some-salt", Some(16384), Some(12), Some(2), Some(64)).unwrap();

        println!("{:?}", hash);

        // assert!(Scrypt.verify_password(b"hunter42", &parsed_hash).is_ok());
    }

    #[test]
    fn test_scrypt_with_invalid_params() {
        assert!(scrypt("hunter42", "test", Some(0), Some(0), Some(0), Some(0)).is_err());
    }
}