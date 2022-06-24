use ext_php_rs::binary::Binary;
use ext_php_rs::prelude::*;

/// Creates a scrypt password hash.
///
/// @param string password The clear text password
/// @param string salt     The salt to use for the hash
/// @param u8     n        The CPU difficulty [default=32768]
/// @param u32    r        The memory difficulty [default=8]
/// @param u32    p        The parallel difficulty [default=1]
/// @param u23    len      The length of the generated hash [default=8]
///
/// @return string The hashed password
#[php_function]
pub fn scrypt(
    password: &str,
    salt: Binary<u8>,
    n: Option<u32>,
    r: Option<u32>,
    p: Option<u32>,
    len: Option<usize>,
) -> Result<String, String> {
    let password_bytes = password.as_bytes();

    let params = scrypt::Params::new(
        match n {
            Some(data) => fast_math::log2(data as f32) as u8,
            None => 15, // 32768
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

    let len = match len {
        Some(data) => data,
        None => 8,
    };

    let mut password_hash: Vec<u8> = vec![0; len];

    match scrypt::scrypt(password_bytes, &salt, &params, &mut password_hash) {
        Ok(_) => (),
        Err(e) => return Err(format!("{}", e)),
    }

    return Ok(hex::encode(password_hash));
}

// Required to register the extension with PHP.
#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
