use std::ffi::{self, CString};
use std::ops::Drop;

use s2n::*;
pub use s2n::s2n_status_request_type as StatusRequestType;
pub use s2n::s2n_tls_extension_type as TLSExtensionType;
pub use s2n::s2n_cert_auth_type as CertAuthType;

pub struct Config {
    pub(crate) s2n_config: *mut s2n_config,
}

#[derive(Debug, Fail)]
pub enum ConfigError {
    #[fail(display = "FFI Error: {}", _0)]
    FFIError(#[cause]
             ffi::NulError),
    #[fail(display = "Invalid cipher version: {}", _0)]
    CipherPreferencesError(String),
    #[fail(display = "Invalid Certificate chain or Private key")]
    CertChainKeyError,
    #[fail(display = "Invalid Diffe-Hellman parameters")]
    DHParamsError,
    #[fail(display = "Invalid Protocol Preferences")]
    ProtocolPreferencesError,
    #[fail(display = "Invalid Status Request Type")]
    StatusRequestTypeError,
    #[fail(display = "Invalid Extension Data")]
    ExtensionDataError,
    #[fail(display = "Error setting Certificate Authentication type")]
    CertAuthTypeError,
}
use self::ConfigError::*;

type ConfigResult = Result<(), ConfigError>;

impl Default for Config {
    fn default() -> Self {
        super::init();
        let s2n_config = unsafe { s2n_config_new() };
        Self { s2n_config }
    }
}

impl Config {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_cipher_preferences(&mut self, version: &str) -> ConfigResult {
        // These must be on seperate lines to ensure the lifetime of the string is longer than the FFI call
        let version_c = CString::new(version).map_err(FFIError)?;
        let version_ptr = version_c.as_ptr();

        let ret = unsafe { s2n_config_set_cipher_preferences(self.s2n_config, version_ptr) };
        match ret {
            0 => Ok(()),
            -1 => Err(CipherPreferencesError(version.to_owned())),
            _ => unreachable!(),
        }
    }

    pub fn add_cert_chain_and_key(&mut self,
                                  cert_chain_pem: &str,
                                  private_key_pem: &str)
                                  -> ConfigResult {
        // These must be on seperate lines to ensure the lifetime of the string is longer than the FFI call
        let cert_chain_pem_c = CString::new(cert_chain_pem).map_err(FFIError)?;
        let cert_chain_pem_ptr = cert_chain_pem_c.as_ptr();
        let private_key_pem_c = CString::new(private_key_pem).map_err(FFIError)?;
        let private_key_pem_ptr = private_key_pem_c.as_ptr();

        let ret = unsafe {
            s2n_config_add_cert_chain_and_key(self.s2n_config,
                                              cert_chain_pem_ptr,
                                              private_key_pem_ptr)
        };
        match ret {
            0 => Ok(()),
            -1 => Err(CertChainKeyError),
            _ => unreachable!(),
        }
    }

    pub fn add_dhparams(&mut self, dhparams_pem: &str) -> ConfigResult {
        // These must be on seperate lines to ensure the lifetime of the string is longer than the FFI call
        let dhparams_pem_c = CString::new(dhparams_pem).map_err(FFIError)?;
        let dhparams_pem_ptr = dhparams_pem_c.as_ptr();
        let ret = unsafe { s2n_config_add_dhparams(self.s2n_config, dhparams_pem_ptr) };

        match ret {
            0 => Ok(()),
            -1 => Err(DHParamsError),
            _ => unreachable!(),
        }
    }

    pub fn set_protocol_preferences(&mut self, protocols: &[&str]) -> ConfigResult {
        // This vec will hold the pointers to the strings
        let mut protocols_ptrs = vec![];
        // This Vec exists to hold the CStrings lifetimes open past the iteration and through the c
        // function call
        let mut cstring_lifetime = vec![];

        for &s in protocols {
            let cstring = CString::new(s).unwrap();
            let cstring_ptr = cstring.as_ptr();
            cstring_lifetime.push(cstring); // Ensure cstring's lifetime lasts long enough

            protocols_ptrs.push(cstring_ptr as *const _ as *const ::std::os::raw::c_void);
        }

        let protocols_ptrs_ptr = protocols_ptrs.as_ptr() as *const *const ::std::os::raw::c_char;
        let protocols_ptrs_len = protocols_ptrs.len() as ::std::os::raw::c_int;

        let ret = unsafe {
            s2n_config_set_protocol_preferences(self.s2n_config,
                                                protocols_ptrs_ptr,
                                                protocols_ptrs_len)
        };

        match ret {
            0 => Ok(()),
            -1 => Err(ProtocolPreferencesError),
            _ => unreachable!(),
        }
    }

    pub fn set_status_request_type(&mut self, request_type: StatusRequestType) -> ConfigResult {
        let ret = unsafe { s2n_config_set_status_request_type(self.s2n_config, request_type) };

        match ret {
            0 => Ok(()),
            -1 => Err(StatusRequestTypeError),
            _ => unreachable!(),
        }
    }

    #[allow(dead_code, unused_variables, unreachable_code)]
    pub fn set_extension_data(&mut self,
                              extension_type: TLSExtensionType,
                              data: &[u8])
                              -> ConfigResult {
        unimplemented!();
        // Segfault
        let data_ptr = data.as_ptr();
        let ret = unsafe {
            s2n_config_set_extension_data(self.s2n_config,
                                          extension_type,
                                          data_ptr,
                                          data.len() as u32)
        };
        match ret {
            0 => Ok(()),
            -1 => Err(ExtensionDataError),
            _ => unreachable!(),
        }
    }

    // pub fn set_nanoseconds_since_epoch_callback<'d, F, D>(&self,
    //                                                                  callback: Option<&'d F>,
    //                                                                  data: &'d D)
    //                                                                  -> ConfigResult {
    //     unsafe extern "C" fn c_callback(data_ptr: *mut ::std::os::raw::c_void,
    //                                     seconds: *mut u64)
    //                                     -> ::std::os::raw::c_int {
    //         let data = data_ptr as D;
    //         *seconds = callback.map(|f| f(data, seconds as u64));

    //         0
    //     }

    //     let data_ptr = &mut data as *mut _ as *mut ::std::os::raw::c_void;

    //     let ret = unsafe {
    //         s2n_config_set_nanoseconds_since_epoch_callback(self.s2n_config,
    //                                                         Some(c_callback),
    //                                                         data_ptr)
    //     };
    //     match ret {
    //         0 => Ok(()),
    //         -1 => Err(ExtensionDataError),
    //         _ => unreachable!(),
    //     }
    // }

    // pub fn set_client_hello_cb<F, D>(&mut self, callback: Option<F>, ctx: D) -> ConfigResult {
    //     let ctx_ptr = &mut ctx as *mut _ as *mut ::std::os::raw::c_void;
    //     let ret = unsafe { s2n_config_set_client_hello_cb(self.s2n_config, callback, ctx_ptr) };

    //     match ret {
    //         0 => Ok(()),
    //         -1 => Err(ExtensionDataError),
    //         _ => unreachable!(),
    //     }
    // }

    pub fn set_client_auth_type(&mut self, cert_auth_type: CertAuthType) -> ConfigResult {
        let ret = unsafe { s2n_config_set_client_auth_type(self.s2n_config, cert_auth_type) };
        match ret {
            0 => Ok(()),
            -1 => Err(CertAuthTypeError),
            _ => unreachable!(),
        }
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        unsafe { s2n_config_free(self.s2n_config) };
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_drop_config() {
        let config = Config::new();
        drop(config);
    }

    #[test]
    fn test_config_set_cipher() {
        let mut config = Config::new();
        config.set_cipher_preferences("default").unwrap();
    }

    #[test]
    fn test_config_set_cipher_version() {
        let mut config = Config::new();
        config.set_cipher_preferences("20160411").unwrap();
    }

    #[test]
    fn test_config_set_bad_cipher() {
        let mut config = Config::new();
        config.set_cipher_preferences("NOTACIPHER").unwrap_err();
    }

    #[test]
    fn test_config_set_cert_and_key() {
        let mut config = Config::new();

        let cert = include_str!("../test/apiserver.pem");
        let key = include_str!("../test/apiserver-key.pem");

        config.add_cert_chain_and_key(cert, key).unwrap();
    }

    #[test]
    fn test_config_set_bad_cert() {
        let mut config = Config::new();
        config
            .add_cert_chain_and_key("NOTACERT", "NOTAKEY")
            .unwrap_err();
    }

    // #[test]
    fn test_config_set_dh_param() {
        let mut config = Config::new();
        let params = include_str!("../test/dhparam.pem");
        config.add_dhparams(params).unwrap();
    }

    #[test]
    fn test_config_set_bad_dh_param() {
        let mut config = Config::new();
        config.add_dhparams("NOTPARAMS").unwrap_err();
    }

    #[test]
    fn test_config_set_protocol_preferences() {
        let mut config = Config::new();
        let protocols = vec!["http/1.1", "spdy/3.1"];
        config.set_protocol_preferences(&protocols).unwrap();
    }

    #[test]
    fn test_config_set_status_request_type() {
        let mut config = Config::new();
        config
            .set_status_request_type(StatusRequestType::S2N_STATUS_REQUEST_OCSP)
            .unwrap();
    }

    // #[test]
    fn test_config_set_extension_data() {
        let mut config = Config::new();

        let data = vec![1, 2, 3];
        config
            .set_extension_data(TLSExtensionType::S2N_EXTENSION_CERTIFICATE_TRANSPARENCY,
                                &data)
            .unwrap();
    }

    #[test]
    fn test_config_set_cert_auth_type() {
        let mut config = Config::new();
        config
            .set_client_auth_type(CertAuthType::S2N_CERT_AUTH_REQUIRED)
            .unwrap();
    }
}
