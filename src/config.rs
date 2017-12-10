use std::ffi::{self, CString};
use std::fmt;
use std::ops::Drop;

use s2n::*;
use types::*;

pub struct Config {
    pub(crate) s2n_config: *mut s2n_config,
    // s2n_config->cert_and_key_pairs is initialised as NULL, but not checked in places
    has_cert_chain_and_key: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Config {{ s2n_config: {:p} }}", self.s2n_config)
    }
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
    #[fail(display = "Free Error")]
    FreeError,
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
    #[fail(display = "Error setting Certificate Transparency support level")]
    CTSupportLevelError,
    #[fail(display = "Error setting Max Fragment length")]
    MaxFragmentLengthError,
    #[fail(display = "Error setting callback")]
    CallbackError,

    #[fail(display = "No Certificate or Key added to config")]
    MissingCertKeyError,
}
use self::ConfigError::*;

type ConfigResult = Result<(), ConfigError>;

impl Default for Config {
    fn default() -> Self {
        super::init();
        let s2n_config = unsafe { s2n_config_new() };
        if s2n_config.is_null() {
            panic!("Unable to make config")
        }
        Self {
            s2n_config,
            has_cert_chain_and_key: false,
        }
    }
}

impl Config {
    /// Returns a new configuration object suitable for associating certs and keys.
    /// This object can (and should) be associated with many connection objects.
    pub fn new() -> Self {
        Default::default()
    }

    pub unsafe fn free(&mut self) -> ConfigResult {
        let ret = s2n_config_free(self.s2n_config);
        match ret {
            0 => Ok(()),
            -1 => Err(FreeError),
            _ => unreachable!(),
        }
    }

    pub unsafe fn free_dhparams(&mut self) -> ConfigResult {
        let ret = s2n_config_free_dhparams(self.s2n_config);
        match ret {
            0 => Ok(()),
            -1 => Err(FreeError),
            _ => unreachable!(),
        }
    }

    pub unsafe fn free_cert_chain_and_key(&mut self) -> ConfigResult {
        let ret = s2n_config_free_cert_chain_and_key(self.s2n_config);
        self.has_cert_chain_and_key = false;
        match ret {
            0 => Ok(()),
            -1 => Err(FreeError),
            _ => unreachable!(),
        }
    }


    pub fn set_nanoseconds_since_epoch_callback<D>(&mut self,
                                                   callback: NanosecondsSinceEpochFn,
                                                   mut data: D)
                                                   -> ConfigResult {
        let data_ptr = &mut data as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe {
            s2n_config_set_nanoseconds_since_epoch_callback(self.s2n_config,
                                                            Some(callback),
                                                            data_ptr)
        };

        ::std::mem::forget(data);

        match ret {
            0 => Ok(()),
            -1 => Err(CallbackError),
            _ => unreachable!(),
        }
    }

    pub fn set_cache_store_callback<D>(&mut self,
                                       callback: CacheStoreFn,
                                       mut data: D)
                                       -> ConfigResult {
        let data_ptr = &mut data as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe {
            s2n_config_set_cache_store_callback(self.s2n_config, Some(callback), data_ptr)
        };

        ::std::mem::forget(data);

        match ret {
            0 => Ok(()),
            -1 => Err(CallbackError),
            _ => unreachable!(),
        }
    }

    pub fn set_cache_retrieve_callback<D>(&mut self,
                                          callback: CacheRetreiveFn,
                                          mut data: D)
                                          -> ConfigResult {
        let data_ptr = &mut data as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe {
            s2n_config_set_cache_retrieve_callback(self.s2n_config, Some(callback), data_ptr)
        };

        ::std::mem::forget(data);

        match ret {
            0 => Ok(()),
            -1 => Err(CallbackError),
            _ => unreachable!(),
        }
    }

    pub fn set_cache_delete_callback<D>(&mut self,
                                        callback: CacheDeleteFn,
                                        mut data: D)
                                        -> ConfigResult {
        let data_ptr = &mut data as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe {
            s2n_config_set_cache_delete_callback(self.s2n_config, Some(callback), data_ptr)
        };

        ::std::mem::forget(data);

        match ret {
            0 => Ok(()),
            -1 => Err(CallbackError),
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
            0 => {
                self.has_cert_chain_and_key = true;
                Ok(())
            }
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

    pub fn set_ct_support_level(&mut self, ct_support_level: CTSupportLevel) -> ConfigResult {
        let ret = unsafe { s2n_config_set_ct_support_level(self.s2n_config, ct_support_level) };

        match ret {
            0 => Ok(()),
            -1 => Err(CTSupportLevelError),
            _ => unreachable!(),
        }
    }

    pub fn set_extension_data(&mut self,
                              extension_type: TLSExtensionType,
                              data: &[u8])
                              -> ConfigResult {
        if !self.has_cert_chain_and_key {
            return Err(MissingCertKeyError);
        }
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

    /// send_max_fragment_length allows the caller to set a TLS Maximum Fragment Length
    /// extension that will be used to fragment outgoing messages.
    /// s2n currently does not reject fragments larger than the configured maximum when
    /// in server mode.
    /// The TLS negotiated maximum fragment length overrides the preference set by the
    /// s2n_connection_prefer_throughput and s2n_connection_prefer_low_latency.
    pub fn send_max_fragment_length(&mut self, mfl_code: MaxFragLen) -> ConfigResult {
        let ret = unsafe { s2n_config_send_max_fragment_length(self.s2n_config, mfl_code) };
        match ret {
            0 => Ok(()),
            -1 => Err(MaxFragmentLengthError),
            _ => unreachable!(),
        }
    }

    /// s2n_config_accept_max_fragment_length allows the server to opt-in to accept client's TLS
    /// maximum fragment length extension requests. If this API is not called, and client requests
    /// the extension, server will ignore the request and continue TLS handshake with default
    /// maximum fragment length of 8k bytes
    pub fn accept_max_fragment_length(&mut self) -> ConfigResult {
        let ret = unsafe { s2n_config_accept_max_fragment_length(self.s2n_config) };
        match ret {
            0 => Ok(()),
            -1 => Err(MaxFragmentLengthError),
            _ => unreachable!(),
        }
    }

    pub fn set_client_hello_cb<D>(&mut self, callback: ClientHelloFn, mut ctx: D) -> ConfigResult {
        let ctx_ptr = &mut ctx as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe { s2n_config_set_client_hello_cb(self.s2n_config, callback, ctx_ptr) };

        ::std::mem::forget(ctx);

        match ret {
            0 => Ok(()),
            -1 => Err(CallbackError),
            _ => unreachable!(),
        }
    }

    pub fn get_client_auth_type(&self) -> Result<CertAuthType, ConfigError> {
        let mut client_auth_type: CertAuthType = CertAuthType::S2N_CERT_AUTH_NONE;
        let ret =
            unsafe { s2n_config_get_client_auth_type(self.s2n_config, &mut client_auth_type) };
        match ret {
            0 => Ok(client_auth_type),
            -1 => Err(CertAuthTypeError),
            _ => unreachable!(),
        }
    }

    pub fn set_client_auth_type(&mut self, cert_auth_type: CertAuthType) -> ConfigResult {
        let ret = unsafe { s2n_config_set_client_auth_type(self.s2n_config, cert_auth_type) };
        match ret {
            0 => Ok(()),
            -1 => Err(CertAuthTypeError),
            _ => unreachable!(),
        }
    }

    pub fn set_verify_cert_chain_cb<D>(&mut self,
                                       callback: VerifyCertTrustChainFn,
                                       mut ctx: D)
                                       -> ConfigResult {
        let ctx_ptr = &mut ctx as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe {
            s2n_config_set_verify_cert_chain_cb(self.s2n_config, Some(callback), ctx_ptr)
        };

        ::std::mem::forget(ctx);

        match ret {
            0 => Ok(()),
            -1 => Err(CallbackError),
            _ => unreachable!(),
        }
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        let _ = unsafe { self.free() };
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

    #[test]
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
    fn test_config_set_protocol_preferences2() {
        let mut config = Config::new();
        let protocols = vec!["http/1.1", "spdy/3.1", "myprot/2.7"];
        config.set_protocol_preferences(&protocols).unwrap();
    }

    #[test]
    fn test_config_set_status_request_type() {
        let mut config = Config::new();
        config
            .set_status_request_type(StatusRequestType::S2N_STATUS_REQUEST_OCSP)
            .unwrap();
    }

    #[test]
    fn test_config_set_extension_data() {
        let mut config = Config::new();

        let cert = include_str!("../test/apiserver.pem");
        let key = include_str!("../test/apiserver-key.pem");

        config.add_cert_chain_and_key(cert, key).unwrap();

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

    #[test]
    fn test_config_get_cert_auth_type() {
        let mut config = Config::new();
        config
            .set_client_auth_type(CertAuthType::S2N_CERT_AUTH_REQUIRED)
            .unwrap();

        assert_eq!(CertAuthType::S2N_CERT_AUTH_REQUIRED,
                   config.get_client_auth_type().unwrap());
    }

    #[test]
    fn test_config_set_client_hello_cb_no_func() {
        let mut config = Config::new();

        config
            .set_client_hello_cb::<Option<()>>(None, None)
            .unwrap();
    }

    #[test]
    fn test_config_set_client_hello_cb_func() {
        let mut config = Config::new();

        unsafe extern "C" fn test(_: *mut s2n_connection,
                                  _: *mut ::std::os::raw::c_void)
                                  -> ::std::os::raw::c_int {
            unimplemented!()
        }

        config
            .set_client_hello_cb::<Option<()>>(Some(test), None)
            .unwrap();
    }

    #[test]
    fn test_config_set_verify_cert_chain_cb_func() {
        let mut config = Config::new();

        unsafe extern "C" fn test(_conn: *mut s2n_connection,
                                  _der_cert_chain_in: *mut u8,
                                  _cert_chain_len: u32,
                                  _cert_type: *mut s2n_cert_type,
                                  _public_key_out: *mut s2n_cert_public_key,
                                  _context: *mut ::std::os::raw::c_void)
                                  -> CertValidationCode {
            unimplemented!()
        }

        config
            .set_verify_cert_chain_cb::<Option<()>>(test, None)
            .unwrap();
    }

    #[test]
    fn test_config_set_nanoseconds_since_epoch_callback() {
        let mut config = Config::new();

        unsafe extern "C" fn test(_data: *mut ::std::os::raw::c_void,
                                  _unix_time: *mut u64)
                                  -> ::std::os::raw::c_int {
            unimplemented!()
        }

        config
            .set_nanoseconds_since_epoch_callback::<Option<()>>(test, None)
            .unwrap();
    }

    #[test]
    fn test_config_set_cache_store_callback() {
        let mut config = Config::new();

        unsafe extern "C" fn test(_data: *mut ::std::os::raw::c_void,
                                  _ttl_in_seconds: u64,
                                  _key: *const ::std::os::raw::c_void,
                                  _key_size: u64,
                                  _value: *const ::std::os::raw::c_void,
                                  _value_size: u64)
                                  -> ::std::os::raw::c_int {
            unimplemented!()
        }

        config
            .set_cache_store_callback::<Option<()>>(test, None)
            .unwrap();
    }

    #[test]
    fn test_config_set_cache_retrieve_callback() {
        let mut config = Config::new();

        unsafe extern "C" fn test(_data: *mut ::std::os::raw::c_void,
                                  _key: *const ::std::os::raw::c_void,
                                  _key_size: u64,
                                  _value: *mut ::std::os::raw::c_void,
                                  _value_size: *mut u64)
                                  -> ::std::os::raw::c_int {
            unimplemented!()
        }

        config
            .set_cache_retrieve_callback::<Option<()>>(test, None)
            .unwrap();
    }

    #[test]
    fn test_config_set_cache_delete_callback() {
        let mut config = Config::new();

        unsafe extern "C" fn test(_data: *mut ::std::os::raw::c_void,
                                  _key: *const ::std::os::raw::c_void,
                                  _key_size: u64)
                                  -> ::std::os::raw::c_int {
            unimplemented!()
        }

        config
            .set_cache_delete_callback::<Option<()>>(test, None)
            .unwrap();
    }
}
