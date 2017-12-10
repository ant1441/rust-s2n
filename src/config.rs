use std::ffi::{self, CString};
use std::fmt;
use std::ops::Drop;

use s2n::*;
use types::*;

/// Config is used by servers for holding cryptographic certificates, keys and
/// preferences.
/// This object can (and should) be associated with many connection objects.
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
    ///
    /// ```
    /// use s2n::Config;
    ///
    /// let config = Config::new();
    /// ```
    pub fn new() -> Self {
        Default::default()
    }

    /// Frees the memory associated with the linked s2n_config object.
    /// This is used in the structs `Drop` implementation.
    ///
    /// # Safety
    ///
    /// This function is unsafe as calling it frees the memory backing
    /// this struct. Calling it twice would be a double free.
    ///
    /// This generally shouldn't be used, as the `Drop` implementation
    /// will handle that for you.
    pub unsafe fn free(&mut self) -> ConfigResult {
        let ret = s2n_config_free(self.s2n_config);
        match ret {
            0 => Ok(()),
            -1 => Err(FreeError),
            _ => unreachable!(),
        }
    }

    /// Frees the memory used to store the configured Diffie-Hellman
    /// parameters.
    ///
    /// Currently this memory is leaked on a second call to `add_dhparams`.
    ///
    /// # Safety
    ///
    /// Calling this before configuring Diffie-Hellman parameters is undefined.
    ///
    /// Calling this twice results in a double free. Eventually we
    /// should handle this for the user.
    pub unsafe fn free_dhparams(&mut self) -> ConfigResult {
        let ret = s2n_config_free_dhparams(self.s2n_config);
        match ret {
            0 => Ok(()),
            -1 => Err(FreeError),
            _ => unreachable!(),
        }
    }

    /// Frees the memory used to store the configured certificate chain and
    /// private key.
    ///
    /// Currently this memory is leaked on a second call to `add_cert_chain_and_key`.
    ///
    /// # Safety
    ///
    /// Calling this before adding a certificate chain and private key is
    /// undefined.
    ///
    /// Calling this twice results in a double free. Eventually we
    /// should handle this for the user.
    pub unsafe fn free_cert_chain_and_key(&mut self) -> ConfigResult {
        let ret = s2n_config_free_cert_chain_and_key(self.s2n_config);
        self.has_cert_chain_and_key = false;
        match ret {
            0 => Ok(()),
            -1 => Err(FreeError),
            _ => unreachable!(),
        }
    }


    /// Allows the caller to set a callback function that will be used to
    /// get the time.
    ///
    /// The callback function takes two arguments:
    ///
    ///  * A pointer to abitrary data for use within the callback
    ///  * A pointer to a `u64`.
    ///
    /// The first pointer will be set to the value of data which supplied by
    /// the caller when setting the callback.
    /// The integer pointed to by the second pointer should be set to the
    /// number of nanoseconds since the Unix epoch (Midnight, January 1st, 1970).
    ///
    /// The function should return 0 on success and -1 on error.
    /// The function is also required to implement a monotonic time source;
    /// the number of nanoseconds returned should never decrease between calls.
    ///
    /// # Safety
    ///
    /// Currently the callback function is required to be an `unsafe` func.
    /// This is because the function is passed directly to the s2n c code.
    ///
    /// Eventually this should be wrapped for safety.
    ///
    /// `callback` is permanently leaked by this.
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

    /// Allows setting a callback function that will be used to store SSL session
    /// data in a cache.
    ///
    /// The callback function takes six arguments:
    ///
    ///  * A pointer to abitrary data for use within the callback
    ///  * A 64-bit unsigned integer specifying the number of seconds the session data may be stored for
    ///  * A pointer to a key which can be used to retrieve the cached entry
    ///  * A 64 bit unsigned integer specifying the size of this key
    ///  * A pointer to a value which should be stored
    ///  * A 64 bit unsigned integer specified the size of this value
    ///
    /// # Safety
    ///
    /// Currently the callback function is required to be an `unsafe` func.
    /// This is because the function is passed directly to the s2n c code.
    ///
    /// Eventually this should be wrapped for safety.
    ///
    /// `callback` is permanently leaked by this.
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

    /// Allows setting a callback function that will be used to retrieve SSL session
    /// data from a cache.
    ///
    /// The callback function takes five arguments:
    ///
    ///  * A pointer to abitrary data for use within the callback
    ///  * A pointer to a key which can be used to retrieve the cached entry
    ///  * A 64 bit unsigned integer specifying the size of this key
    ///  * A pointer to a memory location where the value should be stored
    ///  * A pointer to a 64 bit unsigned integer specifing the size of this value. Initially *value_size will be set to the amount of space allocated for the value
    ///
    /// The callback should set *value_size to the actual size of the data returned.
    /// If there is insufficient space -1 should be returned.
    ///
    /// # Safety
    ///
    /// Currently the callback function is required to be an `unsafe` func.
    /// This is because the function is passed directly to the s2n c code.
    ///
    /// Eventually this should be wrapped for safety.
    ///
    /// `callback` is permanently leaked by this.
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

    /// Allows setting a callback function that will be used to delete SSL session
    /// data from a cache.
    ///
    /// The callback function takes three arguments:
    ///
    ///  * A pointer to abitrary data for use within the callback
    ///  * A pointer to a key which can be used to delete the cached entry
    ///  * A 64 bit unsigned integer specifying the size of this key
    ///
    /// # Safety
    ///
    /// Currently the callback function is required to be an `unsafe` func.
    /// This is because the function is passed directly to the s2n c code.
    ///
    /// Eventually this should be wrapped for safety.
    ///
    /// `callback` is permanently leaked by this.
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

    /// Associates a certificate chain and a private key, with a `Config` struct.
    /// At present, only one certificate-chain/key pair may be associated with a
    /// config.
    ///
    /// `cert_chain_pem` should be a PEM encoded certificate chain, with the first
    /// certificate in the chain being your servers certificate. `private_key_pem`
    /// should be a PEM encoded private key corresponding to the server certificate.
    ///
    /// # Example
    ///
    /// ```
    /// use s2n::Config;
    ///
    /// let mut config = Config::new();
    ///
    /// let cert = include_str!("../test/apiserver.pem");
    /// let key = include_str!("../test/apiserver-key.pem");
    ///
    /// config.add_cert_chain_and_key(cert, key).unwrap();
    /// ```
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

    /// Associate a set of Diffie-Hellman parameters with the `Config` struct.
    /// `dhparams_pem` should be PEM encoded DH parameters.
    ///
    /// # Example
    ///
    /// ```
    /// use s2n::Config;
    ///
    /// let mut config = Config::new();
    ///
    /// let params = include_str!("../test/dhparam.pem");
    ///
    /// config.add_dhparams(params).unwrap();
    /// ```
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

    /// Set the ciphersuite and protocol versions.
    /// The currently supported versions are:
    ///
    /// |    version | SSLv3 | TLS1.0 | TLS1.1 | TLS1.2 | AES-CBC | ChaCha20-Poly1305 | AES-GCM | 3DES | RC4 | DHE | ECDHE |
    /// |------------|-------|--------|--------|--------|---------|-------------------|---------|------|-----|-----|-------|
    /// | "default"  |       |   X    |    X   |    X   |    X    |         X         |    X    |      |     |     |   X   |
    /// | "20170718" |       |   X    |    X   |    X   |    X    |                   |    X    |      |     |     |   X   |
    /// | "20170405" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
    /// | "20170328" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |  X  |   X   |
    /// | "20170210" |       |   X    |    X   |    X   |    X    |         X         |    X    |      |     |     |   X   |
    /// | "20160824" |       |   X    |    X   |    X   |    X    |                   |    X    |      |     |     |   X   |
    /// | "20160804" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
    /// | "20160411" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
    /// | "20150306" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
    /// | "20150214" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |  X  |       |
    /// | "20150202" |       |   X    |    X   |    X   |    X    |                   |         |  X   |     |  X  |       |
    /// | "20141001" |       |   X    |    X   |    X   |    X    |                   |         |  X   |  X  |  X  |       |
    /// | "20140601" |   X   |   X    |    X   |    X   |    X    |                   |         |  X   |  X  |  X  |       |
    ///
    /// The "default" version is special in that it will be updated with future s2n
    /// changes and ciphersuites and protocol versions may be added and removed,
    /// or their internal order of preference might change.
    /// Numbered versions are fixed and will never change.
    ///
    /// Please check the [s2n
    /// Documetation](https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md#s2n_config_set_cipher_preferences)
    /// for more specific details.
    ///
    /// # Example
    ///
    /// ```
    /// use s2n::Config;
    ///
    /// let mut config = Config::new();
    ///
    /// config.set_cipher_preferences("20170405").unwrap();
    /// ```
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

    /// Set the application protocol preferences on a `Config` struct.
    /// `protocols` is a list in order of preference, with most preferred protocol first,
    /// and of length protocol_count.
    ///
    /// When acting as an **S2N_CLIENT** the protocol list is included in the Client Hello
    /// message as the ALPN extension.
    ///
    /// As an **S2N_SERVER**, the list is used to negotiate a mutual application protocol
    /// with the client.
    ///
    /// After the negotiation for the connection has completed, the agreed upon protocol
    /// can be retrieved with [`get_application_protocol`](struct.Connection.html#method.get_application_protocol)
    ///
    /// # Example
    ///
    /// ```
    /// use s2n::Config;
    ///
    /// let mut config = Config::new();
    ///
    /// let protocols = vec!["http/1.1", "spdy/3.1"];
    /// config.set_protocol_preferences(&protocols).unwrap();
    /// ```
    pub fn set_protocol_preferences(&mut self, protocols: &[&str]) -> ConfigResult {
        // This vec will hold the pointers to the strings
        let mut protocols_ptrs = vec![];
        // This Vec exists to hold the CStrings lifetimes open past the iteration and
        // through the c function call
        let mut cstring_lifetime = vec![];

        for &s in protocols {
            let cstring = CString::new(s).unwrap();
            let cstring_ptr = cstring.as_ptr();
            // Ensure cstring's lifetime lasts long enough
            cstring_lifetime.push(cstring);

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

    /// Unset the application protocol preferences on a `Config` struct.
    ///
    /// # Example
    ///
    /// ```
    /// use s2n::Config;
    ///
    /// let mut config = Config::new();
    ///
    /// let protocols = vec!["http/1.1", "spdy/3.1"];
    /// config.set_protocol_preferences(&protocols).unwrap();
    ///
    /// config.unset_protocol_preferences();
    /// ```
    pub fn unset_protocol_preferences(&mut self) {
        use std::ptr;

        // Calling `s2n_config_set_protocol_preferences` with NULL
        // clears the protocol preferences.
        let ret = unsafe { s2n_config_set_protocol_preferences(self.s2n_config, ptr::null(), 0) };

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_config_set_protocol_preferences")
    }

    /// Set up an **S2N_CLIENT** to request the server certificate status
    /// during an SSL handshake.
    /// If set to [S2N_STATUS_REQUEST_NONE](enum.StatusRequestType.html#variant.S2N_STATUS_REQUEST_NONE), no status request is made.
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

    /// Sets the extension data in the `Config` struct for the specified extension.
    /// This method will clear any existing data that is set.
    /// If the data parameters is empty, no new data is set in the `Config` struct,
    /// effectively clearing existing data.
    ///
    /// At this time the following extensions are supported:
    ///
    /// [S2N_EXTENSION_OCSP_STAPLING](enum.TLSExtensionType.html#variant.S2N_EXTENSION_OCSP_STAPLING) -
    ///   If a client requests the OCSP status of the server certificate,
    ///   this is the response used in the CertificateStatus handshake message.
    ///
    /// [S2N_EXTENSION_CERTIFICATE_TRANSPARENCY](enum.TLSExtensionType.html#variant.S2N_EXTENSION_CERTIFICATE_TRANSPARENCY) -
    ///   If a client supports receiving SCTs via the TLS extension
    ///   (section 3.3.1 of RFC6962) this data is returned within
    ///   the extension response during the handshake.
    ///   The format of this data is the SignedCertificateTimestampList structure
    ///   defined in that document. See http://www.certificate-transparency.org/
    ///   for more information about Certificate Transparency.
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

    /// Set a TLS Maximum Fragment Length extension that will be used to fragment outgoing messages.
    ///
    /// s2n currently does not reject fragments larger than the configured maximum when in server mode.
    ///
    /// The TLS negotiated maximum fragment length overrides the preference set by
    /// [`prefer_throughput`](struct.Connection.html#method.prefer_throughput) and
    /// [`prefer_low_latency`](struct.Connection.html#method.prefer_low_latency).
    pub fn send_max_fragment_length(&mut self, mfl_code: MaxFragLen) -> ConfigResult {
        let ret = unsafe { s2n_config_send_max_fragment_length(self.s2n_config, mfl_code) };
        match ret {
            0 => Ok(()),
            -1 => Err(MaxFragmentLengthError),
            _ => unreachable!(),
        }
    }

    /// Allows the server to opt-in to accept client's TLS maximum fragment length extension requests.
    ///
    /// If this API is not called, and client requests the extension, server will ignore the request
    /// and continue TLS handshake with default maximum fragment length of 8k bytes.
    pub fn accept_max_fragment_length(&mut self) -> ConfigResult {
        let ret = unsafe { s2n_config_accept_max_fragment_length(self.s2n_config) };
        match ret {
            0 => Ok(()),
            -1 => Err(MaxFragmentLengthError),
            _ => unreachable!(),
        }
    }

    /// Set a callback function that will be called after *ClientHello* was parsed.
    ///
    /// The callback function take as an input the s2n connection, which received ClientHello
    /// and the context provided here.
    /// The callback can get any ClientHello infromation from the connection and use
    /// [`set_config`](struct.Connection.html#method.set_config) call to change the config of the connection.
    ///
    /// The callback can return 0 to continue handshake in s2n or it can return negative value to
    /// make s2n terminate handshake early with fatal handshake failure alert.
    ///
    /// # Safety
    ///
    /// Currently the callback function is required to be an `unsafe` func.
    /// This is because the function is passed directly to the s2n c code.
    ///
    /// Eventually this should be wrapped for safety.
    ///
    /// `callback` and `ctx` are permanently leaked by this.
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

    /// Sets whether or not a Client Certificate should be required to complete the TLS Connection.
    ///
    /// If this is set to [S2N_CERT_AUTH_REQUIRED](enum.CertAuthType.html#variant.S2N_CERT_AUTH_REQUIRED)
    /// then a verify_cert_trust_chain_fn callback should be provided as well since the
    /// current default is for s2n to accept all RSA Certs on the client side,
    /// and deny all certs on the server side.
    pub fn set_client_auth_type(&mut self, cert_auth_type: CertAuthType) -> ConfigResult {
        let ret = unsafe { s2n_config_set_client_auth_type(self.s2n_config, cert_auth_type) };
        match ret {
            0 => Ok(()),
            -1 => Err(CertAuthTypeError),
            _ => unreachable!(),
        }
    }

    /// Sets the verify_cert_trust_chain_fn callback function and context that will be used when
    /// verifying Certificates for the connection.
    ///
    /// verify_cert_trust_chain_fn defines a Callback Function intended to be used only
    /// in special circumstances, and may be removed in a later release.
    /// Implementations should verify the Certificate Chain of trust, and place the leaf
    /// Certificate's Public Key in the `public_key_out` parameter.
    ///
    /// The callback function takes five arguments:
    ///
    /// * The connection the certificate chain is validated for
    /// * The DER encoded full chain of certificates recieved
    /// * The length in bytes of the DER encoded Cert Chain
    /// * The public key that should be updated with the key extracted from the first certificate in the chain (the leaf Cert)
    /// * A pointer to any caller defined context data needed for the callback (Cert Trust Store, etc)
    ///
    /// The function should return 0 if the Certificate Chain is trusted and public key
    /// extraction was successful, and less than 0 if any Certificate in the chain is
    /// untrusted, or there was some other error.
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
    fn test_debug() {
        let config = Config::new();

        println!("Config: {:?}", config);
    }

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
    #[should_panic(expected = "CertChainKeyError")]
    fn test_config_set_bad_cert() {
        let mut config = Config::new();
        config
            .add_cert_chain_and_key("NOTACERT", "NOTAKEY")
            .unwrap();
    }

    #[test]
    fn test_config_set_dh_param() {
        let mut config = Config::new();
        let params = include_str!("../test/dhparam.pem");
        config.add_dhparams(params).unwrap();
    }

    #[test]
    #[should_panic(expected = "DHParamsError")]
    fn test_config_set_bad_dh_param() {
        let mut config = Config::new();
        config.add_dhparams("NOTPARAMS").unwrap();
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
    fn test_config_unset_protocol_preferences() {
        let mut config = Config::new();
        let protocols = vec!["http/1.1", "spdy/3.1", "myprot/2.7"];
        config.set_protocol_preferences(&protocols).unwrap();
        config.unset_protocol_preferences();
    }

    #[test]
    fn test_config_unset_protocol_preferences_not_set() {
        let mut config = Config::new();

        config.unset_protocol_preferences();
    }

    #[test]
    fn test_config_set_status_request_type() {
        let mut config = Config::new();
        config.set_status_request_type(StatusRequestType::S2N_STATUS_REQUEST_OCSP);
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
    fn test_config_send_max_fragment_length() {
        let mut config = Config::new();
        config.send_max_fragment_length(MaxFragLen::S2N_TLS_MAX_FRAG_LEN_4096);
    }

    #[test]
    fn test_config_accept_max_fragment_length() {
        let mut config = Config::new();
        config.accept_max_fragment_length();
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
