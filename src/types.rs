use s2n;

pub use s2n::s2n_tls_extension_type as TLSExtensionType;
pub use s2n::s2n_max_frag_len as MaxFragLen;
pub use s2n::s2n_status_request_type as StatusRequestType;
pub use s2n::s2n_ct_support_level as CTSupportLevel;

pub use s2n::s2n_mode as Mode;
pub use s2n::s2n_blinding as Blinding;
pub use s2n::s2n_blocked_status as BlockedStatus;
pub use s2n::s2n_cert_auth_type as CertAuthType;
pub use s2n::s2n_cert_validation_code as CertValidationCode;
pub use s2n::s2n_cert_type as CertType;


pub use s2n::s2n_client_hello_fn as ClientHelloFn;
pub type VerifyCertTrustChainFn =
    unsafe extern "C" fn(conn: *mut s2n::s2n_connection,
                         der_cert_chain_in: *mut u8,
                         cert_chain_len: u32,
                         cert_type: *mut s2n::s2n_cert_type,
                         public_key_out: *mut s2n::s2n_cert_public_key,
                         context: *mut ::std::os::raw::c_void)
                         -> s2n::s2n_cert_validation_code;
pub type CacheDeleteFn = unsafe extern "C" fn(data: *mut ::std::os::raw::c_void,
                                              key: *const ::std::os::raw::c_void,
                                              key_size: u64)
                                              -> ::std::os::raw::c_int;

pub type CacheRetreiveFn = unsafe extern "C" fn(data: *mut ::std::os::raw::c_void,
                                                key: *const ::std::os::raw::c_void,
                                                key_size: u64,
                                                value: *mut ::std::os::raw::c_void,
                                                value_size: *mut u64)
                                                -> ::std::os::raw::c_int;

pub type CacheStoreFn = unsafe extern "C" fn(data: *mut ::std::os::raw::c_void,
                                             ttl_in_seconds: u64,
                                             key: *const ::std::os::raw::c_void,
                                             key_size: u64,
                                             value: *const ::std::os::raw::c_void,
                                             value_size: u64)
                                             -> ::std::os::raw::c_int;

pub type NanosecondsSinceEpochFn = unsafe extern "C" fn(data: *mut ::std::os::raw::c_void,
                                                        unix_time: *mut u64)
                                                        -> ::std::os::raw::c_int;
