use std::ffi::{self, CStr, CString};
use std::fmt;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::net::TcpStream;
use std::os::unix::io::RawFd;
use std::slice;
use std::string::ToString;

use failure::Fail;

use config::Config;
use s2n::*;
use types::*;

pub struct Connection<C = ()> {
    s2n_connection: *mut s2n_connection,
    context_phantom: PhantomData<C>,
}

#[derive(Debug, Fail)]
pub enum ConnectionError {
    #[fail(display = "FFI Error: {}", _0)]
    FFIError(#[cause]
             ffi::NulError),
    #[fail(display = "UTF8 Error: {}", _0)]
    Utf8Error(#[cause]
              ::std::str::Utf8Error),
    #[fail(display = "Error wiping connection")]
    ConnectionWipeError,
    #[fail(display = "Error getting curve")]
    GetCurveError,
    #[fail(display = "Error setting connection file descripter")]
    ConnectionSetFDError,
    #[fail(display = "Error setting connection server name")]
    ConnectionServerNameError,
    #[fail(display = "Error negotiating connection")]
    ConnectionNegotiateError,
    #[fail(display = "Error getting protocol version")]
    ProtocolVersionError,
    #[fail(display = "Error setting Certificate Authentication type")]
    CertAuthTypeError,
    #[fail(display = "Error reading")]
    ReadError,
    #[fail(display = "Error sending")]
    SendError,
    #[fail(display = "Shutdown Error")]
    ShutdownError,
    #[fail(display = "Free Error")]
    FreeError,
    #[fail(display = "Error setting CorkedIO")]
    SetCorkedIOError,
    #[fail(display = "Error with Client Cert Chain")]
    ClientCertChainError,
}
use self::ConnectionError::*;

type ConnectionResult = Result<(), ConnectionError>;

impl<C> Default for Connection<C> {
    fn default() -> Self {
        Self::new(Mode::S2N_SERVER)
    }
}

impl<C> Connection<C> {
    pub fn new(mode: Mode) -> Self {
        super::init();
        let s2n_connection = unsafe { s2n_connection_new(mode) };
        if s2n_connection.is_null() {
            panic!("Unable to make connection")
        }
        Self {
            s2n_connection,
            context_phantom: PhantomData,
        }
    }

    /// Associates a [`Config`](struct.Config.html) struct with a connection.
    pub fn set_config(&mut self, config: &Config) {
        let ret = unsafe { s2n_connection_set_config(self.s2n_connection, config.s2n_config) };
        assert_eq!(0, ret, "Unexpected response from s2n_connection_set_config")
    }

    /// Set user defined context.
    pub fn set_context(&mut self, mut ctx: C) {
        let ctx_ptr = &mut ctx as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe { s2n_connection_set_ctx(self.s2n_connection, ctx_ptr) };
        assert_eq!(0, ret, "Unexpected response from s2n_connection_set_ctx")
    }

    /// Get user defined context.
    pub fn get_context(&self) -> Option<&mut C> {
        let ctx_ptr = unsafe { s2n_connection_get_ctx(self.s2n_connection) };
        if ctx_ptr.is_null() {
            None
        } else {
            let ctx: &mut C = unsafe { &mut *(ctx_ptr as *mut C) };
            Some(ctx)
        }
    }

    /// Sets the file-descriptor for an s2n connection.
    /// This file-descriptor should be active and connected.
    ///
    /// s2n also supports setting the read and write file-descriptors to different values
    /// (for pipes or other unusual types of I/O).
    pub fn set_fd(&mut self, readfd: RawFd) -> ConnectionResult {
        let ret = unsafe { s2n_connection_set_fd(self.s2n_connection, readfd) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionSetFDError),
            _ => unreachable!(),
        }
    }

    pub fn set_read_fd(&mut self, readfd: RawFd) -> ConnectionResult {
        let ret = unsafe { s2n_connection_set_read_fd(self.s2n_connection, readfd) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionSetFDError),
            _ => unreachable!(),
        }
    }

    pub fn set_write_fd(&mut self, readfd: RawFd) -> ConnectionResult {
        let ret = unsafe { s2n_connection_set_write_fd(self.s2n_connection, readfd) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionSetFDError),
            _ => unreachable!(),
        }
    }

    pub fn use_corked_io(&mut self) -> ConnectionResult {
        let ret = unsafe { s2n_connection_use_corked_io(self.s2n_connection) };
        match ret {
            0 => Ok(()),
            -1 => Err(SetCorkedIOError),
            _ => unreachable!(),
        }
    }

    /// s2n provides an I/O abstraction layer in the event the application would like to keep
    /// control over I/O operations.
    ///
    /// This is defined using callbacks, which take as input a context containing
    /// anything needed in the function (for example, a file descriptor), the buffer
    /// holding data to be sent or received, and the length of the buffer.
    ///
    /// The io_context passed to the callbacks may be set using
    /// [`set_recv_ctx`](struct.Connection.html#method.set_recv_ctx) and
    /// [`set_send_ctx`](struct.Connection.html#method.set_send_ctx).
    pub fn set_recv_ctx<RC>(&mut self, mut ctx: RC) {
        let ctx_ptr = &mut ctx as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe { s2n_connection_set_recv_ctx(self.s2n_connection, ctx_ptr) };

        ::std::mem::forget(ctx);

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_set_recv_ctx")
    }

    pub fn set_send_ctx<RC>(&mut self, mut ctx: RC) {
        let ctx_ptr = &mut ctx as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe { s2n_connection_set_send_ctx(self.s2n_connection, ctx_ptr) };

        ::std::mem::forget(ctx);

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_set_send_ctx")
    }

    /// s2n provides an I/O abstraction layer in the event the application would like to keep
    /// control over I/O operations.
    ///
    /// [`set_recv_cb`](struct.Connection.html#method.set_recv_cb) and
    /// [`set_send_cb`](struct.Connection.html#method.set_send_cb) may
    /// be used to send or receive data with callbacks defined by the user.
    /// These may be blocking or nonblocking.
    ///
    /// These callbacks take as input a context containing anything needed in the function (for
    /// example, a file descriptor), the buffer holding data to be sent or received, and the length
    /// of the buffer.
    /// The io_context passed to the callbacks may be set separately using
    /// [`set_recv_ctx`](struct.Connection.html#method.set_recv_ctx) and
    /// [`set_send_ctx`](struct.Connection.html#method.set_send_ctx).
    pub fn set_recv_cb(&mut self, callback: RecvFn) {
        let ret = unsafe { s2n_connection_set_recv_cb(self.s2n_connection, callback) };

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_set_recv_cb")
    }

    pub fn set_send_cb(&mut self, callback: SendFn) {
        let ret = unsafe { s2n_connection_set_send_cb(self.s2n_connection, callback) };

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_set_send_cb")
    }

    /// [`prefer_throughput`](struct.Connection.html#method.prefer_throughput) and
    /// [`prefer_low_latency`](struct.Connection.html#method.prefer_low_latency) change the behavior
    /// of s2n when sending data to prefer either throughput or low latency.
    ///
    /// Connections prefering low latency will be encrypted using small record sizes that can be
    /// decrypted sooner by the recipient.
    ///
    /// Connections prefering throughput will use large record sizes that minimize overhead.
    ///
    /// # Note
    ///
    /// Connections default to an 8k outgoing maximum
    pub fn prefer_throughput(&mut self) {
        let ret = unsafe { s2n_connection_prefer_throughput(self.s2n_connection) };

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_prefer_throughput")
    }

    /// [`prefer_throughput`](struct.Connection.html#method.prefer_throughput) and
    /// [`prefer_low_latency`](struct.Connection.html#method.prefer_low_latency) change the behavior
    /// of s2n when sending data to prefer either throughput or low latency.
    ///
    /// Connections prefering low latency will be encrypted using small record sizes that can be
    /// decrypted sooner by the recipient.
    ///
    /// Connections prefering throughput will use large record sizes that minimize overhead.
    ///
    /// # Note
    ///
    /// Connections default to an 8k outgoing maximum
    pub fn prefer_low_latency(&mut self) {
        let ret = unsafe { s2n_connection_prefer_low_latency(self.s2n_connection) };

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_prefer_low_latency")
    }

    /// `set_blinding` can be used to configure s2n to either use built-in blinding
    /// (set blinding to [`S2N_BUILT_IN_BLINDING`](enum.Blinding.html#variant.S2N_BUILT_IN_BLINDING))
    /// or self-service blinding (set blinding to
    /// [`S2N_SELF_SERVICE_BLINDING`](enum.Blinding.html#variant.S2N_SELF_SERVICE_BLINDING)).
    pub fn set_blinding(&mut self, blinding: Blinding) {
        let ret = unsafe { s2n_connection_set_blinding(self.s2n_connection, blinding) };

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_set_blinding")
    }

    /// Return the number of nanoseconds an application using self-service
    /// blinding should pause before closing/shutting down the connection.
    pub fn get_delay(&mut self) -> u64 {
        // TODO: Should be &mut self? It calls nanoseconds_since_epoch
        unsafe { s2n_connection_get_delay(self.s2n_connection) }
    }

    /// Set the server name for the connection.
    ///
    /// In future, this can be used by clients who wish to use the TLS "Server Name indicator" extension.
    /// At present, client functionality is disabled.
    pub fn set_server_name(&mut self, server_name: &str) -> ConnectionResult {
        // These must be on seperate lines to ensure the lifetime of the string is longer than the FFI call
        let server_name_c = CString::new(server_name).map_err(FFIError)?;
        let server_name_ptr = server_name_c.as_ptr();

        let ret = unsafe { s2n_set_server_name(self.s2n_connection, server_name_ptr) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionServerNameError),
            _ => unreachable!(),
        }
    }

    /// Return the server name associated with a connection, or `None` if none is found.
    /// This can be used by a server to determine which server name the client is using.
    pub fn get_server_name(&self) -> Option<String> {
        let ret = unsafe { s2n_get_server_name(self.s2n_connection) };
        if ret.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ret) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }

    /// Return the negotiated application protocol for a connection.
    /// In the event of no protocol being negotiated, `None` is returned.
    pub fn get_application_protocol(&self) -> Option<String> {
        let ret = unsafe { s2n_get_application_protocol(self.s2n_connection) };
        if ret.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ret) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }

    /// Return the OCSP response sent by a server during the handshake.
    /// If no status response is received, `None` is returned.
    pub fn get_ocsp_response(&self) -> Option<&[u8]> {
        let mut length: u32 = 0;

        let ret = unsafe { s2n_connection_get_ocsp_response(self.s2n_connection, &mut length) };
        if ret.is_null() {
            return None;
        }
        unsafe { Some(slice::from_raw_parts(ret, length as usize)) }
    }

    pub fn get_sct_list(&self) -> Option<&[u8]> {
        let mut length: u32 = 0;

        let ret = unsafe { s2n_connection_get_sct_list(self.s2n_connection, &mut length) };
        if ret.is_null() {
            return None;
        }
        unsafe { Some(slice::from_raw_parts(ret, length as usize)) }
    }

    pub fn negotiate(&mut self) -> Result<(), ConnectionError> {
        loop {
            return match self.negotiate_nonblocking() {
                       Ok(None) => Ok(()), // Not blocked
                       Ok(_) => continue,
                       Err(e) => Err(e),
                   };
        }
    }

    pub fn negotiate_nonblocking(&mut self) -> Result<Option<Blocked>, ConnectionError> {
        let mut blocked: BlockedStatus = BlockedStatus::S2N_NOT_BLOCKED;

        let ret = unsafe { s2n_negotiate(self.s2n_connection, &mut blocked) };
        match ret {
            0 => {
                match blocked {
                    BlockedStatus::S2N_NOT_BLOCKED => Ok(None),
                    BlockedStatus::S2N_BLOCKED_ON_READ => Ok(Some(Blocked::OnRead)),
                    BlockedStatus::S2N_BLOCKED_ON_WRITE => Ok(Some(Blocked::OnWrite)),
                }
            }
            -1 => Err(ConnectionNegotiateError),
            _ => unreachable!(),
        }
    }

    /// Wipe an existing connection and allows it to be reused.
    ///
    /// It erases all data associated with a connection including pending reads.
    /// This function should be called after all I/O is completed and
    /// [`shutdown`](struct.Connection.html#method.shutdown) has been called.
    ///
    /// Reusing the same connection handle(s) is more performant than repeatedly
    /// constructing new [`Connection`](struct.Connection.html) structs.
    ///
    /// The `Drop` impl performs its own wipe of sensitive data.
    pub fn wipe(&mut self) -> ConnectionResult {
        let ret = unsafe { s2n_connection_wipe(self.s2n_connection) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionWipeError),
            _ => unreachable!(),
        }
    }

    /// Free the memory associated with an connection handle.
    /// The handle is considered invalid after [`free`](struct.Connection.html#method.free) is used.
    ///
    /// [`wipe`](struct.Connection.html#method.wipe) does not need to be called prior to this function.
    /// [`free`](struct.Connection.html#method.free) performs its own wipe of sensitive data.
    ///
    /// # Safety
    ///
    /// This function will cause a double free if called twice.
    /// Users should generally not call this, and depend on the `Drop` implementation.
    pub unsafe fn free(&mut self) -> ConnectionResult {
        let ret = s2n_connection_free(self.s2n_connection);
        match ret {
            0 => Ok(()),
            -1 => Err(FreeError),
            _ => unreachable!(),
        }
    }

    /// Attempt a closure at the TLS layer.
    /// It does not close the underlying transport.
    /// The call may block in either direction.
    ///
    /// Unlike other TLS implementations, this attempts a graceful shutdown by default.
    /// It will not return with success unless a *close_notify* alert is successfully sent and received.
    /// As a result, `shutdown` may fail when interacting with a non-conformant TLS implementation.
    ///
    /// Once `shutdown` is complete:
    ///
    /// * The `Connection` handle cannot be used for reading for writing.
    /// * The underlying transport can be closed.
    /// * The `Connection` handle can be freed via [`free`](struct.Connection.html#method.free) or reused via [`wipe`](struct.Connection.html#method.wipe)
    pub fn shutdown(&self) -> ConnectionResult {
        let mut blocked: BlockedStatus = BlockedStatus::S2N_NOT_BLOCKED;

        let ret = unsafe { s2n_shutdown(self.s2n_connection, &mut blocked) };
        match ret {
            0 => Ok(()),
            -1 => Err(ShutdownError),
            _ => unreachable!(),
        }
    }

    pub fn get_client_auth_type(&self) -> CertAuthType {
        let mut client_auth_type: CertAuthType = CertAuthType::S2N_CERT_AUTH_NONE;
        let ret = unsafe {
            s2n_connection_get_client_auth_type(self.s2n_connection, &mut client_auth_type)
        };

        assert_eq!(0,
                   ret,
                   "Unexpected response from s2n_connection_get_client_auth_type");

        client_auth_type
    }

    /// Sets whether or not a Client Certificate should be required to complete the TLS Connection.
    ///
    /// If this is set to [`S2N_CERT_AUTH_REQUIRED`](enum.CertAuthType.html#variant.S2N_CERT_AUTH_REQUIRED)
    /// then a verify_cert_trust_chain_fn callback should be provided as well since the current
    /// default is for s2n to accept all RSA Certs on the client side, and deny all certs on the server side.
    pub fn set_client_auth_type(&mut self, client_auth_type: CertAuthType) -> ConnectionResult {
        let ret =
            unsafe { s2n_connection_set_client_auth_type(self.s2n_connection, client_auth_type) };
        match ret {
            0 => Ok(()),
            -1 => Err(CertAuthTypeError),
            _ => unreachable!(),
        }
    }

    // TODO: I think we need slice::from_raw_parts to convert back here
    pub fn get_client_cert_chain(&self) -> Result<&[u8], ConnectionError> {
        let der_cert_chain_out: &[u8] = &[];
        let mut cert_chain_len: u32 = 0;

        let der_cert_chain_out_ptr = der_cert_chain_out.as_ptr() as *mut *mut u8;

        let ret = unsafe {
            s2n_connection_get_client_cert_chain(self.s2n_connection,
                                                 der_cert_chain_out_ptr,
                                                 &mut cert_chain_len)
        };

        match ret {
            0 => Ok(der_cert_chain_out),
            -1 => Err(ClientCertChainError),
            _ => unreachable!(),
        }
    }

    /// [`get_wire_bytes_in`](struct.Connection.html#method.get_wire_bytes_in) and
    /// [`get_wire_bytes_out`](struct.Connection.html#method.get_wire_bytes_out) return
    /// the number of bytes transmitted by s2n "on the wire", in and out respectively.
    pub fn get_wire_bytes_in(&self) -> u64 {
        unsafe { s2n_connection_get_wire_bytes_in(self.s2n_connection) }
    }

    /// [`get_wire_bytes_in`](struct.Connection.html#method.get_wire_bytes_in) and
    /// [`get_wire_bytes_out`](struct.Connection.html#method.get_wire_bytes_out) return
    /// the number of bytes transmitted by s2n "on the wire", in and out respectively.
    pub fn get_wire_bytes_out(&self) -> u64 {
        unsafe { s2n_connection_get_wire_bytes_out(self.s2n_connection) }
    }

    /// Return the protocol version number supported by the client.
    pub fn get_client_protocol_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_client_protocol_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }

    /// Return the protocol version number supported by the server.
    pub fn get_server_protocol_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_server_protocol_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }

    /// Return the protocol version number actually used by s2n for the connection.
    pub fn get_actual_protocol_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_actual_protocol_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }

    /// Return the protocol version used in the initial client hello message.
    pub fn get_client_hello_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_client_hello_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }

    pub fn client_cert_used(&self) -> bool {
        match unsafe { s2n_connection_client_cert_used(self.s2n_connection) } {
            1 => true,
            0 => false,
            _ => unreachable!(),
        }
    }

    /// Return a string indicating the cipher suite negotiated by s2n for a connection
    /// in Openssl format, e.g. "ECDHE-RSA-AES128-GCM-SHA256".
    pub fn get_cipher(&self) -> Option<String> {
        let ret = unsafe { s2n_connection_get_cipher(self.s2n_connection) };
        if ret.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ret) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }

    /// Return a string indicating the elliptic curve used during ECDHE key exchange.
    /// `None` is returned if no curve was used.
    pub fn get_curve(&self) -> Result<Option<String>, ConnectionError> {
        let ret = unsafe { s2n_connection_get_curve(self.s2n_connection) };
        if ret.is_null() {
            return Err(GetCurveError);
        }
        let curve = unsafe { CStr::from_ptr(ret) }
            .to_str()
            .map_err(Utf8Error)?
            .to_string();
        if curve == "NONE" {
            Ok(None)
        } else {
            Ok(Some(curve))
        }
    }

    /// If a connection was shut down by the peer, return the TLS alert code that
    /// caused a connection to be shut down.
    ///
    /// s2n considers all TLS alerts fatal and shuts down a connection whenever one is received.
    pub fn get_alert(&mut self) -> Option<::std::os::raw::c_int> {
        let ret = unsafe { s2n_connection_get_alert(self.s2n_connection) };
        match ret {
            0 => Some(ret),
            -1 => None,
            _ => unreachable!(),
        }
    }
}


impl<C> Connection<C> {
    pub fn set_tcp_stream(&mut self, stream: &TcpStream) -> ConnectionResult {
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
        self.set_fd(fd)
    }
}


impl<C> Drop for Connection<C> {
    fn drop(&mut self) {
        let _ = unsafe { self.free() };
    }
}

impl<C> Read for Connection<C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut blocked: s2n_blocked_status = s2n_blocked_status::S2N_NOT_BLOCKED;

        let bytes_read = unsafe {
            s2n_recv(self.s2n_connection,
                     buf.as_mut_ptr() as *mut ::std::os::raw::c_void,
                     buf.len() as isize,
                     &mut blocked)
        };

        if bytes_read < 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, ReadError.compat()));
        }
        if bytes_read == 0 {
            // Connection has been closed
            let _ = self.wipe();
        }
        Ok(bytes_read as usize)
    }

    #[cfg(nightly)]
    #[inline]
    unsafe fn initializer(&self) -> ::std::io::Initializer {
        ::std::io::Initializer::nop()
    }
}

impl<C> Write for Connection<C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut blocked: s2n_blocked_status = s2n_blocked_status::S2N_NOT_BLOCKED;

        let bytes_read = unsafe {
            s2n_send(self.s2n_connection,
                     buf.as_ptr() as *mut ::std::os::raw::c_void,
                     buf.len() as isize,
                     &mut blocked)
        };

        if bytes_read <= 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, SendError.compat()))?;
        }
        Ok(bytes_read as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        /* noop */
        Ok(())
    }
}

pub enum Blocked {
    OnRead,
    OnWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    SSLv2,
    SSLv3,
    TLS10,
    TLS11,
    TLS12,
    UnknownProtocolVersion,
}

impl ProtocolVersion {
    #[allow(non_upper_case_globals)]
    fn from_int(i: ::std::os::raw::c_uint) -> Option<Self> {
        use self::ProtocolVersion::*;
        Some(match i {
                 S2N_SSLv2 => SSLv2,
                 S2N_SSLv3 => SSLv3,
                 S2N_TLS10 => TLS10,
                 S2N_TLS11 => TLS11,
                 S2N_TLS12 => TLS12,
                 S2N_UNKNOWN_PROTOCOL_VERSION => UnknownProtocolVersion,
                 _ => return None,
             })
    }
}


impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ProtocolVersion::*;
        let s = match *self {
            SSLv2 => "SSLv2",
            SSLv3 => "SSLv3",
            TLS10 => "TLSv1.0",
            TLS11 => "TLSv1.1",
            TLS12 => "TLSv1.2",
            UnknownProtocolVersion => "Unknown Protocol Version",
        };
        write!(f, "{}", s)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_drop_connection() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        drop(connection);
    }

    #[test]
    fn test_connection_set_config() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        let config = Config::new();
        connection.set_config(&config);
    }

    #[test]
    fn test_connection_set_context() {
        let mut connection = Connection::new(Mode::S2N_SERVER);
        let context = "some data";
        connection.set_context(context);
    }

    #[test]
    fn test_connection_get_server_name() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_server_name().is_none());
    }

    #[test]
    fn test_connection_set_get_server_name() {
        ::std::env::set_var("S2N_ENABLE_CLIENT_MODE", "TRUE_FOR_TEST");

        let mut connection: Connection = Connection::new(Mode::S2N_CLIENT);
        let name = "server.example.com";
        connection.set_server_name(&name).unwrap();
        assert_eq!(connection.get_server_name().unwrap(), name);

        ::std::env::remove_var("S2N_ENABLE_CLIENT_MODE");
    }

    #[test]
    fn test_connection_get_curve_no_curve() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_curve().unwrap().is_none());
    }

    #[test]
    fn test_connection_wipe() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection.wipe().unwrap();
    }

    #[test]
    fn test_protocolversion_from_int() {
        assert_eq!(ProtocolVersion::UnknownProtocolVersion,
                   ProtocolVersion::from_int(0).unwrap())
    }

    #[test]
    fn test_protocolversion_from_c_int() {
        assert_eq!(ProtocolVersion::TLS12,
                   ProtocolVersion::from_int(S2N_TLS12).unwrap())
    }

    #[test]
    fn test_protocolversion_display() {
        assert_eq!("TLSv1.2", ProtocolVersion::TLS12.to_string())
    }

    #[test]
    fn test_connection_wire_bytes_out() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert_eq!(0, connection.get_wire_bytes_out())
    }

    #[test]
    fn test_connection_wire_bytes_in() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert_eq!(0, connection.get_wire_bytes_in())
    }

    #[test]
    fn test_connection_set_client_auth_type() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection
            .set_client_auth_type(CertAuthType::S2N_CERT_AUTH_REQUIRED)
            .unwrap();
    }

    #[test]
    fn test_connection_get_client_auth_type() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection
            .set_client_auth_type(CertAuthType::S2N_CERT_AUTH_REQUIRED)
            .unwrap();
        assert_eq!(CertAuthType::S2N_CERT_AUTH_REQUIRED,
                   connection.get_client_auth_type())
    }

    #[test]
    fn test_connection_shutdown() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection.shutdown().unwrap();
    }

    #[test]
    fn test_connection_get_sct_list() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_sct_list().is_none())
    }

    #[test]
    fn test_connection_get_ocsp_response() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_ocsp_response().is_none())
    }

    #[test]
    fn test_connection_get_application_protocol() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_application_protocol().is_none())
    }

    #[test]
    fn test_connection_get_delay() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert_eq!(0, connection.get_delay())
    }

    #[test]
    fn test_connection_set_blinding() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection.set_blinding(Blinding::S2N_SELF_SERVICE_BLINDING)
    }

    #[test]
    fn test_connection_prefer_low_latency() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection.prefer_low_latency()
    }

    #[test]
    fn test_connection_prefer_throughput() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection.prefer_throughput()
    }

    #[test]
    fn test_connection_use_corked_io() {
        use std::os::unix::io::AsRawFd;

        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection
            .set_fd(::std::io::stdout().as_raw_fd())
            .unwrap();
        connection.use_corked_io().unwrap()
    }

    #[test]
    fn test_connection_set_recv_ctx() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);

        let ctx = ();

        connection.set_recv_ctx(ctx)
    }

    #[test]
    fn test_connection_set_send_ctx() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);

        let ctx = ();

        connection.set_send_ctx(ctx)
    }

    #[test]
    fn test_connection_set_recv_cb() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);

        unsafe extern "C" fn test(_io_context: *mut ::std::os::raw::c_void,
                                  _buf: *mut u8,
                                  _len: u32)
                                  -> i32 {
            unimplemented!()
        }

        connection.set_recv_cb(Some(test))
    }

    #[test]
    fn test_connection_set_send_cb() {
        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);

        unsafe extern "C" fn test(_io_context: *mut ::std::os::raw::c_void,
                                  _buf: *const u8,
                                  _len: u32)
                                  -> i32 {
            unimplemented!()
        }

        connection.set_send_cb(Some(test))
    }

    #[test]
    fn test_connection_set_write_fd() {
        use std::os::unix::io::AsRawFd;

        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection
            .set_write_fd(::std::io::stdout().as_raw_fd())
            .unwrap();
    }

    #[test]
    fn test_connection_set_read_fd() {
        use std::os::unix::io::AsRawFd;

        let mut connection: Connection = Connection::new(Mode::S2N_SERVER);
        connection
            .set_read_fd(::std::io::stdout().as_raw_fd())
            .unwrap();
    }

    #[test]
    fn test_connection_get_context_no_context() {
        let connection: Connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_context().is_none());
    }

    #[test]
    fn test_connection_set_context_get_context() {
        let mut connection = Connection::new(Mode::S2N_SERVER);

        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Example {
            One,
            Two,
        }

        let context = Example::One;

        connection.set_context(context);
        assert_eq!(&context, connection.get_context().unwrap());
    }


    #[test]
    #[ignore]
    fn test_connection_set_context_get_context_string() {
        let mut connection = Connection::new(Mode::S2N_SERVER);

        let context = "Hello";
        ::std::mem::forget(context);

        connection.set_context(context);
        assert_eq!(&context, connection.get_context().unwrap());
    }
}
