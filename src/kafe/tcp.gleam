import gleam/dynamic.{type Dynamic}
import mug.{type Socket}

pub type SecureSocket

pub type Protocol {
  Tlsv1
  Tlsv1m1
  Tlsv1m2
  Tlsv1m3
}

pub type SslOptions

pub type TlsAlert {
  CloseNotify(description: String)
  UnexpectedMessage(description: String)
  BadRecordMac(description: String)
  RecordOverflow(description: String)
  HandshakeFailure(description: String)
  BadCertificate(description: String)
  UnsupportedCertificate(description: String)
  CertificateRevoked(description: String)
  CertificateExpired(description: String)
  CertificateUnknown(description: String)
  IllegalParameter(description: String)
  UnknownCa(description: String)
  AccessDenied(description: String)
  DecodeError(description: String)
  DecryptError(description: String)
  ExportRestriction(description: String)
  ProtocolVersion(description: String)
  InsufficientSecurity(description: String)
  InternalError(description: String)
  InappropriateFallback(description: String)
  UserCanceled(description: String)
  NoRenegotiation(description: String)
  UnsupportedExtension(description: String)
  CertificateUnobtainable(description: String)
  UnrecognizedName(description: String)
  BadCertificateStatusResponse(description: String)
  BadCertificateHashValue(description: String)
  UnknownPskIdentity(description: String)
  NoApplicationProtocol(description: String)
}

pub type WrapError {
  Closed
  Options(Dynamic)
  TlsAlert(TlsAlert)
  Other(Dynamic)
  ChiperSuiteNotRecognized(String)
}

@external(erlang, "kafe_ffi", "wrap")
pub fn wrap(
  socket: Socket,
  options opts: SslOptions,
) -> Result(SecureSocket, WrapError)
