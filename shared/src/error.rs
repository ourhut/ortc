#![allow(dead_code)]

use rcgen::RcgenError;
use std::io;
use std::net;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    #[error("buffer: full")]
    ErrBufferFull,
    #[error("buffer: closed")]
    ErrBufferClosed,
    #[error("buffer: short")]
    ErrBufferShort,
    #[error("packet too big")]
    ErrPacketTooBig,
    #[error("i/o timeout")]
    ErrTimeout,
    #[error("udp: listener closed")]
    ErrClosedListener,
    #[error("udp: listen queue exceeded")]
    ErrListenQueueExceeded,
    #[error("udp: listener accept ch closed")]
    ErrClosedListenerAcceptCh,
    #[error("obs cannot be nil")]
    ErrObsCannotBeNil,
    #[error("se of closed network connection")]
    ErrUseClosedNetworkConn,
    #[error("addr is not a net.UDPAddr")]
    ErrAddrNotUdpAddr,
    #[error("something went wrong with locAddr")]
    ErrLocAddr,
    #[error("already closed")]
    ErrAlreadyClosed,
    #[error("no remAddr defined")]
    ErrNoRemAddr,
    #[error("address already in use")]
    ErrAddressAlreadyInUse,
    #[error("no such UDPConn")]
    ErrNoSuchUdpConn,
    #[error("cannot remove unspecified IP by the specified IP")]
    ErrCannotRemoveUnspecifiedIp,
    #[error("no address assigned")]
    ErrNoAddressAssigned,
    #[error("1:1 NAT requires more than one mapping")]
    ErrNatRequriesMapping,
    #[error("length mismtach between mappedIPs and localIPs")]
    ErrMismatchLengthIp,
    #[error("non-udp translation is not supported yet")]
    ErrNonUdpTranslationNotSupported,
    #[error("no associated local address")]
    ErrNoAssociatedLocalAddress,
    #[error("no NAT binding found")]
    ErrNoNatBindingFound,
    #[error("has no permission")]
    ErrHasNoPermission,
    #[error("host name must not be empty")]
    ErrHostnameEmpty,
    #[error("failed to parse IP address")]
    ErrFailedToParseIpaddr,
    #[error("no interface is available")]
    ErrNoInterface,
    #[error("not found")]
    ErrNotFound,
    #[error("unexpected network")]
    ErrUnexpectedNetwork,
    #[error("can't assign requested address")]
    ErrCantAssignRequestedAddr,
    #[error("unknown network")]
    ErrUnknownNetwork,
    #[error("no router linked")]
    ErrNoRouterLinked,
    #[error("invalid port number")]
    ErrInvalidPortNumber,
    #[error("unexpected type-switch failure")]
    ErrUnexpectedTypeSwitchFailure,
    #[error("bind failed")]
    ErrBindFailed,
    #[error("end port is less than the start")]
    ErrEndPortLessThanStart,
    #[error("port space exhausted")]
    ErrPortSpaceExhausted,
    #[error("vnet is not enabled")]
    ErrVnetDisabled,
    #[error("invalid local IP in static_ips")]
    ErrInvalidLocalIpInStaticIps,
    #[error("mapped in static_ips is beyond subnet")]
    ErrLocalIpBeyondStaticIpsSubset,
    #[error("all static_ips must have associated local IPs")]
    ErrLocalIpNoStaticsIpsAssociated,
    #[error("router already started")]
    ErrRouterAlreadyStarted,
    #[error("router already stopped")]
    ErrRouterAlreadyStopped,
    #[error("static IP is beyond subnet")]
    ErrStaticIpIsBeyondSubnet,
    #[error("address space exhausted")]
    ErrAddressSpaceExhausted,
    #[error("no IP address is assigned for eth0")]
    ErrNoIpaddrEth0,
    #[error("Invalid mask")]
    ErrInvalidMask,

    //ExportKeyingMaterial errors
    #[error("tls handshake is in progress")]
    HandshakeInProgress,
    #[error("context is not supported for export_keying_material")]
    ContextUnsupported,
    #[error("export_keying_material can not be used with a reserved label")]
    ReservedExportKeyingMaterial,
    #[error("no cipher suite for export_keying_material")]
    CipherSuiteUnset,
    #[error("export_keying_material hash: {0}")]
    Hash(String),
    #[error("mutex poison: {0}")]
    PoisonError(String),

    //RTCP errors
    /// Wrong marshal size.
    #[error("Wrong marshal size")]
    WrongMarshalSize,
    /// Packet lost exceeds maximum amount of packets
    /// that can possibly be lost.
    #[error("Invalid total lost count")]
    InvalidTotalLost,
    /// Packet contains an invalid header.
    #[error("Invalid header")]
    InvalidHeader,
    /// Packet contains empty compound.
    #[error("Empty compound packet")]
    EmptyCompound,
    /// Invalid first packet in compound packets. First packet
    /// should either be a SenderReport packet or ReceiverReport
    #[error("First packet in compound must be SR or RR")]
    BadFirstPacket,
    /// CNAME was not defined.
    #[error("Compound missing SourceDescription with CNAME")]
    MissingCname,
    /// Packet was defined before CNAME.
    #[error("Feedback packet seen before CNAME")]
    PacketBeforeCname,
    /// Too many reports.
    #[error("Too many reports")]
    TooManyReports,
    /// Too many chunks.
    #[error("Too many chunks")]
    TooManyChunks,
    /// Too many sources.
    #[error("too many sources")]
    TooManySources,
    /// Packet received is too short.
    #[error("Packet status chunk must be 2 bytes")]
    PacketTooShort,
    /// Buffer is too short.
    #[error("Buffer too short to be written")]
    BufferTooShort,
    /// Wrong packet type.
    #[error("Wrong packet type")]
    WrongType,
    /// SDES received is too long.
    #[error("SDES must be < 255 octets long")]
    SdesTextTooLong,
    /// SDES type is missing.
    #[error("SDES item missing type")]
    SdesMissingType,
    /// Reason is too long.
    #[error("Reason must be < 255 octets long")]
    ReasonTooLong,
    /// Invalid packet version.
    #[error("Invalid packet version")]
    BadVersion,
    /// Invalid padding value.
    #[error("Invalid padding value")]
    WrongPadding,
    /// Wrong feedback message type.
    #[error("Wrong feedback message type")]
    WrongFeedbackType,
    /// Wrong payload type.
    #[error("Wrong payload type")]
    WrongPayloadType,
    /// Header length is too small.
    #[error("Header length is too small")]
    HeaderTooSmall,
    /// Media ssrc was defined as zero.
    #[error("Media SSRC must be 0")]
    SsrcMustBeZero,
    /// Missing REMB identifier.
    #[error("Missing REMB identifier")]
    MissingRembIdentifier,
    /// SSRC number and length mismatches.
    #[error("SSRC num and length do not match")]
    SsrcNumAndLengthMismatch,
    /// Invalid size or start index.
    #[error("Invalid size or startIndex")]
    InvalidSizeOrStartIndex,
    /// Delta exceeds limit.
    #[error("Delta exceed limit")]
    DeltaExceedLimit,
    /// Packet status chunk is not 2 bytes.
    #[error("Packet status chunk must be 2 bytes")]
    PacketStatusChunkLength,
    #[error("Invalid bitrate")]
    InvalidBitrate,
    #[error("Wrong chunk type")]
    WrongChunkType,
    #[error("Struct contains unexpected member type")]
    BadStructMemberType,
    #[error("Cannot read into non-pointer")]
    BadReadParameter,

    //RTP errors
    #[error("RTP header size insufficient")]
    ErrHeaderSizeInsufficient,
    #[error("RTP header size insufficient for extension")]
    ErrHeaderSizeInsufficientForExtension,
    #[error("buffer too small")]
    ErrBufferTooSmall,
    #[error("extension not enabled")]
    ErrHeaderExtensionsNotEnabled,
    #[error("extension not found")]
    ErrHeaderExtensionNotFound,

    #[error("header extension id must be between 1 and 14 for RFC 5285 extensions")]
    ErrRfc8285oneByteHeaderIdrange,
    #[error("header extension payload must be 16bytes or less for RFC 5285 one byte extensions")]
    ErrRfc8285oneByteHeaderSize,

    #[error("header extension id must be between 1 and 255 for RFC 5285 extensions")]
    ErrRfc8285twoByteHeaderIdrange,
    #[error("header extension payload must be 255bytes or less for RFC 5285 two byte extensions")]
    ErrRfc8285twoByteHeaderSize,

    #[error("header extension id must be 0 for none RFC 5285 extensions")]
    ErrRfc3550headerIdrange,

    #[error("packet is not large enough")]
    ErrShortPacket,
    #[error("invalid nil packet")]
    ErrNilPacket,
    #[error("too many PDiff")]
    ErrTooManyPDiff,
    #[error("too many spatial layers")]
    ErrTooManySpatialLayers,
    #[error("NALU Type is unhandled")]
    ErrUnhandledNaluType,

    #[error("corrupted h265 packet")]
    ErrH265CorruptedPacket,
    #[error("invalid h265 packet type")]
    ErrInvalidH265PacketType,

    #[error("extension_payload must be in 32-bit words")]
    HeaderExtensionPayloadNot32BitWords,
    #[error("audio level overflow")]
    AudioLevelOverflow,
    #[error("payload is not large enough")]
    PayloadIsNotLargeEnough,
    #[error("STAP-A declared size({0}) is larger than buffer({1})")]
    StapASizeLargerThanBuffer(usize, usize),
    #[error("nalu type {0} is currently not handled")]
    NaluTypeIsNotHandled(u8),

    //SRTP
    #[error("duplicated packet")]
    ErrDuplicated,
    #[error("SRTP master key is not long enough")]
    ErrShortSrtpMasterKey,
    #[error("SRTP master salt is not long enough")]
    ErrShortSrtpMasterSalt,
    #[error("no such SRTP Profile")]
    ErrNoSuchSrtpProfile,
    #[error("indexOverKdr > 0 is not supported yet")]
    ErrNonZeroKdrNotSupported,
    #[error("exporter called with wrong label")]
    ErrExporterWrongLabel,
    #[error("no config provided")]
    ErrNoConfig,
    #[error("no conn provided")]
    ErrNoConn,
    #[error("failed to verify auth tag")]
    ErrFailedToVerifyAuthTag,
    #[error("packet is too short to be rtcp packet")]
    ErrTooShortRtcp,
    #[error("payload differs")]
    ErrPayloadDiffers,
    #[error("started channel used incorrectly, should only be closed")]
    ErrStartedChannelUsedIncorrectly,
    #[error("stream has not been inited, unable to close")]
    ErrStreamNotInited,
    #[error("stream is already closed")]
    ErrStreamAlreadyClosed,
    #[error("stream is already inited")]
    ErrStreamAlreadyInited,
    #[error("failed to cast child")]
    ErrFailedTypeAssertion,

    #[error("index_over_kdr > 0 is not supported yet")]
    UnsupportedIndexOverKdr,
    #[error("SRTP Master Key must be len {0}, got {1}")]
    SrtpMasterKeyLength(usize, usize),
    #[error("SRTP Salt must be len {0}, got {1}")]
    SrtpSaltLength(usize, usize),
    #[error("SyntaxError: {0}")]
    ExtMapParse(String),
    #[error("ssrc {0} not exist in srtp_ssrc_state")]
    SsrcMissingFromSrtp(u32),
    #[error("srtp ssrc={0} index={1}: duplicated")]
    SrtpSsrcDuplicated(u32, u16),
    #[error("srtcp ssrc={0} index={1}: duplicated")]
    SrtcpSsrcDuplicated(u32, usize),
    #[error("ssrc {0} not exist in srtcp_ssrc_state")]
    SsrcMissingFromSrtcp(u32),
    #[error("Stream with ssrc {0} exists")]
    StreamWithSsrcExists(u32),
    #[error("Session RTP/RTCP type must be same as input buffer")]
    SessionRtpRtcpTypeMismatch,
    #[error("Session EOF")]
    SessionEof,
    #[error("too short SRTP packet: only {0} bytes, expected > {1} bytes")]
    SrtpTooSmall(usize, usize),
    #[error("too short SRTCP packet: only {0} bytes, expected > {1} bytes")]
    SrtcpTooSmall(usize, usize),
    #[error("failed to verify rtp auth tag")]
    RtpFailedToVerifyAuthTag,
    #[error("failed to verify rtcp auth tag")]
    RtcpFailedToVerifyAuthTag,
    #[error("SessionSRTP has been closed")]
    SessionSrtpAlreadyClosed,
    #[error("this stream is not a RTPStream")]
    InvalidRtpStream,
    #[error("this stream is not a RTCPStream")]
    InvalidRtcpStream,

    //STUN errors
    #[error("attribute not found")]
    ErrAttributeNotFound,
    #[error("transaction is stopped")]
    ErrTransactionStopped,
    #[error("transaction not exists")]
    ErrTransactionNotExists,
    #[error("transaction exists with same id")]
    ErrTransactionExists,
    #[error("agent is closed")]
    ErrAgentClosed,
    #[error("transaction is timed out")]
    ErrTransactionTimeOut,
    #[error("no default reason for ErrorCode")]
    ErrNoDefaultReason,
    #[error("unexpected EOF")]
    ErrUnexpectedEof,
    #[error("attribute size is invalid")]
    ErrAttributeSizeInvalid,
    #[error("attribute size overflow")]
    ErrAttributeSizeOverflow,
    #[error("attempt to decode to nil message")]
    ErrDecodeToNil,
    #[error("unexpected EOF: not enough bytes to read header")]
    ErrUnexpectedHeaderEof,
    #[error("integrity check failed")]
    ErrIntegrityMismatch,
    #[error("fingerprint check failed")]
    ErrFingerprintMismatch,
    #[error("FINGERPRINT before MESSAGE-INTEGRITY attribute")]
    ErrFingerprintBeforeIntegrity,
    #[error("bad UNKNOWN-ATTRIBUTES size")]
    ErrBadUnknownAttrsSize,
    #[error("invalid length of IP value")]
    ErrBadIpLength,
    #[error("no connection provided")]
    ErrNoConnection,
    #[error("client is closed")]
    ErrClientClosed,
    #[error("no agent is set")]
    ErrNoAgent,
    #[error("collector is closed")]
    ErrCollectorClosed,
    #[error("unsupported network")]
    ErrUnsupportedNetwork,
    #[error("invalid url")]
    ErrInvalidUrl,
    #[error("unknown scheme type")]
    ErrSchemeType,
    #[error("invalid hostname")]
    ErrHost,

    // DTLS errors
    #[error("conn is closed")]
    ErrConnClosed,
    #[error("read/write timeout")]
    ErrDeadlineExceeded,
    #[error("context is not supported for export_keying_material")]
    ErrContextUnsupported,
    #[error("packet is too short")]
    ErrDtlspacketInvalidLength,
    #[error("handshake is in progress")]
    ErrHandshakeInProgress,
    #[error("invalid content type")]
    ErrInvalidContentType,
    #[error("invalid mac")]
    ErrInvalidMac,
    #[error("packet length and declared length do not match")]
    ErrInvalidPacketLength,
    #[error("export_keying_material can not be used with a reserved label")]
    ErrReservedExportKeyingMaterial,
    #[error("client sent certificate verify but we have no certificate to verify")]
    ErrCertificateVerifyNoCertificate,
    #[error("client+server do not support any shared cipher suites")]
    ErrCipherSuiteNoIntersection,
    #[error("server hello can not be created without a cipher suite")]
    ErrCipherSuiteUnset,
    #[error("client sent certificate but did not verify it")]
    ErrClientCertificateNotVerified,
    #[error("server required client verification, but got none")]
    ErrClientCertificateRequired,
    #[error("server responded with SRTP Profile we do not support")]
    ErrClientNoMatchingSrtpProfile,
    #[error("client required Extended Master Secret extension, but server does not support it")]
    ErrClientRequiredButNoServerEms,
    #[error("server hello can not be created without a compression method")]
    ErrCompressionMethodUnset,
    #[error("client+server cookie does not match")]
    ErrCookieMismatch,
    #[error("cookie must not be longer then 255 bytes")]
    ErrCookieTooLong,
    #[error("PSK Identity Hint provided but PSK is nil")]
    ErrIdentityNoPsk,
    #[error("no certificate provided")]
    ErrInvalidCertificate,
    #[error("cipher spec invalid")]
    ErrInvalidCipherSpec,
    #[error("invalid or unknown cipher suite")]
    ErrInvalidCipherSuite,
    #[error("unable to determine if ClientKeyExchange is a public key or PSK Identity")]
    ErrInvalidClientKeyExchange,
    #[error("invalid or unknown compression method")]
    ErrInvalidCompressionMethod,
    #[error("ECDSA signature contained zero or negative values")]
    ErrInvalidEcdsasignature,
    #[error("invalid or unknown elliptic curve type")]
    ErrInvalidEllipticCurveType,
    #[error("invalid extension type")]
    ErrInvalidExtensionType,
    #[error("invalid hash algorithm")]
    ErrInvalidHashAlgorithm,
    #[error("invalid named curve")]
    ErrInvalidNamedCurve,
    #[error("invalid private key type")]
    ErrInvalidPrivateKey,
    #[error("named curve and private key type does not match")]
    ErrNamedCurveAndPrivateKeyMismatch,
    #[error("invalid server name format")]
    ErrInvalidSniFormat,
    #[error("invalid signature algorithm")]
    ErrInvalidSignatureAlgorithm,
    #[error("expected and actual key signature do not match")]
    ErrKeySignatureMismatch,
    #[error("Conn can not be created with a nil nextConn")]
    ErrNilNextConn,
    #[error("connection can not be created, no CipherSuites satisfy this Config")]
    ErrNoAvailableCipherSuites,
    #[error("connection can not be created, no SignatureScheme satisfy this Config")]
    ErrNoAvailableSignatureSchemes,
    #[error("no certificates configured")]
    ErrNoCertificates,
    #[error("no config provided")]
    ErrNoConfigProvided,
    #[error("client requested zero or more elliptic curves that are not supported by the server")]
    ErrNoSupportedEllipticCurves,
    #[error("unsupported protocol version")]
    ErrUnsupportedProtocolVersion,
    #[error("Certificate and PSK provided")]
    ErrPskAndCertificate,
    #[error("PSK and PSK Identity Hint must both be set for client")]
    ErrPskAndIdentityMustBeSetForClient,
    #[error("SRTP support was requested but server did not respond with use_srtp extension")]
    ErrRequestedButNoSrtpExtension,
    #[error("Certificate is mandatory for server")]
    ErrServerMustHaveCertificate,
    #[error("client requested SRTP but we have no matching profiles")]
    ErrServerNoMatchingSrtpProfile,
    #[error(
        "server requires the Extended Master Secret extension, but the client does not support it"
    )]
    ErrServerRequiredButNoClientEms,
    #[error("expected and actual verify data does not match")]
    ErrVerifyDataMismatch,
    #[error("handshake message unset, unable to marshal")]
    ErrHandshakeMessageUnset,
    #[error("invalid flight number")]
    ErrInvalidFlight,
    #[error("unable to generate key signature, unimplemented")]
    ErrKeySignatureGenerateUnimplemented,
    #[error("unable to verify key signature, unimplemented")]
    ErrKeySignatureVerifyUnimplemented,
    #[error("data length and declared length do not match")]
    ErrLengthMismatch,
    #[error("buffer not long enough to contain nonce")]
    ErrNotEnoughRoomForNonce,
    #[error("feature has not been implemented yet")]
    ErrNotImplemented,
    #[error("sequence number overflow")]
    ErrSequenceNumberOverflow,
    #[error("unable to marshal fragmented handshakes")]
    ErrUnableToMarshalFragmented,
    #[error("invalid state machine transition")]
    ErrInvalidFsmTransition,
    #[error("ApplicationData with epoch of 0")]
    ErrApplicationDataEpochZero,
    #[error("unhandled contentType")]
    ErrUnhandledContextType,
    #[error("context canceled")]
    ErrContextCanceled,
    #[error("empty fragment")]
    ErrEmptyFragment,
    #[error("Alert is Fatal or Close Notify")]
    ErrAlertFatalOrClose,
    #[error(
        "Fragment buffer overflow. New size {new_size} is greater than specified max {max_size}"
    )]
    ErrFragmentBufferOverflow { new_size: usize, max_size: usize },

    #[error("{0}")]
    Sec1(#[source] sec1::Error),
    #[error("{0}")]
    P256(#[source] P256Error),
    #[error("{0}")]
    RcGen(#[from] RcgenError),

    /// Error parsing a given PEM string.
    #[error("invalid PEM: {0}")]
    InvalidPEM(String),

    //SCTP errors
    #[error("raw is too small for a SCTP chunk")]
    ErrChunkHeaderTooSmall,
    #[error("not enough data left in SCTP packet to satisfy requested length")]
    ErrChunkHeaderNotEnoughSpace,
    #[error("chunk PADDING is non-zero at offset")]
    ErrChunkHeaderPaddingNonZero,
    #[error("chunk has invalid length")]
    ErrChunkHeaderInvalidLength,

    #[error("ChunkType is not of type ABORT")]
    ErrChunkTypeNotAbort,
    #[error("failed build Abort Chunk")]
    ErrBuildAbortChunkFailed,
    #[error("ChunkType is not of type COOKIEACK")]
    ErrChunkTypeNotCookieAck,
    #[error("ChunkType is not of type COOKIEECHO")]
    ErrChunkTypeNotCookieEcho,
    #[error("ChunkType is not of type ctError")]
    ErrChunkTypeNotCt,
    #[error("failed build Error Chunk")]
    ErrBuildErrorChunkFailed,
    #[error("failed to marshal stream")]
    ErrMarshalStreamFailed,
    #[error("chunk too short")]
    ErrChunkTooShort,
    #[error("ChunkType is not of type ForwardTsn")]
    ErrChunkTypeNotForwardTsn,
    #[error("ChunkType is not of type HEARTBEAT")]
    ErrChunkTypeNotHeartbeat,
    #[error("ChunkType is not of type HEARTBEATACK")]
    ErrChunkTypeNotHeartbeatAck,
    #[error("heartbeat is not long enough to contain Heartbeat Info")]
    ErrHeartbeatNotLongEnoughInfo,
    #[error("failed to parse param type")]
    ErrParseParamTypeFailed,
    #[error("heartbeat should only have HEARTBEAT param")]
    ErrHeartbeatParam,
    #[error("failed unmarshalling param in Heartbeat Chunk")]
    ErrHeartbeatChunkUnmarshal,
    #[error("unimplemented")]
    ErrUnimplemented,
    #[error("heartbeat Ack must have one param")]
    ErrHeartbeatAckParams,
    #[error("heartbeat Ack must have one param, and it should be a HeartbeatInfo")]
    ErrHeartbeatAckNotHeartbeatInfo,
    #[error("unable to marshal parameter for Heartbeat Ack")]
    ErrHeartbeatAckMarshalParam,

    #[error("raw is too small for error cause")]
    ErrErrorCauseTooSmall,

    #[error("unhandled ParamType")]
    ErrParamTypeUnhandled,

    #[error("unexpected ParamType")]
    ErrParamTypeUnexpected,

    #[error("param header too short")]
    ErrParamHeaderTooShort,
    #[error("param self reported length is shorter than header length")]
    ErrParamHeaderSelfReportedLengthShorter,
    #[error("param self reported length is longer than header length")]
    ErrParamHeaderSelfReportedLengthLonger,
    #[error("failed to parse param type")]
    ErrParamHeaderParseFailed,

    #[error("packet to short")]
    ErrParamPacketTooShort,
    #[error("outgoing SSN reset request parameter too short")]
    ErrSsnResetRequestParamTooShort,
    #[error("reconfig response parameter too short")]
    ErrReconfigRespParamTooShort,
    #[error("invalid algorithm type")]
    ErrInvalidAlgorithmType,

    #[error("failed to parse param type")]
    ErrInitChunkParseParamTypeFailed,
    #[error("failed unmarshalling param in Init Chunk")]
    ErrInitChunkUnmarshalParam,
    #[error("unable to marshal parameter for INIT/INITACK")]
    ErrInitAckMarshalParam,

    #[error("ChunkType is not of type INIT")]
    ErrChunkTypeNotTypeInit,
    #[error("chunk Value isn't long enough for mandatory parameters exp")]
    ErrChunkValueNotLongEnough,
    #[error("ChunkType of type INIT flags must be all 0")]
    ErrChunkTypeInitFlagZero,
    #[error("failed to unmarshal INIT body")]
    ErrChunkTypeInitUnmarshalFailed,
    #[error("failed marshaling INIT common data")]
    ErrChunkTypeInitMarshalFailed,
    #[error("ChunkType of type INIT ACK InitiateTag must not be 0")]
    ErrChunkTypeInitInitiateTagZero,
    #[error("INIT ACK inbound stream request must be > 0")]
    ErrInitInboundStreamRequestZero,
    #[error("INIT ACK outbound stream request must be > 0")]
    ErrInitOutboundStreamRequestZero,
    #[error("INIT ACK Advertised Receiver Window Credit (a_rwnd) must be >= 1500")]
    ErrInitAdvertisedReceiver1500,

    #[error("packet is smaller than the header size")]
    ErrChunkPayloadSmall,
    #[error("ChunkType is not of type PayloadData")]
    ErrChunkTypeNotPayloadData,
    #[error("ChunkType is not of type Reconfig")]
    ErrChunkTypeNotReconfig,
    #[error("ChunkReconfig has invalid ParamA")]
    ErrChunkReconfigInvalidParamA,

    #[error("failed to parse param type")]
    ErrChunkParseParamTypeFailed,
    #[error("unable to marshal parameter A for reconfig")]
    ErrChunkMarshalParamAReconfigFailed,
    #[error("unable to marshal parameter B for reconfig")]
    ErrChunkMarshalParamBReconfigFailed,

    #[error("ChunkType is not of type SACK")]
    ErrChunkTypeNotSack,
    #[error("SACK Chunk size is not large enough to contain header")]
    ErrSackSizeNotLargeEnoughInfo,

    #[error("invalid chunk size")]
    ErrInvalidChunkSize,
    #[error("ChunkType is not of type SHUTDOWN")]
    ErrChunkTypeNotShutdown,

    #[error("ChunkType is not of type SHUTDOWN-ACK")]
    ErrChunkTypeNotShutdownAck,
    #[error("ChunkType is not of type SHUTDOWN-COMPLETE")]
    ErrChunkTypeNotShutdownComplete,

    #[error("raw is smaller than the minimum length for a SCTP packet")]
    ErrPacketRawTooSmall,
    #[error("unable to parse SCTP chunk, not enough data for complete header")]
    ErrParseSctpChunkNotEnoughData,
    #[error("failed to unmarshal, contains unknown chunk type")]
    ErrUnmarshalUnknownChunkType,
    #[error("checksum mismatch theirs")]
    ErrChecksumMismatch,

    #[error("unexpected chunk popped (unordered)")]
    ErrUnexpectedChuckPoppedUnordered,
    #[error("unexpected chunk popped (ordered)")]
    ErrUnexpectedChuckPoppedOrdered,
    #[error("unexpected q state (should've been selected)")]
    ErrUnexpectedQState,
    #[error("try again")]
    ErrTryAgain,

    #[error("abort chunk, with following errors: {0}")]
    ErrAbortChunk(String),
    #[error("shutdown called in non-Established state")]
    ErrShutdownNonEstablished,
    #[error("association closed before connecting")]
    ErrAssociationClosedBeforeConn,
    #[error("association init failed")]
    ErrAssociationInitFailed,
    #[error("association handshake closed")]
    ErrAssociationHandshakeClosed,
    #[error("silently discard")]
    ErrSilentlyDiscard,
    #[error("the init not stored to send")]
    ErrInitNotStoredToSend,
    #[error("cookieEcho not stored to send")]
    ErrCookieEchoNotStoredToSend,
    #[error("sctp packet must not have a source port of 0")]
    ErrSctpPacketSourcePortZero,
    #[error("sctp packet must not have a destination port of 0")]
    ErrSctpPacketDestinationPortZero,
    #[error("init chunk must not be bundled with any other chunk")]
    ErrInitChunkBundled,
    #[error("init chunk expects a verification tag of 0 on the packet when out-of-the-blue")]
    ErrInitChunkVerifyTagNotZero,
    #[error("todo: handle Init when in state")]
    ErrHandleInitState,
    #[error("no cookie in InitAck")]
    ErrInitAckNoCookie,
    #[error("there already exists a stream with identifier")]
    ErrStreamAlreadyExist,
    #[error("Failed to create a stream with identifier")]
    ErrStreamCreateFailed,
    #[error("unable to be popped from inflight queue TSN")]
    ErrInflightQueueTsnPop,
    #[error("requested non-existent TSN")]
    ErrTsnRequestNotExist,
    #[error("sending reset packet in non-Established state")]
    ErrResetPacketInStateNotExist,
    #[error("unexpected parameter type")]
    ErrParameterType,
    #[error("sending payload data in non-Established state")]
    ErrPayloadDataStateNotExist,
    #[error("unhandled chunk type")]
    ErrChunkTypeUnhandled,
    #[error("handshake failed (INIT ACK)")]
    ErrHandshakeInitAck,
    #[error("handshake failed (COOKIE ECHO)")]
    ErrHandshakeCookieEcho,

    #[error("outbound packet larger than maximum message size")]
    ErrOutboundPacketTooLarge,
    #[error("Stream closed")]
    ErrStreamClosed,
    #[error("Stream not existed")]
    ErrStreamNotExisted,
    #[error("Short buffer to be filled")]
    ErrShortBuffer,
    #[error("Io EOF")]
    ErrEof,
    #[error("Invalid SystemTime")]
    ErrInvalidSystemTime,
    #[error("Net Conn read error")]
    ErrNetConnRead,
    #[error("Max Data Channel ID")]
    ErrMaxDataChannelID,

    //#[error("mpsc send: {0}")]
    //MpscSend(String),
    #[error("aes gcm: {0}")]
    AesGcm(#[from] aes_gcm::Error),

    //#[error("parse ipnet: {0}")]
    //ParseIpnet(#[from] ipnet::AddrParseError),
    #[error("parse ip: {0}")]
    ParseIp(#[from] net::AddrParseError),
    #[error("parse int: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("{0}")]
    Io(#[source] IoError),
    #[error("url parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("utf8: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("{0}")]
    Std(#[source] StdError),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn from_std<T>(error: T) -> Self
    where
        T: std::error::Error + Send + Sync + 'static,
    {
        Error::Std(StdError(Box::new(error)))
    }

    pub fn downcast_ref<T: std::error::Error + 'static>(&self) -> Option<&T> {
        if let Error::Std(s) = self {
            return s.0.downcast_ref();
        }

        None
    }
}

#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(IoError(e))
    }
}

/// An escape hatch to preserve stack traces when we don't know the error.
///
/// This crate exports some traits such as `Conn` and `Listener`. The trait functions
/// produce the local error `util::Error`. However when used in crates higher up the stack,
/// we are forced to handle errors that are local to that crate. For example we use
/// `Listener` the `dtls` crate and it needs to handle `dtls::Error`.
///
/// By using `util::Error::from_std` we can preserve the underlying error (and stack trace!).
#[derive(Debug, Error)]
#[error("{0}")]
pub struct StdError(pub Box<dyn std::error::Error + Send + Sync>);

impl PartialEq for StdError {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        Error::PoisonError(e.to_string())
    }
}

impl From<sec1::Error> for Error {
    fn from(e: sec1::Error) -> Self {
        Error::Sec1(e)
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct P256Error(#[source] p256::elliptic_curve::Error);

impl PartialEq for P256Error {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl From<p256::elliptic_curve::Error> for Error {
    fn from(e: p256::elliptic_curve::Error) -> Self {
        Error::P256(P256Error(e))
    }
}

impl From<block_modes::InvalidKeyIvLength> for Error {
    fn from(e: block_modes::InvalidKeyIvLength) -> Self {
        Error::Other(e.to_string())
    }
}
impl From<block_modes::BlockModeError> for Error {
    fn from(e: block_modes::BlockModeError) -> Self {
        Error::Other(e.to_string())
    }
}