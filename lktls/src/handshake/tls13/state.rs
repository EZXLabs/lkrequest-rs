use super::{HkdfPrk, Tls13State, TranscriptHash};
use crate::crypto::suites::Tls13Suite;

#[derive(Clone, Copy)]
pub(super) struct Negotiated {
    pub(super) code: u16,
    pub(super) suite: &'static Tls13Suite,
}

pub(super) struct Retry {
    pub(super) negotiated: Negotiated,
    pub(super) transcript: TranscriptHash,
}

pub(super) struct Crypto {
    pub(super) negotiated: Negotiated,
    pub(super) transcript: TranscriptHash,
    pub(super) secret: HkdfPrk,
    pub(super) client_secret: Vec<u8>,
    pub(super) server_secret: Vec<u8>,
}

pub(super) struct CertificateFlight {
    pub(super) crypto: Crypto,
    pub(super) client_auth: Option<Vec<u8>>,
}

pub(super) struct CertificateVerify {
    pub(super) flight: CertificateFlight,
    pub(super) certificates: Vec<Vec<u8>>,
}

pub(super) enum PeerIdentity {
    Verified(Vec<Vec<u8>>),
    Insecure(Vec<Vec<u8>>),
    Resumed,
}

impl PeerIdentity {
    pub(super) fn into_certificates(self) -> Vec<Vec<u8>> {
        match self {
            Self::Verified(certificates) | Self::Insecure(certificates) => certificates,
            Self::Resumed => Vec::new(),
        }
    }
}

pub(super) struct Finished {
    pub(super) crypto: Crypto,
    pub(super) client_auth: Option<Vec<u8>>,
    pub(super) peer: PeerIdentity,
}

pub(super) enum Phase {
    Start,
    ServerHello(Option<Retry>),
    EncryptedExtensions(Crypto),
    Certificate(CertificateFlight),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    Connected,
    Failed(Tls13State),
}

impl Phase {
    pub(super) fn public_view(&self) -> Tls13State {
        match self {
            Self::Start => Tls13State::Start,
            Self::ServerHello(_) => Tls13State::WaitServerHello,
            Self::EncryptedExtensions(_) => Tls13State::WaitEncryptedExtensions,
            Self::Certificate(_) => Tls13State::WaitCertificate,
            Self::CertificateVerify(_) => Tls13State::WaitCertificateVerify,
            Self::Finished(_) => Tls13State::WaitFinished,
            Self::Connected => Tls13State::Connected,
            Self::Failed(previous) => *previous,
        }
    }

    pub(super) fn crypto(&self) -> Option<&Crypto> {
        match self {
            Self::EncryptedExtensions(crypto) => Some(crypto),
            Self::Certificate(flight) => Some(&flight.crypto),
            Self::CertificateVerify(verify) => Some(&verify.flight.crypto),
            Self::Finished(finish) => Some(&finish.crypto),
            _ => None,
        }
    }

    pub(super) fn transcript(&self) -> Option<&TranscriptHash> {
        match self {
            Self::ServerHello(Some(retry)) => Some(&retry.transcript),
            _ => self.crypto().map(|crypto| &crypto.transcript),
        }
    }
}
