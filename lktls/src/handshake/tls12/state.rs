use super::{
    prf, PrfAlgorithm, Result, ServerExtensions, Tls12CipherSuite, Tls12KeyExchange, Tls12State,
    Tls12TrafficKeys, TranscriptHash,
};
use crate::crypto::kx::KxGroup;
use crate::session_store::ticket::Tls12Ticket;

/// Data needed only until a ServerHello selects the transcript algorithm.
#[derive(Default)]
pub(super) struct Initial {
    pub(super) client_hello: Vec<u8>,
    pub(super) resumption: Option<Resumption>,
}

/// Unknown values occur only at the explicitly legacy low-level API boundary.
pub(super) struct Resumption {
    pub(super) required_session_id: Option<Vec<u8>>,
    pub(super) master_secret: Vec<u8>,
    pub(super) used_ems: Option<bool>,
    pub(super) suite: Option<Tls12CipherSuite>,
}

pub(super) struct Negotiated {
    pub(super) session_id: Vec<u8>,
    pub(super) suite: Tls12CipherSuite,
    pub(super) server_random: [u8; 32],
    pub(super) extensions: ServerExtensions,
}

impl Negotiated {
    pub(super) fn prf(&self) -> PrfAlgorithm {
        self.suite.prf_algorithm()
    }

    pub(super) fn traffic_keys(
        &self,
        secret: &[u8],
        client_random: &[u8; 32],
    ) -> Result<Tls12TrafficKeys> {
        let keys = prf::expand_key_block(
            self.prf(),
            secret,
            &self.server_random,
            client_random,
            self.suite.mac_key_len(),
            self.suite.enc_key_len(),
            self.suite.fixed_iv_len(),
        )?;
        Ok(Tls12TrafficKeys {
            cipher_suite: self.suite,
            client_write_key: keys.client_write_key,
            server_write_key: keys.server_write_key,
            client_write_iv: keys.client_write_iv,
            server_write_iv: keys.server_write_iv,
            client_write_mac_key: keys.client_write_mac_key,
            server_write_mac_key: keys.server_write_mac_key,
        })
    }
}

pub(super) enum PeerIdentity {
    Verified(Vec<Vec<u8>>),
    Insecure(Vec<Vec<u8>>),
    Resumed,
}

impl PeerIdentity {
    pub(super) fn certificates(&self) -> &[Vec<u8>] {
        match self {
            Self::Verified(certs) | Self::Insecure(certs) => certs,
            Self::Resumed => &[],
        }
    }
}

pub(super) enum Exchange {
    Rsa,
    Ecdhe { group: KxGroup, public_key: Vec<u8> },
}

pub(super) enum ServerFlightStep {
    Certificate,
    CertificateOrResume(Resumption),
    ResumeAfterTicket {
        resumption: Resumption,
        ticket: Tls12Ticket,
    },
    CertificateStatus(PeerIdentity),
    KeyExchange(PeerIdentity),
    RequestOrDone {
        peer: PeerIdentity,
        exchange: Exchange,
    },
    Done {
        peer: PeerIdentity,
        exchange: Exchange,
    },
}

pub(super) struct ServerFlight {
    pub(super) negotiated: Negotiated,
    pub(super) transcript: TranscriptHash,
    pub(super) step: ServerFlightStep,
}

pub(super) struct Established {
    pub(super) negotiated: Negotiated,
    pub(super) peer: PeerIdentity,
    pub(super) master_secret: Vec<u8>,
    pub(super) ticket: Option<Tls12Ticket>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FinishStep {
    FullAwaitTicket,
    FullAwaitCcs,
    FullAwaitFinished,
    ResumedAwaitFinished,
}

pub(super) struct Finishing {
    pub(super) connection: Established,
    pub(super) transcript: TranscriptHash,
    pub(super) step: FinishStep,
}

/// Every phase owns its mandatory transcript, negotiated values and secrets.
pub(super) enum Phase {
    Initial(Initial),
    ServerFlight(ServerFlight),
    Finishing(Finishing),
    Connected(Established),
    Failed(Tls12State),
}

impl Phase {
    pub(super) fn public_view(&self) -> Tls12State {
        match self {
            Self::Initial(_) => Tls12State::WaitServerHello,
            Self::ServerFlight(flight) => match &flight.step {
                ServerFlightStep::Certificate => Tls12State::WaitCertificate,
                ServerFlightStep::CertificateOrResume(_)
                | ServerFlightStep::ResumeAfterTicket { .. } => {
                    Tls12State::WaitCertificateOrAbbreviated
                }
                ServerFlightStep::CertificateStatus(_)
                    if flight.negotiated.suite.key_exchange() == Tls12KeyExchange::Rsa =>
                {
                    Tls12State::WaitServerHelloDone
                }
                ServerFlightStep::CertificateStatus(_) | ServerFlightStep::KeyExchange(_) => {
                    Tls12State::WaitServerKeyExchange
                }
                ServerFlightStep::RequestOrDone { .. } | ServerFlightStep::Done { .. } => {
                    Tls12State::WaitServerHelloDone
                }
            },
            Self::Finishing(finish) => match finish.step {
                FinishStep::FullAwaitTicket | FinishStep::FullAwaitCcs => {
                    Tls12State::WaitServerChangeCipherSpec
                }
                _ => Tls12State::WaitServerFinished,
            },
            Self::Connected(_) => Tls12State::Connected,
            Self::Failed(previous) => *previous,
        }
    }

    pub(super) fn negotiated(&self) -> Option<&Negotiated> {
        match self {
            Self::ServerFlight(flight) => Some(&flight.negotiated),
            Self::Finishing(finish) => Some(&finish.connection.negotiated),
            Self::Connected(connection) => Some(&connection.negotiated),
            _ => None,
        }
    }

    pub(super) fn established(&self) -> Option<&Established> {
        match self {
            Self::Finishing(finish) => Some(&finish.connection),
            Self::Connected(connection) => Some(connection),
            _ => None,
        }
    }

    pub(super) fn certificates(&self) -> &[Vec<u8>] {
        match self {
            Self::ServerFlight(flight) => match &flight.step {
                ServerFlightStep::CertificateStatus(peer)
                | ServerFlightStep::KeyExchange(peer)
                | ServerFlightStep::RequestOrDone { peer, .. }
                | ServerFlightStep::Done { peer, .. } => peer.certificates(),
                _ => &[],
            },
            _ => self
                .established()
                .map_or(&[], |connection| connection.peer.certificates()),
        }
    }

    pub(super) fn transcript_mut(&mut self) -> Option<&mut TranscriptHash> {
        match self {
            Self::ServerFlight(flight) => Some(&mut flight.transcript),
            Self::Finishing(finish) => Some(&mut finish.transcript),
            _ => None,
        }
    }
}
