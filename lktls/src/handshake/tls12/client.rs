//! Client transitions consume phase data and produce the next valid owner.

use super::state::{
    Established, Exchange, FinishStep, Finishing, Initial, Negotiated, PeerIdentity, Resumption,
    ServerFlight, ServerFlightStep,
};
use super::*;

impl Tls12Handshake {
    /// Create a new TLS 1.2 handshake processor.
    ///
    /// `client_random` is the 32-byte random from the ClientHello we sent.
    /// `hostname` is the server name for certificate verification.
    pub fn new(
        client_random: [u8; 32],
        hostname: &str,
        verification_policy: VerificationPolicy,
    ) -> Self {
        Self {
            state: Phase::Initial(Initial::default()),
            client_random,
            hostname: hostname.to_owned(),
            verification_policy,
            custom_ca_anchors: None,
            offered_groups: None,
            offered_signature_algorithms: None,
            offered_extensions: None,
            offered_alpn_protocols: None,
            offered_cipher_suites: None,
            offered_compression_methods: None,
        }
    }

    /// Returns the ALPN protocol negotiated during the handshake (if any).
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.state.negotiated()?.extensions.alpn.as_deref()
    }

    /// The server's RFC 8449 `record_size_limit`, if the ServerHello carried one.
    ///
    /// `None` means the extension was not negotiated and records are chunked at
    /// the protocol maximum, exactly as if RFC 8449 did not exist.
    pub fn peer_record_size_limit(&self) -> Option<u16> {
        self.state.negotiated()?.extensions.record_size_limit
    }

    /// Returns the master secret (if computed).
    pub fn master_secret(&self) -> Option<&[u8]> {
        Some(&self.state.established()?.master_secret)
    }

    /// Returns the negotiated TLS 1.2 cipher suite (if ServerHello was processed).
    pub fn negotiated_cipher_suite(&self) -> Option<Tls12CipherSuite> {
        Some(self.state.negotiated()?.suite)
    }

    /// The server's certificate chain (DER, leaf first) from the Certificate
    /// message. Empty on an abbreviated (resumption) handshake.
    pub fn server_certificates(&self) -> &[Vec<u8>] {
        self.state.certificates()
    }

    /// Whether the server agreed to `extended_master_secret` (RFC 7627) for
    /// the session established by this handshake.
    ///
    /// Whoever stores a session ticket issued on this connection must record
    /// this alongside it: RFC 7627 §5.4 — "they need to differentiate between
    /// sessions that use legacy and extended master secrets by adding a flag
    /// to the session state" — and §5.3's abbreviated-handshake checks are
    /// unrunnable without it. Feed it back in through
    /// [`Self::set_session_ticket_resumption`] on the resuming handshake.
    pub fn used_extended_master_secret(&self) -> bool {
        self.state
            .negotiated()
            .is_some_and(|n| n.extensions.extended_master_secret)
    }

    /// Authentication order selected by this handshake, including resumption.
    pub fn cbc_mac_mode(&self) -> CbcMacMode {
        self.state
            .negotiated()
            .map_or(CbcMacMode::default(), |n| n.extensions.cbc_mac_mode)
    }

    /// Set the master secret from a stored session ticket for resumption.
    ///
    /// When set, the handshake will attempt abbreviated handshake (RFC 5077).
    /// If the server rejects the ticket (sends Certificate instead of CCS),
    /// the handshake falls back to full handshake automatically.
    ///
    /// The ticket's `extended_master_secret` state is left unknown, which
    /// disables the RFC 7627 §5.3 checks for this handshake. Prefer
    /// [`Self::set_session_ticket_resumption`], which carries it.
    pub fn set_session_ticket_master_secret(&mut self, master_secret: Vec<u8>) {
        self.set_session_ticket_resumption(master_secret, None);
    }

    /// Set up session-ticket resumption, carrying the original session's
    /// `extended_master_secret` (RFC 7627) state along with its master secret.
    ///
    /// `original_used_extended_master_secret` is what
    /// [`Self::used_extended_master_secret`] reported on the handshake that
    /// issued the ticket. `None` means the stored ticket predates that
    /// bookkeeping; the handshake then proceeds exactly as before, with the
    /// §5.3 checks skipped, because assuming either answer would be wrong:
    /// assuming `false` would abort every resumption against the (near
    /// universal) servers that do negotiate EMS, and assuming `true` would
    /// abort every resumption of a legacy non-EMS session.
    pub fn set_session_ticket_resumption(
        &mut self,
        master_secret: Vec<u8>,
        original_used_extended_master_secret: Option<bool>,
    ) {
        if let Phase::Initial(initial) = &mut self.state {
            initial.resumption = Some(Resumption {
                required_session_id: None,
                master_secret,
                used_ems: original_used_extended_master_secret,
                suite: None,
            });
        }
    }

    pub(crate) fn set_resumption_session(
        &mut self,
        session: crate::session_store::client::Tls12Session,
        session_id_only: bool,
    ) {
        if let Phase::Initial(initial) = &mut self.state {
            initial.resumption = Some(Resumption {
                required_session_id: session_id_only.then_some(session.session_id),
                master_secret: session.master_secret.to_vec(),
                used_ems: Some(session.used_ems),
                suite: Some(session.suite),
            });
        }
    }

    /// Set custom CA trust anchors (merged with Mozilla root store).
    pub fn set_custom_ca_anchors(
        &mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) {
        self.custom_ca_anchors = Some(anchors);
    }

    /// Whether the handshake is using abbreviated mode (session ticket resumption).
    ///
    /// Only valid after `process_server_hello()` has been called and the
    /// server accepted the session ticket.
    pub fn is_abbreviated(&self) -> bool {
        self.state
            .established()
            .is_some_and(|c| matches!(c.peer, PeerIdentity::Resumed))
    }

    /// Feed the original ClientHello bytes into the transcript.
    ///
    /// Must be called before processing any server messages.
    /// The bytes are also saved so we can re-hash if the ServerHello
    /// selects a cipher suite that requires SHA-384 instead of SHA-256.
    pub fn feed_client_hello(&mut self, ch_bytes: &[u8]) {
        if matches!(self.state, Phase::Initial(_)) {
            self.record_offer(ch_bytes);
            if let Phase::Initial(initial) = &mut self.state {
                initial.client_hello = ch_bytes.to_vec();
            }
        }
    }

    /// Current handshake state.
    pub fn state(&self) -> Tls12State {
        self.state.public_view()
    }

    /// Feed a raw handshake message into the transcript hash.
    ///
    /// Used for messages that arrive between our Client Finished and the
    /// server's CCS — typically NewSessionTicket (RFC 5077). These messages
    /// are not processed by the handshake state machine but must be included
    /// in the transcript for the server's Finished verification.
    pub fn feed_handshake_message(&mut self, msg_bytes: &[u8]) {
        if let Phase::Initial(initial) = &mut self.state {
            initial.client_hello.extend_from_slice(msg_bytes);
        } else if let Some(transcript) = self.state.transcript_mut() {
            transcript.update(msg_bytes);
        }
    }

    /// Notify the handshake that the server's ChangeCipherSpec has been received.
    ///
    /// Called by the connector after reading the CCS record (which is handled
    /// at the record layer, not the handshake layer).
    pub fn notify_server_ccs_received(&mut self) {
        let _ = self.receive_server_ccs();
    }

    pub(crate) fn receive_server_ccs(&mut self) -> Result<()> {
        self.transition(|_, state| {
            let Phase::Finishing(mut finish) = state else {
                return Err(unexpected("unexpected server ChangeCipherSpec"));
            };
            if finish.step != FinishStep::FullAwaitCcs {
                return Err(unexpected(
                    "unexpected ChangeCipherSpec or missing NewSessionTicket",
                ));
            }
            finish.step = FinishStep::FullAwaitFinished;
            Ok((Phase::Finishing(finish), ()))
        })
    }

    pub(crate) fn take_session(
        &mut self,
    ) -> Option<(crate::session_store::SessionTicketData, Vec<u8>)> {
        let Phase::Connected(connection) = &mut self.state else {
            return None;
        };
        let ticket = connection.ticket.take().or_else(|| {
            (!matches!(connection.peer, PeerIdentity::Resumed)
                && !connection.negotiated.session_id.is_empty())
            .then(crate::session_store::ticket::Tls12Ticket::session_id_only)
        })?;
        let ticket = ticket.into_session(
            &connection.master_secret,
            connection.negotiated.extensions.alpn.clone(),
            Some(connection.negotiated.suite),
            Some(connection.negotiated.extensions.extended_master_secret),
        );
        let session_id =
            if ticket.ticket.is_empty() && !matches!(connection.peer, PeerIdentity::Resumed) {
                connection.negotiated.session_id.clone()
            } else {
                Vec::new()
            };
        Some((ticket, session_id))
    }

    /// Process an incoming handshake record.
    ///
    /// The `record` is the raw handshake payload (after record-layer decapsulation).
    /// For TLS 1.2, handshake messages before CCS are not encrypted.
    pub fn process_handshake_record(&mut self, record: &[u8]) -> Result<Tls12HandshakeAction> {
        let result = (|| {
            if matches!(self.state, Phase::Failed(_)) {
                return Err(unexpected("handshake has failed"));
            }
            let mut messages = crate::handshake::framing::Messages::new(record);
            while let Some(message) = messages.next() {
                let message = message?;
                let action = self.transition(|this, state| this.advance(state, message))?;
                if !matches!(action, Tls12HandshakeAction::ContinueReading) {
                    if !messages.is_empty() {
                        return Err(unexpected(
                            "unexpected message after TLS 1.2 flight boundary",
                        ));
                    }
                    return Ok(action);
                }
            }
            Ok(Tls12HandshakeAction::ContinueReading)
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }

    /// Accept the abbreviated handshake when CCS is received from the server.
    ///
    /// Called by the connector when it receives a CCS record while in the
    /// `WaitCertificateOrAbbreviated` state. This confirms that the server
    /// accepted our session ticket.
    ///
    /// Returns the traffic keys derived from the restored master secret.
    /// The connector should install read keys, then read + verify server Finished.
    pub fn accept_abbreviated_ccs(&mut self) -> Result<Tls12TrafficKeys> {
        self.transition(|this, state| {
            let Phase::ServerFlight(ServerFlight {
                negotiated,
                transcript,
                step,
            }) = state
            else {
                return Err(unexpected("abbreviated CCS requires a pending resumption"));
            };
            let (resumption, ticket) = match step {
                ServerFlightStep::CertificateOrResume(resumption)
                    if !negotiated.extensions.session_ticket =>
                {
                    (resumption, None)
                }
                ServerFlightStep::ResumeAfterTicket { resumption, ticket } => {
                    (resumption, Some(ticket))
                }
                _ => {
                    return Err(unexpected(
                        "unexpected ChangeCipherSpec or missing NewSessionTicket",
                    ))
                }
            };
            if resumption
                .used_ems
                .is_some_and(|original| original != negotiated.extensions.extended_master_secret)
            {
                return Err(TlsError::local_alert(
                    AlertDescription::HandshakeFailure,
                    "resumed session EMS state differs from ServerHello",
                ));
            }
            if resumption
                .suite
                .is_some_and(|original| original != negotiated.suite)
            {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    "TLS 1.2 resumed cipher suite differs from the original session",
                ));
            }
            let keys = negotiated.traffic_keys(&resumption.master_secret, &this.client_random)?;
            let connection = Established {
                negotiated,
                peer: PeerIdentity::Resumed,
                master_secret: resumption.master_secret,
                ticket,
            };
            Ok((
                Phase::Finishing(Finishing {
                    connection,
                    transcript,
                    step: FinishStep::ResumedAwaitFinished,
                }),
                keys,
            ))
        })
    }

    /// Process the server's Finished message (after CCS, so it's encrypted).
    ///
    /// The caller decrypts the record and passes the plaintext here.
    pub fn process_server_finished(
        &mut self,
        finished_body: &[u8],
    ) -> Result<Tls12HandshakeAction> {
        self.finish_full(finished_body)?;
        self.compatibility_traffic_keys()
            .map(Tls12HandshakeAction::Complete)
    }

    /// Process the server's Finished in abbreviated handshake and compute
    /// the client Finished.
    ///
    /// Called after `accept_abbreviated_ccs()` + reading the encrypted server Finished.
    /// Returns the client Finished bytes and traffic keys for the connector to send.
    pub fn process_abbreviated_server_finished(
        &mut self,
        finished_body: &[u8],
    ) -> Result<Tls12AbbreviatedFlight> {
        let client_finished = self.finish_resumed(finished_body)?;
        Ok(Tls12AbbreviatedFlight {
            client_finished,
            traffic_keys: self.compatibility_traffic_keys()?,
        })
    }

    pub(crate) fn finish_full(&mut self, message: &[u8]) -> Result<()> {
        self.finish(message, FinishStep::FullAwaitFinished)
            .map(|_| ())
    }

    pub(crate) fn finish_resumed(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.finish(message, FinishStep::ResumedAwaitFinished)
    }

    fn compatibility_traffic_keys(&mut self) -> Result<Tls12TrafficKeys> {
        let result = self
            .state
            .established()
            .ok_or_else(|| unexpected("handshake is not complete"))
            .and_then(|c| {
                c.negotiated
                    .traffic_keys(&c.master_secret, &self.client_random)
            });
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn finish(&mut self, message: &[u8], required: FinishStep) -> Result<Vec<u8>> {
        self.transition(|_, state| {
            let Phase::Finishing(mut finish) = state else {
                return Err(unexpected("unexpected server Finished"));
            };
            if finish.step != required {
                return Err(unexpected(
                    "server Finished is in the wrong handshake flow or before CCS",
                ));
            }
            let verify_data = match message {
                [20, 0, 0, 12, rest @ ..] if rest.len() == 12 => rest,
                rest if rest.len() == 12 => rest,
                _ => {
                    return Err(crate::wire::decode_error(
                        "invalid TLS 1.2 Finished header or length",
                    ))
                }
            };
            let connection = finish.connection;
            let expected = prf::compute_verify_data(
                connection.negotiated.prf(),
                &connection.master_secret,
                "server finished",
                &finish.transcript.current_hash(),
            )?;
            aws_lc_rs::constant_time::verify_slices_are_equal(verify_data, &expected).map_err(
                |_| {
                    TlsError::local_alert(
                        AlertDescription::DecryptError,
                        "server Finished verify_data mismatch",
                    )
                },
            )?;
            let client_finished = if required == FinishStep::ResumedAwaitFinished {
                finish.transcript.update(&build_handshake_message(
                    handshake_type::FINISHED,
                    verify_data,
                ));
                let verify = prf::compute_verify_data(
                    connection.negotiated.prf(),
                    &connection.master_secret,
                    "client finished",
                    &finish.transcript.current_hash(),
                )?;
                build_handshake_message(handshake_type::FINISHED, &verify)
            } else {
                Vec::new()
            };
            Ok((Phase::Connected(connection), client_finished))
        })
    }

    fn transition<T>(
        &mut self,
        advance: impl FnOnce(&Self, Phase) -> Result<(Phase, T)>,
    ) -> Result<T> {
        let previous = self.state.public_view();
        let current = std::mem::replace(&mut self.state, Phase::Failed(previous));
        let (next, output) = advance(self, current)?;
        self.state = next;
        Ok(output)
    }

    fn fail(&mut self) {
        self.state = Phase::Failed(self.state.public_view());
    }

    fn advance(&self, state: Phase, message: &[u8]) -> Result<(Phase, Tls12HandshakeAction)> {
        let kind = message[0];
        let body = &message[4..];
        let flight = match state {
            Phase::Initial(initial) => {
                if kind != handshake_type::SERVER_HELLO {
                    return Err(unexpected("expected ServerHello"));
                }
                return self.server_hello(initial, body, message).map(|flight| {
                    (
                        Phase::ServerFlight(flight),
                        Tls12HandshakeAction::ContinueReading,
                    )
                });
            }
            Phase::ServerFlight(flight) => flight,
            Phase::Finishing(mut finish)
                if finish.step == FinishStep::FullAwaitTicket && kind == 4 =>
            {
                let ticket = crate::session_store::ticket::Tls12Ticket::parse_body(body)?;
                finish.connection.ticket = Some(ticket);
                finish.transcript.update(message);
                finish.step = FinishStep::FullAwaitCcs;
                return Ok((
                    Phase::Finishing(finish),
                    Tls12HandshakeAction::ContinueReading,
                ));
            }
            _ => return Err(unexpected("unexpected TLS 1.2 handshake message")),
        };
        let ServerFlight {
            negotiated,
            mut transcript,
            mut step,
        } = flight;
        // RFC 6066 section 8 permits omission even after the server acknowledges it.
        if kind != handshake_type::CERTIFICATE_STATUS {
            if let ServerFlightStep::CertificateStatus(peer) = step {
                step = after_certificate(peer, negotiated.suite);
            }
        }
        let step = match step {
            ServerFlightStep::CertificateOrResume(resumption) if kind == 4 => {
                if !negotiated.extensions.session_ticket {
                    return Err(unexpected("NewSessionTicket was not negotiated"));
                }
                let ticket = crate::session_store::ticket::Tls12Ticket::parse_body(body)?;
                ServerFlightStep::ResumeAfterTicket { resumption, ticket }
            }
            ServerFlightStep::ResumeAfterTicket { .. } => {
                return Err(unexpected(
                    "expected ChangeCipherSpec after NewSessionTicket",
                ))
            }
            ServerFlightStep::Certificate | ServerFlightStep::CertificateOrResume(_) => {
                if kind != handshake_type::CERTIFICATE {
                    return Err(unexpected("expected Certificate"));
                }
                let certificates = crate::wire::tls12::certificate_chain(body)?;
                self.verification_policy.verify_certificate_chain(
                    &certificates,
                    &self.hostname,
                    std::time::SystemTime::now(),
                    self.custom_ca_anchors.as_deref().map(|v| v.as_slice()),
                )?;
                let peer = if self.verification_policy.is_insecure() {
                    PeerIdentity::Insecure(certificates)
                } else {
                    PeerIdentity::Verified(certificates)
                };
                if negotiated.extensions.status_request {
                    ServerFlightStep::CertificateStatus(peer)
                } else {
                    after_certificate(peer, negotiated.suite)
                }
            }
            ServerFlightStep::CertificateStatus(peer) => {
                if kind != handshake_type::CERTIFICATE_STATUS {
                    return Err(unexpected("expected the negotiated CertificateStatus"));
                }
                crate::extensions::status_request::parse_certificate_status(body)?;
                after_certificate(peer, negotiated.suite)
            }
            ServerFlightStep::KeyExchange(peer) => {
                if kind != 12 {
                    return Err(unexpected("expected ServerKeyExchange"));
                }
                let exchange = self.server_key_exchange(&negotiated, &peer, body)?;
                ServerFlightStep::RequestOrDone { peer, exchange }
            }
            ServerFlightStep::RequestOrDone { peer, exchange } => {
                if kind == 13 {
                    crate::wire::tls12::certificate_request(body)?;
                    ServerFlightStep::Done { peer, exchange }
                } else if kind == 14 {
                    return self
                        .client_flight(negotiated, transcript, peer, exchange, false, message);
                } else {
                    return Err(unexpected("expected CertificateRequest or ServerHelloDone"));
                }
            }
            ServerFlightStep::Done { peer, exchange } => {
                if kind != 14 {
                    return Err(unexpected("expected ServerHelloDone"));
                }
                return self.client_flight(negotiated, transcript, peer, exchange, true, message);
            }
        };
        transcript.update(message);
        Ok((
            Phase::ServerFlight(ServerFlight {
                negotiated,
                transcript,
                step,
            }),
            Tls12HandshakeAction::ContinueReading,
        ))
    }

    fn server_hello(&self, initial: Initial, body: &[u8], message: &[u8]) -> Result<ServerFlight> {
        let mut reader = crate::wire::Reader::new(body);
        if reader.u16()? != 0x0303 {
            return Err(TlsError::local_alert(
                AlertDescription::ProtocolVersion,
                "unsupported TLS 1.2 server_version",
            ));
        }
        let server_random = reader.take(32)?.try_into().unwrap();
        let session_id = reader.vector8()?.to_vec();
        if session_id.len() > 32 {
            return Err(crate::wire::decode_error(
                "TLS 1.2 ServerHello session ID exceeds 32 bytes",
            ));
        }
        let code = reader.u16()?;
        let compression = reader.u8()?;
        if compression != 0
            || self
                .offered_compression_methods
                .as_ref()
                .is_some_and(|offered| !offered.contains(&compression))
        {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "TLS 1.2 server selected unsupported or unoffered compression",
            ));
        }
        if self
            .offered_cipher_suites
            .as_ref()
            .is_some_and(|offered| !offered.contains(&code))
        {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "TLS 1.2 server selected an unoffered cipher suite",
            ));
        }
        let suite = Tls12CipherSuite::from_code_point(code).ok_or_else(|| {
            TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!("unsupported TLS 1.2 cipher suite: 0x{code:04x}"),
            )
        })?;
        let extensions = ServerExtensions::parse(
            reader.remaining(),
            suite,
            self.offered_extensions.as_deref(),
            self.offered_alpn_protocols.as_deref(),
        )?;
        let negotiated = Negotiated {
            session_id,
            suite,
            server_random,
            extensions,
        };
        let mut transcript = TranscriptHash::new(negotiated.prf());
        transcript.update(&initial.client_hello);
        transcript.update(message);
        let step = match initial.resumption {
            Some(resumption)
                if resumption
                    .required_session_id
                    .as_ref()
                    .is_some_and(|id| id.is_empty() || id != &negotiated.session_id) =>
            {
                ServerFlightStep::Certificate
            }
            Some(resumption) => ServerFlightStep::CertificateOrResume(resumption),
            None => ServerFlightStep::Certificate,
        };
        Ok(ServerFlight {
            negotiated,
            transcript,
            step,
        })
    }

    fn server_key_exchange(
        &self,
        negotiated: &Negotiated,
        peer: &PeerIdentity,
        body: &[u8],
    ) -> Result<Exchange> {
        let parsed = crate::wire::tls12::EcdheServerKeyExchange::parse(body)?;
        if self
            .offered_groups
            .as_ref()
            .is_some_and(|groups| !groups.contains(&parsed.group))
        {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!(
                    "server selected ECDHE curve 0x{:04x}, which the client did not offer",
                    parsed.group
                ),
            ));
        }
        if self
            .offered_signature_algorithms
            .as_ref()
            .is_some_and(|schemes| !schemes.contains(&parsed.signature_algorithm))
        {
            return Err(TlsError::local_alert(AlertDescription::IllegalParameter, format!("server signed ServerKeyExchange with algorithm 0x{:04x}, which the client did not offer", parsed.signature_algorithm)));
        }
        if crate::verify::signature::tls12_authentication(parsed.signature_algorithm)
            != Some(negotiated.suite.descriptor().authentication)
        {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "ServerKeyExchange signature does not match the cipher suite authentication",
            ));
        }
        let group = KxGroup::from_code_point(parsed.group).ok_or_else(|| {
            TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "unsupported ECDHE curve",
            )
        })?;
        let certificate = peer
            .certificates()
            .first()
            .ok_or_else(|| unexpected("ServerKeyExchange requires a certificate"))?;
        let mut signed = Vec::with_capacity(64 + parsed.signed_params.len());
        signed.extend_from_slice(&self.client_random);
        signed.extend_from_slice(&negotiated.server_random);
        signed.extend_from_slice(parsed.signed_params);
        self.verification_policy
            .verify_server_key_exchange_signature(
                certificate,
                parsed.signature_algorithm,
                &signed,
                parsed.signature,
            )?;
        Ok(Exchange::Ecdhe {
            group,
            public_key: parsed.public_key.to_vec(),
        })
    }

    fn client_flight(
        &self,
        negotiated: Negotiated,
        mut transcript: TranscriptHash,
        peer: PeerIdentity,
        exchange: Exchange,
        client_auth: bool,
        hello_done: &[u8],
    ) -> Result<(Phase, Tls12HandshakeAction)> {
        crate::wire::Reader::new(&hello_done[4..]).finish()?;
        transcript.update(hello_done);
        let (pre_master_secret, client_key_exchange) = match exchange {
            Exchange::Ecdhe { group, public_key } => ecdhe_key_exchange(group, &public_key)?,
            Exchange::Rsa => rsa_key_exchange(peer.certificates())?,
        };
        let client_certificate =
            client_auth.then(|| build_handshake_message(handshake_type::CERTIFICATE, &[0, 0, 0]));
        if let Some(certificate) = &client_certificate {
            transcript.update(certificate);
        }
        transcript.update(&client_key_exchange);
        let master_secret = if negotiated.extensions.extended_master_secret {
            prf::compute_extended_master_secret(
                negotiated.prf(),
                &pre_master_secret,
                &transcript.current_hash(),
            )?
        } else {
            prf::compute_master_secret(
                negotiated.prf(),
                &pre_master_secret,
                &self.client_random,
                &negotiated.server_random,
            )?
        };
        let traffic_keys = negotiated.traffic_keys(&master_secret, &self.client_random)?;
        let verify = prf::compute_verify_data(
            negotiated.prf(),
            &master_secret,
            "client finished",
            &transcript.current_hash(),
        )?;
        let client_finished = build_handshake_message(handshake_type::FINISHED, &verify);
        transcript.update(&client_finished);
        let step = if negotiated.extensions.session_ticket {
            FinishStep::FullAwaitTicket
        } else {
            FinishStep::FullAwaitCcs
        };
        let connection = Established {
            negotiated,
            peer,
            master_secret,
            ticket: None,
        };
        let state = Phase::Finishing(Finishing {
            connection,
            transcript,
            step,
        });
        Ok((
            state,
            Tls12HandshakeAction::SendClientFlight(Tls12ClientFlight {
                client_certificate,
                client_key_exchange,
                client_finished,
                traffic_keys,
            }),
        ))
    }
}

fn after_certificate(peer: PeerIdentity, suite: Tls12CipherSuite) -> ServerFlightStep {
    match suite.key_exchange() {
        Tls12KeyExchange::Ecdhe => ServerFlightStep::KeyExchange(peer),
        Tls12KeyExchange::Rsa => ServerFlightStep::RequestOrDone {
            peer,
            exchange: Exchange::Rsa,
        },
    }
}

fn ecdhe_key_exchange(group: KxGroup, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = kx::generate_key_pair(group)?;
    let mut body = Vec::with_capacity(1 + key_pair.public_key.len());
    body.push(key_pair.public_key.len() as u8);
    body.extend_from_slice(&key_pair.public_key);
    let secret = kx::compute_shared_secret(key_pair, public_key)?;
    Ok((secret, build_handshake_message(16, &body)))
}

fn rsa_key_exchange(certificates: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<u8>)> {
    let certificate = certificates
        .first()
        .ok_or_else(|| unexpected("no server certificate for RSA key exchange"))?;
    let mut secret = vec![0; 48];
    secret[..2].copy_from_slice(&[3, 3]);
    aws_lc_rs::rand::SecureRandom::fill(&aws_lc_rs::rand::SystemRandom::new(), &mut secret[2..])
        .map_err(|_| TlsError::CryptoError("failed to generate RSA pre_master_secret".into()))?;
    let spki = crate::verify::certchain::extract_spki_from_cert(certificate)?;
    let public_key = aws_lc_rs::rsa::PublicEncryptingKey::from_der(spki).map_err(|_| {
        TlsError::CryptoError("failed to parse RSA public key from certificate".into())
    })?;
    let key = aws_lc_rs::rsa::Pkcs1PublicEncryptingKey::new(public_key)
        .map_err(|_| TlsError::CryptoError("failed to create PKCS1 encrypting key".into()))?;
    let mut encrypted = vec![0; key.ciphertext_size()];
    let encrypted = key.encrypt(&secret, &mut encrypted).map_err(|_| {
        TlsError::CryptoError("RSA PKCS1 encryption of pre_master_secret failed".into())
    })?;
    let mut body = Vec::with_capacity(2 + encrypted.len());
    body.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
    body.extend_from_slice(encrypted);
    Ok((secret, build_handshake_message(16, &body)))
}

fn unexpected(message: &str) -> TlsError {
    TlsError::local_alert(AlertDescription::UnexpectedMessage, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_store::ticket::Tls12Ticket;

    #[test]
    fn empty_renewed_ticket_does_not_turn_an_echo_into_a_session_id() {
        for resumed in [false, true] {
            let mut handshake =
                Tls12Handshake::new([0x42; 32], "localhost", VerificationPolicy::Insecure);
            handshake.state = Phase::Connected(Established {
                negotiated: Negotiated {
                    session_id: vec![0x37; 32],
                    suite: Tls12CipherSuite::from_code_point(0xc02f).unwrap(),
                    server_random: [0x24; 32],
                    extensions: Default::default(),
                },
                peer: if resumed {
                    PeerIdentity::Resumed
                } else {
                    PeerIdentity::Insecure(Vec::new())
                },
                master_secret: vec![0x5a; 48],
                ticket: Some(Tls12Ticket::parse_body(&[0, 0, 14, 16, 0, 0]).unwrap()),
            });
            let (ticket, session_id) = handshake.take_session().unwrap();
            assert!(ticket.ticket.is_empty());
            assert_eq!(session_id.is_empty(), resumed);
        }
    }
}
