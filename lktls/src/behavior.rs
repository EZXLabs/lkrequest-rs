//! Client wire reactions, independent of transport scheduling.

use crate::error::AlertDescription;
use crate::profile::types::TlsClientHelloStyle;

#[derive(Clone, Copy)]
pub(crate) struct ClientBehavior(pub(crate) TlsClientHelloStyle);

impl ClientBehavior {
    pub(crate) fn key_update_limit(self) -> Option<u8> {
        (self.0 == TlsClientHelloStyle::ChromiumBoringssl).then_some(32)
    }

    pub(crate) fn invalid_key_update(self) -> AlertDescription {
        match self.0 {
            TlsClientHelloStyle::ChromiumBoringssl | TlsClientHelloStyle::FirefoxNss => {
                AlertDescription::DecodeError
            }
            _ => AlertDescription::IllegalParameter,
        }
    }

    pub(crate) fn respond_to_key_update(
        self,
        pending_output: bool,
        unused_write_key: bool,
    ) -> bool {
        match self.0 {
            TlsClientHelloStyle::ChromiumBoringssl => !pending_output,
            TlsClientHelloStyle::FirefoxNss => !unused_write_key,
            _ => true,
        }
    }

    pub(crate) fn flush_key_update(self) -> bool {
        self.0 == TlsClientHelloStyle::FirefoxNss
    }

    pub(crate) fn defer_idle_key_update(self) -> bool {
        self.0 == TlsClientHelloStyle::ChromiumBoringssl
    }

    pub(crate) fn browser_close_notify(self) -> bool {
        self.0 != TlsClientHelloStyle::ChromiumBoringssl
    }
}
