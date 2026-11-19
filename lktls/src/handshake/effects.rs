use crate::error::{Result, TlsError};
use crate::record::reader::RecordReader;
use crate::record::writer::{RecordWriter, WriteStop};
use crate::record::{ReadKeys, WriteKeys};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Epoch {
    #[default]
    Plaintext,
    EarlyData,
    Handshake,
    // TLS 1.2 uses this same protected epoch from CCS through application data.
    Application,
}

/// Consumed in protocol order. Record bytes are committed before the next
/// effect can reset a direction's sequence number; transport flush is separate.
pub(super) enum RecordEffect<'a> {
    Emit {
        epoch: Epoch,
        content_type: u8,
        bytes: &'a [u8],
    },
    InstallRead {
        epoch: Epoch,
        keys: ReadKeys,
    },
    InstallWrite {
        epoch: Epoch,
        keys: WriteKeys,
    },
}

#[derive(Default)]
pub(super) struct RecordEffects {
    read: Epoch,
    write: Epoch,
}

impl RecordEffects {
    pub(super) fn apply(
        &mut self,
        effect: RecordEffect<'_>,
        reader: &mut RecordReader,
        writer: &mut RecordWriter,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        match effect {
            RecordEffect::Emit {
                epoch,
                content_type,
                bytes,
            } => {
                if epoch != self.write {
                    return Err(TlsError::HandshakeFailure(
                        "record effect has the wrong write epoch".into(),
                    ));
                }
                match writer
                    .write_into(content_type, bytes, output, 256 * 1024)
                    .stop
                {
                    WriteStop::Complete => {}
                    WriteStop::Terminal(error) => return Err(error),
                    WriteStop::NeedOutputCapacity => {
                        output.clear();
                        return Err(TlsError::HandshakeFailure(
                            "TLS handshake flight exceeds output budget".into(),
                        ));
                    }
                }
            }
            RecordEffect::InstallRead { epoch, keys } => {
                if reader.is_poisoned() {
                    return Err(poisoned());
                }
                check_transition(self.read, epoch)?;
                reader.install_keys(keys);
                self.read = epoch;
            }
            RecordEffect::InstallWrite { epoch, keys } => {
                if writer.is_poisoned() {
                    return Err(poisoned());
                }
                check_transition(self.write, epoch)?;
                writer.install_keys(keys);
                self.write = epoch;
            }
        }
        Ok(())
    }
}

fn check_transition(from: Epoch, to: Epoch) -> Result<()> {
    if matches!(
        (from, to),
        (
            Epoch::Plaintext,
            Epoch::EarlyData | Epoch::Handshake | Epoch::Application
        ) | (Epoch::EarlyData, Epoch::Handshake)
            | (Epoch::Handshake, Epoch::Application)
    ) {
        Ok(())
    } else {
        Err(TlsError::HandshakeFailure(
            "invalid record key epoch transition".into(),
        ))
    }
}

fn poisoned() -> TlsError {
    TlsError::CryptoError("cannot install keys after a terminal record failure".into())
}
