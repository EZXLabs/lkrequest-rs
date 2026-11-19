use std::time::Duration;

use lkh2::policy::H2BehaviorConfig;
use serde::{Deserialize, Serialize};

use crate::network_partition::TlsSessionCachePartitionPolicy;
use crate::protocol::{
    AcquisitionPolicy, FallbackPolicy, HttpIntent, ProtocolPolicy, RacePolicy, UpgradePolicy,
};

use super::document::{PresetError, PresetErrorCode};

/// The executable portion of a v2 profile bundle. Names never select policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetRuntime {
    pub version: u32,
    pub protocol: ProtocolConfig,
    pub tls_session_cache_partition: CachePartitionConfig,
    pub h2_behavior: H2BehaviorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolConfig {
    pub intent: IntentConfig,
    pub acquisition: AcquisitionConfig,
    pub upgrade: UpgradeConfig,
    pub fallback: FallbackConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentConfig {
    H2Only,
    H3Only,
    AcquireH3WhenViable,
    ReuseExistingProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcquisitionConfig {
    ReuseExistingFirst,
    EstablishBestAvailable,
    Race {
        enable_tcp: bool,
        enable_quic: bool,
        tcp_delay_ms: u64,
        quic_delay_ms: u64,
        only_when_h3_advertised: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeConfig {
    Off,
    ProbeOnly,
    ProbeAndMigrate,
    ForceForNewRequests,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackConfig {
    AllowFallback,
    AllowFallbackOnNetworkErrors,
    NoFallback,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePartitionConfig {
    Unpartitioned,
    TopLevelSite,
    TopLevelAndFrameSite,
    Chromium,
    Firefox,
}

macro_rules! mapping {
    ($from:ident, $to:ident, $($variant:ident),+ $(,)?) => {
        impl From<$from> for $to {
            fn from(value: $from) -> Self { match value { $($from::$variant => $to::$variant),+ } }
        }
    };
}
mapping!(
    IntentConfig,
    HttpIntent,
    H2Only,
    H3Only,
    AcquireH3WhenViable,
    ReuseExistingProtocol
);
mapping!(
    UpgradeConfig,
    UpgradePolicy,
    Off,
    ProbeOnly,
    ProbeAndMigrate,
    ForceForNewRequests
);
mapping!(
    FallbackConfig,
    FallbackPolicy,
    AllowFallback,
    AllowFallbackOnNetworkErrors,
    NoFallback
);
mapping!(
    FallbackPolicy,
    FallbackConfig,
    AllowFallback,
    AllowFallbackOnNetworkErrors,
    NoFallback
);
mapping!(
    CachePartitionConfig,
    TlsSessionCachePartitionPolicy,
    Unpartitioned,
    TopLevelSite,
    TopLevelAndFrameSite,
    Chromium,
    Firefox
);
mapping!(
    TlsSessionCachePartitionPolicy,
    CachePartitionConfig,
    Unpartitioned,
    TopLevelSite,
    TopLevelAndFrameSite,
    Chromium,
    Firefox
);

impl ProtocolConfig {
    pub fn build(&self) -> Result<ProtocolPolicy, PresetError> {
        let acquisition = match self.acquisition {
            AcquisitionConfig::ReuseExistingFirst => AcquisitionPolicy::ReuseExistingFirst,
            AcquisitionConfig::EstablishBestAvailable => AcquisitionPolicy::EstablishBestAvailable,
            AcquisitionConfig::Race {
                enable_tcp,
                enable_quic,
                tcp_delay_ms,
                quic_delay_ms,
                only_when_h3_advertised,
            } => {
                if tcp_delay_ms > 86_400_000 || quic_delay_ms > 86_400_000 {
                    return Err(PresetError::invalid(
                        "/runtime/protocol/acquisition",
                        "race delays must not exceed one day",
                    ));
                }
                AcquisitionPolicy::Race(RacePolicy {
                    enable_tcp,
                    enable_quic,
                    tcp_delay: Duration::from_millis(tcp_delay_ms),
                    quic_delay: Duration::from_millis(quic_delay_ms),
                    only_when_h3_advertised,
                })
            }
        };
        let policy = ProtocolPolicy::new(
            self.intent.into(),
            acquisition,
            self.upgrade.into(),
            self.fallback.into(),
        );
        policy
            .validate()
            .map_err(|e| PresetError::invalid("/runtime/protocol", e.to_string()))?;
        Ok(policy)
    }

    #[allow(deprecated)]
    pub fn from_policy(policy: &ProtocolPolicy) -> Result<Self, PresetError> {
        let intent = match policy.intent {
            HttpIntent::H2Only => IntentConfig::H2Only,
            HttpIntent::H3Only => IntentConfig::H3Only,
            HttpIntent::AcquireH3WhenViable | HttpIntent::PreferH3 => {
                IntentConfig::AcquireH3WhenViable
            }
            HttpIntent::ReuseExistingProtocol | HttpIntent::Auto => {
                IntentConfig::ReuseExistingProtocol
            }
        };
        let upgrade = match policy.upgrade {
            UpgradePolicy::Off | UpgradePolicy::Disabled => UpgradeConfig::Off,
            UpgradePolicy::ProbeOnly | UpgradePolicy::BackgroundProbe => UpgradeConfig::ProbeOnly,
            UpgradePolicy::ProbeAndMigrate | UpgradePolicy::BackgroundProbeAndMigrate => {
                UpgradeConfig::ProbeAndMigrate
            }
            UpgradePolicy::ForceForNewRequests | UpgradePolicy::ForceUpgradeForNewRequests => {
                UpgradeConfig::ForceForNewRequests
            }
        };
        let acquisition = match &policy.acquisition {
            AcquisitionPolicy::ReuseExistingFirst => AcquisitionConfig::ReuseExistingFirst,
            AcquisitionPolicy::EstablishBestAvailable => AcquisitionConfig::EstablishBestAvailable,
            AcquisitionPolicy::Race(race) => {
                let millis = |d: Duration| {
                    if !d.subsec_nanos().is_multiple_of(1_000_000) || d.as_millis() > 86_400_000 {
                        Err(PresetError::new(
                            PresetErrorCode::UnsupportedBehavior,
                            "/runtime/protocol/acquisition",
                            "race delay must be whole milliseconds within one day",
                        ))
                    } else {
                        Ok(d.as_millis() as u64)
                    }
                };
                AcquisitionConfig::Race {
                    enable_tcp: race.enable_tcp,
                    enable_quic: race.enable_quic,
                    tcp_delay_ms: millis(race.tcp_delay)?,
                    quic_delay_ms: millis(race.quic_delay)?,
                    only_when_h3_advertised: race.only_when_h3_advertised,
                }
            }
        };
        let config = Self {
            intent,
            acquisition,
            upgrade,
            fallback: policy.fallback.into(),
        };
        config.build()?;
        Ok(config)
    }
}
