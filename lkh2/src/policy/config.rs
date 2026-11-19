//! Versioned, data-only descriptions of supported HTTP/2 runtime policies.

use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct H2BehaviorConfig {
    pub version: u32,
    pub write: WritePolicyConfig,
    pub flow_control: FlowControlConfig,
    pub hpack: HpackPolicyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WritePolicyConfig {
    pub split_headers: bool,
    pub split_data: bool,
    pub max_data_frame_payload: Option<usize>,
    pub send_goaway_on_close: bool,
    pub separate_end_stream_data: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FlowControlConfig {
    Immediate,
    Threshold { ratio: f32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HpackPolicyConfig {
    Indexed,
    Chromium,
    Firefox,
    Safari,
    AdaptiveHuffman,
}

impl H2BehaviorConfig {
    /// Custom trait implementations must explicitly opt into a supported descriptor.
    pub fn from_behavior(behavior: &H2Behavior) -> Result<Self, &'static str> {
        Ok(Self {
            version: 1,
            write: behavior
                .write_policy
                .config()
                .ok_or("unserializable write policy")?,
            flow_control: behavior
                .flow_control
                .config()
                .ok_or("unserializable flow-control policy")?,
            hpack: behavior
                .hpack_policy
                .config()
                .ok_or("unserializable HPACK policy")?,
        })
    }

    pub fn build(&self) -> Result<H2Behavior, &'static str> {
        if self.version != 1 {
            return Err("unsupported H2 behavior version");
        }
        if self
            .write
            .max_data_frame_payload
            .is_some_and(|n| n == 0 || n > 0xff_ffff)
        {
            return Err("DATA payload cap must be in 1..16777215");
        }
        let flow_control: Box<dyn FlowControlPolicy> = match self.flow_control {
            FlowControlConfig::Immediate => Box::new(ImmediateFlowControl),
            FlowControlConfig::Threshold { ratio } => {
                if !ratio.is_finite() || !(0.1..=1.0).contains(&ratio) {
                    return Err("flow-control ratio must be in 0.1..1.0");
                }
                Box::new(ThresholdFlowControl::new(ratio))
            }
        };
        let hpack_policy: Box<dyn HpackEncodePolicy> = match self.hpack {
            HpackPolicyConfig::Indexed => Box::new(DefaultHpackPolicy),
            HpackPolicyConfig::Chromium => Box::new(ChromeHpackPolicy),
            HpackPolicyConfig::Firefox => Box::new(FirefoxHpackPolicy),
            HpackPolicyConfig::Safari => Box::new(SafariHpackPolicy),
            HpackPolicyConfig::AdaptiveHuffman => Box::new(AdaptiveHuffmanPolicy),
        };
        Ok(H2Behavior {
            write_policy: Box::new(ConfigurableWritePolicy {
                split_headers: self.write.split_headers,
                split_data: self.write.split_data,
                max_data_frame_payload: self.write.max_data_frame_payload,
                send_goaway_on_close: self.write.send_goaway_on_close,
                separate_end_stream_data: self.write.separate_end_stream_data,
            }),
            flow_control,
            hpack_policy,
        })
    }
}

#[derive(Debug, Clone)]
struct AdaptiveHuffmanPolicy;

impl HpackEncodePolicy for AdaptiveHuffmanPolicy {
    fn encoding_for(&self, _name: &str, value: &str) -> HpackFieldEncoding {
        HpackFieldEncoding::IncrementalIndexing {
            huffman_value: crate::hpack::huffman_encoded_len(value.as_bytes()) < value.len(),
        }
    }

    fn config(&self) -> Option<HpackPolicyConfig> {
        Some(HpackPolicyConfig::AdaptiveHuffman)
    }

    fn box_clone(&self) -> Box<dyn HpackEncodePolicy> {
        Box::new(self.clone())
    }
}
