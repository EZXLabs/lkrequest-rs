use bytes::{Bytes, BytesMut};
use lkh2::codec::H2Codec;
use lkh2::engine::{H2Engine, H2Event};
use lkh2::frame::{DataFrame, H2Frame, HeadersFrame, SettingsFrame, SettingsParameter};
use lkh2::policy::ThresholdFlowControl;

fn feed(engine: &mut H2Engine, frame: H2Frame) -> (Vec<H2Event>, Vec<H2Frame>) {
    let mut input = BytesMut::new();
    H2Codec::new().encode(&frame, &mut input);
    engine.process(&mut input)
}

#[test]
fn firefox_receive_credit_is_independent_of_remote_send_window() {
    for peer_window in [65_535, 262_144, 1_048_576] {
        let (mut engine, _) = H2Engine::client_with_policies(
            &lkh2::profile::firefox_156_h2(),
            Box::new(ThresholdFlowControl::firefox()),
            None,
            None,
        );
        feed(
            &mut engine,
            H2Frame::Settings(SettingsFrame {
                ack: false,
                settings: vec![SettingsParameter {
                    id: 4,
                    value: peer_window,
                }],
            }),
        );
        let stream_id = engine.open_stream();
        engine.build_headers(
            stream_id,
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/"),
            ],
            true,
            None,
        );
        feed(
            &mut engine,
            H2Frame::Headers(HeadersFrame {
                stream_id,
                end_stream: false,
                end_headers: true,
                priority: None,
                padding: None,
                header_block: Bytes::from_static(&[0x88]),
            }),
        );
        let total = 131_073;
        let mut credit = 131_072;
        let mut received = 0;
        let mut updates = Vec::new();
        while received < total && credit > 0 {
            let length = credit.min(16_384).min(total - received);
            let (events, outbound) = feed(
                &mut engine,
                H2Frame::Data(DataFrame {
                    stream_id,
                    end_stream: received + length == total,
                    padding: None,
                    data: Bytes::from(vec![0; length]),
                }),
            );
            credit -= length;
            for event in events {
                if let H2Event::ResponseData { data, .. } = event {
                    received += data.len();
                }
            }
            for frame in outbound {
                if let H2Frame::WindowUpdate(update) = frame {
                    if update.stream_id == stream_id {
                        credit += update.increment as usize;
                        updates.push(update.increment);
                    }
                }
            }
        }
        assert_eq!(
            received, total,
            "peer window {peer_window} exhausted receive credit"
        );
        assert_eq!(updates, [65_536, 65_536]);
    }
}

#[test]
fn local_settings_ack_updates_receive_windows_without_touching_send_windows() {
    use lkh2::conn_state::ConnState;
    use lkh2::profile::{H2Setting, H2SettingId};
    let mut state = ConnState::client();
    let settings = |size| {
        [H2Setting {
            id: H2SettingId::InitialWindowSize,
            value: size,
        }]
    };
    let ack = SettingsFrame {
        ack: true,
        settings: Vec::new(),
    };
    state.apply_profile_settings(&settings(131_072));
    let id = state.open_stream();
    state.apply_remote_settings(&ack).unwrap();
    state
        .get_stream_mut(id)
        .unwrap()
        .consume_recv_window(1024)
        .unwrap();
    state.apply_profile_settings(&settings(262_144));
    state.apply_remote_settings(&ack).unwrap();
    state
        .apply_remote_settings(&SettingsFrame {
            ack: false,
            settings: vec![SettingsParameter {
                id: 4,
                value: 1_048_576,
            }],
        })
        .unwrap();
    let stream = state.get_stream(id).unwrap();
    assert_eq!(stream.recv_window(), 262_144 - 1024);
    assert_eq!(stream.initial_recv_window_size(), 262_144);
    assert_eq!(stream.send_window(), 1_048_576);
    assert_eq!(stream.initial_window_size(), 1_048_576);
}
