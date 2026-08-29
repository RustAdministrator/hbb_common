use hbb_common::{
    message_proto::{KeyEvent, KeyboardMode},
    protobuf::Message,
};

#[test]
fn scan_code_text_survives_key_event_round_trip() {
    let mut event = KeyEvent::new();
    event.set_seq("abc".to_owned());
    event.mode = KeyboardMode::Translate.into();
    event.scan_code_text = true;

    let encoded = event.write_to_bytes().expect("serialize key event");
    let decoded = KeyEvent::parse_from_bytes(&encoded).expect("parse key event");

    assert!(decoded.scan_code_text);
    assert_eq!(decoded.seq(), "abc");
    assert_eq!(decoded.mode.enum_value(), Ok(KeyboardMode::Translate));
}
