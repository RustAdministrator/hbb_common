use hbb_common::{
    message_proto::{PublicKey, SignedId},
    protobuf::Message,
};

#[test]
fn handshake_caps_and_host_ack_round_trip() {
    let mut key = PublicKey::new();
    key.asymmetric_value = vec![1; 32].into();
    key.symmetric_value = vec![2; 48].into();
    key.handshake_caps = 1;
    let decoded = PublicKey::parse_from_bytes(&key.write_to_bytes().unwrap()).unwrap();
    assert_eq!(decoded.handshake_caps, 1);
    assert_eq!(decoded.asymmetric_value.to_vec(), vec![1; 32]);

    let mut id = SignedId::new();
    id.id = vec![3; 10].into();
    id.host_ack_mac = vec![4; 32].into();
    let decoded = SignedId::parse_from_bytes(&id.write_to_bytes().unwrap()).unwrap();
    assert_eq!(decoded.host_ack_mac.to_vec(), vec![4; 32]);
    assert_eq!(decoded.id.to_vec(), vec![3; 10]);
}

#[test]
fn messages_from_older_peers_decode_with_empty_new_fields() {
    // Encoded without the new fields, as an older peer would send them.
    let mut old_key = PublicKey::new();
    old_key.asymmetric_value = vec![9; 32].into();
    let bytes = old_key.write_to_bytes().unwrap();
    let decoded = PublicKey::parse_from_bytes(&bytes).unwrap();
    assert_eq!(decoded.handshake_caps, 0);

    let mut old_id = SignedId::new();
    old_id.id = vec![7; 4].into();
    let decoded = SignedId::parse_from_bytes(&old_id.write_to_bytes().unwrap()).unwrap();
    assert!(decoded.host_ack_mac.is_empty());
}
