use libp2p_gossipsub::metrics::Config;
use libp2p_gossipsub::{Gossipsub, GossipsubConfig, MessageAuthenticity};
use prometheus_client::registry::Registry;

#[test]
fn can_instantiate_protobuf_metrics() {
    let mut registry =
        Registry::<Box<dyn prometheus_client::encoding::proto::SendEncodeMetric>>::default();

    let result = Gossipsub::new_with_metrics(
        MessageAuthenticity::Anonymous,
        GossipsubConfig::default(),
        &mut registry,
        Config::default(),
    )
    .unwrap();
}
