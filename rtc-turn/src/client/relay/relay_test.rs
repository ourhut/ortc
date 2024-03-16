use std::net::Ipv4Addr;

use super::*;
use shared::error::Result;

struct DummyRelayConnObserver {
    turn_server_addr: String,
    username: Username,
    realm: Realm,
}

#[test]
fn test_relay() -> Result<()> {
    let obs = DummyRelayConnObserver {
        turn_server_addr: String::new(),
        username: Username::new(ATTR_USERNAME, "username".to_owned()),
        realm: Realm::new(ATTR_REALM, "realm".to_owned()),
    };

    let (_read_ch_tx, read_ch_rx) = mpsc::channel(100);

    let config = RelayConfig {
        relayed_addr: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
        integrity: MessageIntegrity::default(),
        nonce: Nonce::new(ATTR_NONCE, "nonce".to_owned()),
        lifetime: Duration::from_secs(0),
        binding_mgr: Arc::new(Mutex::new(BindingManager::new())),
        read_ch_rx: Arc::new(Mutex::new(read_ch_rx)),
    };

    let rc = Relay::new(Arc::new(Mutex::new(obs)), config).await;

    let rci = rc.relay_conn.lock().await;
    let (bind_addr, bind_number) = {
        let mut bm = rci.binding_mgr.lock().await;
        let b = bm
            .create(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 1234))
            .unwrap();
        (b.addr, b.number)
    };

    //let binding_mgr = Arc::clone(&rci.binding_mgr);
    let rc_obs = Arc::clone(&rci.obs);
    let nonce = rci.nonce.clone();
    let integrity = rci.integrity.clone();

    if let Err(err) =
        RelayConnInternal::bind(rc_obs, bind_addr, bind_number, nonce, integrity).await
    {
        assert!(Error::ErrUnexpectedResponse != err);
    } else {
        panic!("should fail");
    }

    Ok(())
}
