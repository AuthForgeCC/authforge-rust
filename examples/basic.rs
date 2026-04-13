use authforge::{AuthForgeClient, AuthForgeConfig, HeartbeatMode};

fn main() {
    let client = AuthForgeClient::new(AuthForgeConfig {
        app_id: "your-app-id".into(),
        app_secret: "your-app-secret".into(),
        heartbeat_mode: HeartbeatMode::Server,
        on_failure: Some(Box::new(|err| {
            eprintln!("Auth failed: {}", err);
            std::process::exit(1);
        })),
        ..Default::default()
    });

    match client.login("XXXX-XXXX-XXXX-XXXX") {
        Ok(result) => println!("Authenticated! Expires: {}", result.expires_in),
        Err(e) => eprintln!("Login failed: {:?}", e)
    }
}
