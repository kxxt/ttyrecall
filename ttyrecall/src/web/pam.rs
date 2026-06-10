use pam::Client;

pub fn authenticate(service: &str, username: &str, password: &str) -> Result<(), String> {
    let mut client = Client::with_password(service).map_err(|err| err.to_string())?;
    client
        .conversation_mut()
        .set_credentials(username, password);
    client.authenticate().map_err(|err| err.to_string())?;
    Ok(())
}
