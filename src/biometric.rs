use robius_authentication::{
    AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
};
use zeroize::Zeroizing;

const SERVICE: &str = "com.nouvfurx.locksmith";
const ACCOUNT: &str = "file-unlock-passphrase";

pub fn store_password(password: &[u8]) -> Result<(), String> {
    security_framework::passwords::set_generic_password(SERVICE, ACCOUNT, password)
        .map_err(|error| format!("Could not save the passphrase in Keychain: {error}"))
}

pub fn authenticate_and_load_password() -> Result<Zeroizing<Vec<u8>>, String> {
    let policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(false)
        .companion(false)
        .build()
        .ok_or_else(|| "Touch ID-only authentication is unavailable.".to_string())?;
    let prompt = Text {
        android: AndroidText {
            title: "Locksmith",
            subtitle: None,
            description: None,
        },
        apple: "unlock Locksmith files",
        windows: WindowsText::new_truncated("Locksmith", "Unlock your files with Touch ID"),
    };
    let (sender, receiver) = std::sync::mpsc::channel();
    Context::new(())
        .authenticate(prompt, &policy, move |result| {
            let _ = sender.send(result.map_err(|error| error.to_string()));
        })
        .map_err(|error| format!("Could not start Touch ID authentication: {error}"))?;
    receiver
        .recv()
        .map_err(|error| format!("Touch ID authentication ended unexpectedly: {error}"))?
        .map_err(|error| format!("Touch ID authentication failed: {error}"))?;

    security_framework::passwords::get_generic_password(SERVICE, ACCOUNT)
        .map(Zeroizing::new)
        .map_err(|error| format!("Touch ID could not unlock the saved passphrase: {error}"))
}

pub fn remove_password() -> Result<(), String> {
    security_framework::passwords::delete_generic_password(SERVICE, ACCOUNT)
        .map_err(|error| format!("Could not remove the saved Touch ID passphrase: {error}"))
}
