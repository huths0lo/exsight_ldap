extern crate openldap;

use dotenvy::dotenv;
use openldap::*;
use openldap::errors::*;
use std::env;


fn some_ldap_function(
    ldap_uri: &str,
    ldap_user: &str,
    ldap_pass: &str,
) -> Result<(), LDAPError> {
    let ldap = RustLDAP::new(ldap_uri)?;

    ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &codes::versions::LDAP_VERSION3);

    match ldap.simple_bind(ldap_user, ldap_pass) {
        Ok(_) => println!("Bind successful!"),
        Err(e) => {
            eprintln!("Bind failed: {:?}", e);
            return Err(e);
        }
    }

    let results = ldap.simple_search("CN=Users,DC=jpl,DC=nasa,DC=gov",codes::scopes::LDAP_SCOPE_BASE).unwrap();

    if results.is_empty() {
        println!("No entries found");
        return Ok(());
    }

    for entry in results {
        println!("DN: {}", entry.get("distinguishedName").unwrap_or(&vec!["<missing>".to_string()])[0]);
        if let Some(cn) = entry.get("cn") { println!("CN: {}", cn[0]); }
        if let Some(s_am) = entry.get("sAMAccountName") { println!("sAMAccountName: {}", s_am[0]); }
        if let Some(upn) = entry.get("userPrincipalName") { println!("userPrincipalName: {}", upn[0]); }
        if let Some(groups) = entry.get("memberOf") { println!("Member of groups: {:?}", groups); }
    }

    Ok(())
}


pub struct LDAPConfig {
    pub ldap_uri: String,
    pub ldap_user: String,
    pub ldap_pass: String,
}

fn get_env() -> Result<LDAPConfig, env::VarError> {
    dotenv().ok();

    let ldap_uri = env::var("LDAP_URI")?;
    let ldap_user = env::var("LDAP_USER")?;
    let ldap_pass = env::var("LDAP_PASS")?;

    Ok(LDAPConfig {
        ldap_uri,
        ldap_user,
        ldap_pass,
    })
}



fn main() -> Result<(), Box<dyn std::error::Error>> {

    let ldap_cfg = get_env()?;

    some_ldap_function(
        &ldap_cfg.ldap_uri,
        &ldap_cfg.ldap_user,
        &ldap_cfg.ldap_pass,
    )?;

    Ok(())
}