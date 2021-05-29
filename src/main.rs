use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::stack::StackRef;
use openssl::x509::X509Ref;
use openssl::x509::X509;
//use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use std::net::TcpStream;

#[derive(Serialize, Deserialize, Debug)]
struct DomainData {
    name: String,
    org: Vec<String>,
    cn: Vec<String>,
    alt_doms: Vec<String>,
    dangling: bool,
}

fn extract_ssl(domain: &String) -> X509 {
    let connector = SslConnector::builder(SslMethod::tls_client())
        .unwrap()
        .build();

    connector
        .configure()
        .unwrap()
        .use_server_name_indication(true)
        .verify_hostname(true);
    let con_string = format!("{}:443", &domain);
    let stream = TcpStream::connect(con_string).unwrap();
    let stream = connector.connect(&domain, stream).unwrap();

    let cert_stack: &StackRef<X509> = stream.ssl().peer_cert_chain().unwrap();
    let certs: Vec<X509> = cert_stack.iter().map(X509Ref::to_owned).collect();
    certs[0].to_owned()
}

fn get_value<R: AsRef<X509Ref>>(n: &str, cert: &R) -> Vec<String> {
    let cert = cert.as_ref();
    if n == "cn" {
        let try_common_names: Vec<_> = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .map(|x| x.data().as_utf8())
            .collect();

        let mut common_names: Vec<String> = Vec::with_capacity(try_common_names.len());
        for cn in try_common_names {
            if let Err(ref e) = cn {
                println!("While parsing common name: {}", &e);
            }
            common_names.push(String::from(AsRef::<str>::as_ref(&cn.unwrap())));
        }
        common_names
    } else if n == "org" {
        let org: Vec<_> = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
            .map(|x| x.data().as_utf8())
            .collect();

        let mut org_name: Vec<String> = Vec::with_capacity(org.len());
        for o in org {
            if let Err(ref e) = o {
                println!("While parsing orgnization name: {}", &e);
            }
            org_name.push(String::from(AsRef::<str>::as_ref(&o.unwrap())));
        }
        org_name
    } else {
        let mut names = Vec::new();
        // fixme: common names may not be host names.
        if let Some(san) = cert.subject_alt_names() {
            for name in san.iter() {
                if let Some(name) = name.dnsname() {
                    names.push(String::from(name));
                } else if let Some(uri) = name.uri() {
                    let url_parsed = reqwest::Url::parse(uri)
                        .map_err(|_| {
                            println!("This certificate has a URI SNI, but the URI is not parsable.")
                        })
                        .unwrap();
                    if let Some(host) = url_parsed.domain() {
                        names.push(String::from(host));
                    }
                }
            }
        }
        names
    }
}

fn logic(dom: String) {
    let ex_cert = extract_ssl(&dom);
    let cn = get_value("cn", &ex_cert);
    let org = get_value("org", &ex_cert);
    let alt_doms = get_value("doms", &ex_cert);
    let ch_domain = DomainData {
        name: dom,
        org: org,
        cn: cn,
        alt_doms: alt_doms,
        dangling: false,
    };
    let ser_domain = serde_json::to_string(&ch_domain).unwrap();
    println!("{:#?}", ser_domain);
}

fn main() {
    logic(String::from("15-06-25.dev6.slack.com"));
}
