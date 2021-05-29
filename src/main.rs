use addr::parser::DnsName;
use addr::psl::List;
use clap::{App, Arg};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::stack::StackRef;
use openssl::x509::X509Ref;
use openssl::x509::X509;
use openssl_probe;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};
use std::net::TcpStream;
use threadpool::ThreadPool;

#[derive(Serialize, Deserialize, Debug)]
struct DomainData {
    name: String,
    org: Vec<String>,
    cn: Vec<String>,
    alt_doms: Vec<String>,
    dangling: bool,
}

impl DomainData {
    fn check_dangling(self: &mut Self) {
        let domain = List.parse_dns_name(self.name.as_str()).unwrap();
        let host = List.parse_dns_name(self.cn[0].as_str());
        match host {
            Ok(host) => {
                let host_root = host.root();
                match host_root {
                    Some(host_root) => {
                        if !(domain.root().unwrap() == host_root) {
                            self.dangling = true;
                        }
                    }
                    None => {
                        self.dangling = true;
                    }
                }
            }
            Err(_) => {
                self.dangling = false;
            }
        }
    }
}

fn extract_ssl(domain: &String) -> Result<X509, ()> {
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    let conn = connector.build();

    conn.configure()
        .unwrap()
        .use_server_name_indication(true)
        .verify_hostname(true);

    let con_string = format!("{}:443", &domain);
    let stream = TcpStream::connect(con_string);
    match stream {
        Ok(stream) => {
            let stream = conn.connect(&domain, stream).unwrap();
            let cert_stack: &StackRef<X509> = stream.ssl().peer_cert_chain().unwrap();
            let certs: Vec<X509> = cert_stack.iter().map(X509Ref::to_owned).collect();
            Ok(certs[0].to_owned())
        }
        Err(_err) => Err(()),
    }
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
    match ex_cert {
        Ok(ex_cert) => {
            let cn = get_value("cn", &ex_cert);
            let org = get_value("org", &ex_cert);
            let alt_doms = get_value("doms", &ex_cert);

            let mut ch_domain = DomainData {
                name: dom,
                org: org,
                cn: cn,
                alt_doms: alt_doms,
                dangling: false,
            };
            ch_domain.check_dangling();
            let ser_domain = serde_json::to_string(&ch_domain).unwrap();

            println!("{}", ser_domain);
        },
        Err(_) => {eprintln!("")}
    }
}

fn main() {
    openssl_probe::init_ssl_cert_env_vars();

    let args = App::new("SSLEnum recon tool")
        .version("0.1")
        .author("Mohamed Elbadry <me@melbadry9.xyz>")
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("THREADS")
                .help("Sets number of threads")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .value_name("DOMAIN")
                .help("Sets domain to check")
                .takes_value(true),
        )
        .get_matches();

    if !(args.is_present("domain")) {
        let stream = io::stdin();
        let pool = ThreadPool::new(
            args.value_of("threads")
                .unwrap_or("3")
                .parse::<usize>()
                .unwrap_or(5),
        );
        for domain in stream.lock().lines() {
            pool.execute(|| logic(domain.unwrap().to_string()));
        }
        pool.join();
    } else {
        logic(args.value_of("domain").unwrap().to_string())
    }
}
