use addr::parser::DnsName;
use addr::psl::List;
use clap::{value_t, App, Arg};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::stack::StackRef;
use openssl::x509::{X509Ref, X509};
use openssl_probe;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use threadpool::ThreadPool;

#[derive(Serialize, Deserialize, Debug)]
struct DomainData {
    hostname: String,
    ip: String,
    org: Vec<String>,
    cn: Vec<String>,
    alt_names: Vec<String>,
    dangling: bool,
}

impl DomainData {
    fn check_dangling(self: &mut Self) {
        let domain = List.parse_dns_name(self.hostname.as_str()).unwrap();
        let mut dns_names: Vec<String> = Vec::new();

        dns_names.extend(self.cn.clone());
        dns_names.extend(self.alt_names.clone());
 
        for cand in dns_names {
            let host = List.parse_dns_name(cand.as_str());
            match host {
                Ok(host) => {
                    let host_root = host.root();
                    match host_root {
                        Some(host_root) => {
                            if !(domain.root().unwrap() == host_root) {
                                self.dangling = true;
                            } else {
                                self.dangling = false;
                                break;
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
}

fn make_connection(domain: String, port: String) {
    let tmp_dom = domain.clone();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);

    let conn = connector.build();
    conn.configure()
        .unwrap()
        .use_server_name_indication(true)
        .verify_hostname(true);

    let con_string = format!("{}:{}", domain, &port);
    let con_addrs = con_string.to_socket_addrs();
    match con_addrs {
        Ok(con_addrs) => {
            for ip in con_addrs {
                let tt = TcpStream::connect_timeout(&ip, Duration::from_secs(2));
                let ex_cert = extract_ssl(&tt, &conn, &tmp_dom.as_str());
                match ex_cert {
                    Ok(ex_cert) => {
                        let cn = get_value("cn", &ex_cert);
                        let org = get_value("org", &ex_cert);
                        let alt_names = get_value("doms", &ex_cert);

                        let mut ch_domain = DomainData {
                            hostname: tmp_dom.to_string(),
                            ip: ip.ip().to_string(),
                            org,
                            cn,
                            alt_names,
                            dangling: false,
                        };
                        ch_domain.check_dangling();
                        let ser_domain = serde_json::to_string(&ch_domain).unwrap();

                        println!("{}", ser_domain);
                    }
                    Err(_) => {
                        //eprintln!("SSL/TLS not enabled on: {}:{}", &dom, &port);
                    }
                };
            }
        }
        Err(_) => {}
    }
}

fn extract_ssl(stream: &Result<TcpStream, std::io::Error>, conn: &SslConnector, domain: &str,) -> Result<X509, ()> {
    match stream {
        Ok(stream) => {
            let _ = stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let stream = conn.connect(&domain, stream);
            match stream {
                Ok(stream) => {
                    let cert_stack: &StackRef<X509> = stream.ssl().peer_cert_chain().unwrap();
                    let certs: Vec<X509> = cert_stack.iter().map(X509Ref::to_owned).collect();
                    Ok(certs[0].to_owned())
                }
                Err(_) => {
                    //eprintln!("{}", e.to_string());
                    Err(())
                }
            }
        }
        Err(_) => Err(()),
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
                println!("While parsing organization name: {}", &e);
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

fn main() {
    openssl_probe::init_ssl_cert_env_vars();

    let args = App::new("SSLEnum [SSL Data Enumeration]")
        .version("1.0.0")
        .author("Mohamed Elbadry <me@melbadry9.xyz>")
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("THREADS")
                .help("Sets number of threads")
                .takes_value(true)
                .default_value("5"),
        )
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .value_name("DOMAIN")
                .help("Sets domain to check")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("Sets port number")
                .takes_value(true)
                .default_value("443"),
        )
        .get_matches();

    if !(args.is_present("domain")) {
        let stream = io::stdin();
        let threads_num = value_t!(args.value_of("threads"), usize).unwrap_or(5);
        let pool = ThreadPool::new(threads_num);
        for domain in stream.lock().lines() {
            let tmp = args.value_of("port").unwrap().to_string().clone();
            pool.execute(move || make_connection(domain.unwrap(), tmp));
        }
        pool.join();
    } else {
        make_connection(
            args.value_of("domain").unwrap().to_string(),
            args.value_of("port").unwrap().to_string(),
        )
    }
}
