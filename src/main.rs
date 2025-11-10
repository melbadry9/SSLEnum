use clap::{value_t, App, Arg};
use futures::stream::{FuturesUnordered, StreamExt};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use openssl_probe;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io as stdio;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Semaphore};
use tokio::task;
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
struct DomainData {
    hostname: String,
    ip: String,
    port: String,
    org: String,
    cn: Vec<String>,
    alt_names: Vec<String>,
    dangling: bool,
}

// Extract CN/ORG/SANs from X509
fn get_values_from_cert(cert: &X509) -> (Vec<String>, String, Vec<String>) {
    let mut cn = Vec::new();
    let mut org = String::new();
    let mut alt = Vec::new();

    // Try getting organization from subject
    for entry in cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
    {
        if let Ok(data) = entry.data().as_utf8() {
            org = data.to_string();
            break;
        }
    }

    // If org is empty, try getting it from issuer
    if org.is_empty() {
        for entry in cert
            .issuer_name()
            .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
        {
            if let Ok(data) = entry.data().as_utf8() {
                org = data.to_string();
                break;
            }
        }
    }

    // Try organizational unit from subject if still empty
    if org.is_empty() {
        for entry in cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::ORGANIZATIONALUNITNAME)
        {
            if let Ok(data) = entry.data().as_utf8() {
                org = data.to_string();
                break;
            }
        }
    }

    // Try organizational unit from issuer if still empty
    if org.is_empty() {
        for entry in cert
            .issuer_name()
            .entries_by_nid(openssl::nid::Nid::ORGANIZATIONALUNITNAME)
        {
            if let Ok(data) = entry.data().as_utf8() {
                org = data.to_string();
                break;
            }
        }
    }

    // Get CN (Common Name)
    for entry in cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
    {
        if let Ok(data) = entry.data().as_utf8() {
            cn.push(data.to_string());
        }
    }

    // Get Subject Alternative Names
    if let Some(san) = cert.subject_alt_names() {
        for name in san.iter() {
            if let Some(dns) = name.dnsname() {
                alt.push(dns.to_string());
            } else if let Some(uri) = name.uri() {
                if let Ok(url) = Url::parse(uri) {
                    if let Some(host) = url.domain() {
                        alt.push(host.to_string());
                    }
                }
            }
        }
    }

    (cn, org, alt)
}

fn cert_matches_domain(domain: &str, cn: &[String], alt: &[String]) -> bool {
    fn is_match(name: &str, domain: &str) -> bool {
        name.eq_ignore_ascii_case(domain)
            || domain.eq_ignore_ascii_case(name)
            || domain.ends_with(&format!(".{}", name))
    }

    cn.iter()
        .chain(alt.iter())
        .any(|name| is_match(name, domain))
}

fn blocking_probe_domain(
    domain: &str,
    port: &str,
    connector: Arc<SslConnector>,
    per_ip_timeout: Duration,
) -> Vec<DomainData> {
    let mut results: Vec<DomainData> = Vec::new();
    let addr_string = format!("{}:{}", domain, port);
    let addrs_iter = match addr_string.to_socket_addrs() {
        Ok(a) => a.collect::<Vec<SocketAddr>>(),
        Err(_) => return results,
    };

    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    for addr in addrs_iter {
        let tcp = match TcpStream::connect_timeout(&addr, per_ip_timeout) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let _ = tcp.set_read_timeout(Some(per_ip_timeout));
        let _ = tcp.set_write_timeout(Some(per_ip_timeout));

        let ssl_stream = connector.connect(domain, tcp);
        let ssl_stream = match ssl_stream {
            Ok(s) => s,
            Err(_) => continue,
        };

        let cert_opt = ssl_stream.ssl().peer_certificate();
        let cert = match cert_opt {
            Some(c) => c,
            None => continue,
        };

        let der = match cert.to_der() {
            Ok(d) => d,
            Err(_) => continue,
        };

        if !seen.insert(der.clone()) {
            continue;
        }

        let (cn, org, alt) = get_values_from_cert(&cert);
        let matches = cert_matches_domain(domain, &cn, &alt);
        let dangling = !matches;

        results.push(DomainData {
            hostname: domain.to_string(),
            ip: addr.ip().to_string(),
            port: port.to_string(),
            org,
            cn,
            alt_names: alt,
            dangling,
        });
    }
    results
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> stdio::Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    {
        // Works on all Unix-like systems
        openssl_probe::init_ssl_cert_env_vars();
    }

    #[cfg(any(target_os = "windows", target_os = "netbsd", target_os = "openbsd"))]
    unsafe {
        // Some Windows builds of openssl-probe expose only this
        if let Err(_) = std::panic::catch_unwind(|| {
            // Wrap in catch_unwind in case the symbol doesn't exist
            openssl_probe::init_openssl_env_vars();
        }) {
            // Fallback
            openssl_probe::init_ssl_cert_env_vars();
        }
    }

    let args = App::new("SSLEnum [SSL Data Enumeration]")
        .version("2.0.0")
        .author("Mohamed Elbadry")
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("THREADS")
                .help("Concurrent blocking probes")
                .takes_value(true)
                .default_value("200"),
        )
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .value_name("DOMAIN")
                .takes_value(true)
                .help("Single domain to test"),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .takes_value(true)
                .default_value("443"),
        )
        .arg(
            Arg::with_name("out")
                .short("o")
                .long("out")
                .value_name("FILE")
                .help("Write results to JSONL file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("timeout")
                .short("T")
                .long("timeout")
                .value_name("SECS")
                .help("Per-IP connect/read/write timeout in seconds")
                .takes_value(true)
                .default_value("1"),
        )
        .get_matches();

    let max_threads = value_t!(args.value_of("threads"), usize).unwrap_or(200);
    let port = args.value_of("port").unwrap().to_string();

    let mut builder = SslConnector::builder(SslMethod::tls()).expect("builder");
    builder.set_verify(SslVerifyMode::NONE);
    let connector = Arc::new(builder.build());

    // ✅ Wrap file in Mutex<Arc<File>> for safe concurrent writes
    let out_file = if let Some(path) = args.value_of("out") {
        let file: tokio::fs::File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Some(Arc::new(Mutex::new(file)))
    } else {
        None
    };

    let sem = Arc::new(Semaphore::new(max_threads));
    let per_ip_secs = value_t!(args.value_of("timeout"), u64).unwrap_or(1);
    let per_ip_timeout = Duration::from_secs(per_ip_secs);

    async fn spawn_probe_task(
        sem: Arc<Semaphore>,
        connector: Arc<SslConnector>,
        domain: String,
        port: String,
        per_ip_timeout: Duration,
    ) -> Vec<DomainData> {
        let permit = sem.acquire_owned().await.unwrap();
        task::spawn_blocking(move || {
            let _p = permit;
            blocking_probe_domain(&domain, &port, connector, per_ip_timeout)
        })
        .await
        .unwrap_or_default()
    }

    // Single-domain mode
    if let Some(domain) = args.value_of("domain") {
        let res = spawn_probe_task(
            sem.clone(),
            connector.clone(),
            domain.to_string(),
            port.clone(),
            per_ip_timeout,
        )
        .await;

        if let Some(f) = &out_file {
            let mut file = f.lock().await;
            for entry in res {
                let json = serde_json::to_string(&entry).unwrap();
                let _ = file.write_all(json.as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
        } else {
            for entry in res {
                println!("{}", serde_json::to_string(&entry).unwrap());
            }
        }
        return Ok(());
    }

    // Bulk mode
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut tasks = FuturesUnordered::new();

    while let Ok(Some(line)) = lines.next_line().await {
        let domain = line.trim().to_string();
        if domain.is_empty() {
            continue;
        }

        let sem_c = sem.clone();
        let connector_c = connector.clone();
        let port_c = port.clone();

        let fut = spawn_probe_task(sem_c, connector_c, domain, port_c, per_ip_timeout);
        tasks.push(fut);

        if tasks.len() >= max_threads {
            if let Some(res_vec) = tasks.next().await {
                if let Some(file) = &out_file {
                    let mut file = file.lock().await;
                    for entry in res_vec {
                        let json = serde_json::to_string(&entry).unwrap();
                        let _ = file.write_all(json.as_bytes()).await;
                        let _ = file.write_all(b"\n").await;
                    }
                } else {
                    for entry in res_vec {
                        println!("{}", serde_json::to_string(&entry).unwrap());
                    }
                }
            }
        }
    }

    while let Some(res_vec) = tasks.next().await {
        if let Some(file) = &out_file {
            let mut file = file.lock().await;
            for entry in res_vec {
                let json = serde_json::to_string(&entry).unwrap();
                let _ = file.write_all(json.as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
        } else {
            for entry in res_vec {
                println!("{}", serde_json::to_string(&entry).unwrap());
            }
        }
    }

    Ok(())
}
