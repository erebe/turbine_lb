use crate::config::types::{BackendDiscovery, Config};
use crate::load_balancing_strategy::{Backend, LoadBalancingStrategy};
use crate::{tls, Rule, Upstream, LOCAL_ADDR_V4};
use anyhow::Context;
use nonempty::NonEmpty;
use notify::{EventKind, RecursiveMode, Watcher};
use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

pub mod types;

// FIXME: Remove expect
pub fn parse_config(config_path: &Path) -> anyhow::Result<HashMap<SocketAddr, Arc<Rule>>> {
    let config: Config = serde_yaml::from_reader(BufReader::new(File::open(config_path)?))?;
    let rules: HashMap<SocketAddr, Arc<Rule>> = config
        .rules
        .into_iter()
        .flat_map(|mut x| {
            let listen_addr = std::mem::replace(&mut x.listen_addr, NonEmpty::new(LOCAL_ADDR_V4));
            let ups = x.upstreams.into_iter().map(|u| {
                let tls_acceptor = if let Some(tls) = &u.tls {
                    let certs = tls::load_certificates_from_pem(&tls.certificate)
                        .expect("cannot load certificates");
                    let key = tls::load_private_key_from_file(&tls.private_key)
                        .expect("cannot load private key");
                    let alpns = tls.alpns.iter().map(|x| x.as_bytes().to_vec()).collect();
                    Some(
                        tls::tls_acceptor(certs, key, Some(alpns))
                            .expect("cannot create TLS acceptor"),
                    )
                } else {
                    None
                };
                let backends: Vec<Backend> = match &u.backends {
                    BackendDiscovery::Static(x) => {
                        x.into_iter().map(|x| Backend::new(x.addr)).collect()
                    }
                };

                Upstream {
                    backends: NonEmpty::from_vec(backends).expect("at least one backend"),
                    load_balancing: LoadBalancingStrategy::from(&u.load_balancing),
                    tls_acceptor,
                    cfg: u,
                }
            });

            let rule = Arc::new(Rule {
                protocol: x.protocol,
                upstreams: NonEmpty::from_vec(ups.collect()).expect("at least one upstream"),
            });

            listen_addr
                .into_iter()
                .map(move |addr| (addr, rule.clone()))
        })
        .collect();

    Ok(rules)
}

pub struct ConfigWatcher {
    inner: Arc<Mutex<ConfigWatcherInner>>,
}

struct ConfigWatcherInner {
    watcher: notify::PollWatcher,
    config_tx: mpsc::Sender<HashMap<SocketAddr, Arc<Rule>>>,
}

impl ConfigWatcher {
    pub fn new(
        config_path: PathBuf,
        config_tx: mpsc::Sender<HashMap<SocketAddr, Arc<Rule>>>,
    ) -> anyhow::Result<Self> {
        let watcher_config = notify::Config::default()
            .with_poll_interval(Duration::from_secs(1))
            .with_compare_contents(true);

        let watcher = notify::PollWatcher::new(|_| {}, watcher_config)?;
        let inner = ConfigWatcherInner { watcher, config_tx };
        let this = Self {
            inner: Arc::new(Mutex::new(inner)),
        };

        let mut watcher = notify::PollWatcher::new(
            {
                let config_path = config_path.clone();
                let inner = this.inner.clone();

                move |event: notify::Result<notify::Event>| {
                    if let Err(err) = Self::handle_event(event, &config_path, &inner) {
                        error!("Cannot handle config file change event: {:?}", err);
                    }
                }
            },
            watcher_config,
        )
        .with_context(|| "Cannot create configuration watcher")?;

        info!("Watching config file {} for changes", config_path.display());
        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;
        this.inner.lock().watcher = watcher;

        Ok(this)
    }

    fn handle_event(
        event: notify::Result<notify::Event>,
        config_path: &Path,
        this: &Arc<Mutex<ConfigWatcherInner>>,
    ) -> anyhow::Result<()> {
        let Ok(event) = event else {
            return Ok(());
        };
        match event.kind {
            EventKind::Access(_) | EventKind::Remove(_) => {
                return Ok(());
            }
            EventKind::Any | EventKind::Other => {
                return Ok(());
            }
            EventKind::Create(_) | EventKind::Modify(_) => {}
        };

        debug!("Reloading config due changes on file {:?}", event.paths);
        let config = match parse_config(config_path) {
            Ok(config) => config,
            Err(err) => {
                error!(
                    "Failed to reload configuration at {}: {:?}",
                    config_path.display(),
                    err
                );
                return Err(err);
            }
        };

        let watcher_config = notify::Config::default()
            .with_poll_interval(Duration::from_secs(1))
            .with_compare_contents(true);

        let mut watcher = notify::PollWatcher::new(
            {
                let config_path = config_path.to_path_buf();
                let inner = this.clone();

                move |event: notify::Result<notify::Event>| {
                    if let Err(err) = Self::handle_event(event, &config_path, &inner) {
                        error!("Cannot handle config file change event: {:?}", err);
                    }
                }
            },
            watcher_config,
        )
        .with_context(|| "Cannot create configuration watcher")?;

        let _ = watcher.watch(config_path, RecursiveMode::NonRecursive);
        let paths: BTreeSet<&Path> = config
            .values()
            .flat_map(|c| c.files_to_watch_for_reload())
            .collect();
        for path in paths {
            debug!("Watching {}", path.display());
            watcher.watch(path, RecursiveMode::NonRecursive)?;
        }

        {
            let mut lock = this.lock();
            let _ = lock.config_tx.blocking_send(config);
            lock.watcher = watcher;
        }

        Ok(())
    }
}
