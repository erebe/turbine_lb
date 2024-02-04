use crate::{create_socket, handle_client, Rule};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::log::warn;
use tracing::{error, field, info, instrument, span, Instrument, Level};

pub struct LBAppContext {
    pub shutdown_rx: oneshot::Receiver<()>,
    pub tasks_running: Arc<AtomicUsize>,
}

impl LBAppContext {
    pub fn new() -> (oneshot::Sender<()>, Self) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        (
            shutdown_tx,
            Self {
                shutdown_rx,
                tasks_running: Arc::new(AtomicUsize::new(0)),
            },
        )
    }

    pub async fn listen_config_change(
        &mut self,
        mut config_changes_rx: mpsc::Receiver<HashMap<SocketAddr, Arc<Rule>>>,
    ) {
        let mut listeners: HashMap<SocketAddr, watch::Sender<Arc<Rule>>> = HashMap::new();
        info!("Starting Load balancer");

        loop {
            let listeners_update = select! {
                biased;

                _ = &mut self.shutdown_rx => {
                    info!("Asked to shutdown. So shutting down event loop");
                    break;
                }

                ret = config_changes_rx.recv() => match ret {
                    Some(listeners_update) => listeners_update,
                    None => {
                        info!("Listeners config tx dropped. Cannot listen to change anymore, so exiting");
                        break;
                    }
                }
            };

            // Delete entries that not present anymore
            // Dropping the sender is going tell listener to shutdown
            info!("reloading configuration");
            listeners.retain(|k, _| listeners_update.contains_key(k));

            for (listen_addr, config) in listeners_update.into_iter() {
                match listeners.get(&listen_addr) {
                    None => {
                        // spawn the task, it is not present
                        let (config_tx, config_rx) = watch::channel(config);
                        listeners.insert(listen_addr, config_tx);
                        let mut runner = LBRunner {
                            listen_addr,
                            config_rx,
                            tasks_counter: self.tasks_running.clone(),
                        };

                        tokio::spawn(async move {
                            if let Err(err) = runner.run().await {
                                error!(
                                    "Listener {} exited abruptly: {:?}",
                                    runner.listen_addr, err
                                );
                            }
                        });
                    }
                    Some(config_tx) => {
                        // TODO: Look into send_if_modified to avoid triggering change at each config reload
                        config_tx.send_replace(config);
                    }
                }
            }
        }
    }
}

pub struct LBRunner {
    pub listen_addr: SocketAddr,
    pub config_rx: watch::Receiver<Arc<Rule>>,
    tasks_counter: Arc<AtomicUsize>,
}

impl LBRunner {
    #[instrument(level= "info", name = "lb", skip_all, fields(listen_addr = %self.listen_addr, protocol = ?self.config_rx.borrow().protocol))]
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let tcp_server = create_socket(self.listen_addr)?;
        tcp_server.listen(4096)?;
        let tcp_server = TcpListener::from_std(std::net::TcpListener::from(tcp_server))?;
        let mut rule = self.config_rx.borrow_and_update().clone();

        info!("starting");
        let _guard = scopeguard::guard((), |_| {
            info!("stopped");
        });

        loop {
            let (stream, peer_addr) = select! {
                biased;

                ret = self.config_rx.changed() => {
                    match ret {
                        Ok(_) => {
                            rule = self.config_rx.borrow_and_update().clone();
                            continue;
                        }
                        Err(_) => {
                            warn!("Asked to shutdown");
                            break;
                        }
                    }
                }

                ret = tcp_server.accept() => {
                    match ret {
                        Ok(cnx) => cnx,
                        Err(err) => {
                            // https://stackoverflow.com/questions/76955978/which-socket-accept-errors-are-fatal
                            error!("error accepting new connections: {:?}", err);
                            continue;
                        }
                    }
                }
            };

            let span = span!(
                //parent: Span::none(),
                Level::INFO,
                "cnx",
                peer = %peer_addr,
                upstream = field::Empty,
                upstream_addr = field::Empty,
                proxy = field::Empty,
                timeout = field::Empty
            );

            let rule = rule.clone();
            let task_counter = self.tasks_counter.clone();
            let proxied_client_loop = async move {
                task_counter.fetch_add(1, Ordering::Relaxed);
                let _guard = scopeguard::guard((), |_| {
                    task_counter.fetch_sub(1, Ordering::Relaxed);
                });

                if let Err(err) = handle_client(&rule, stream, peer_addr).await {
                    warn!("{:?}", err);
                }
            }
            .instrument(span);

            tokio::spawn(proxied_client_loop);
        }

        Ok(())
    }
}
