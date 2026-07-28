<p align="center">
  <img src="https://github.com/erebe/turbine_lb/raw/main/turbine_logo_small.png" alt="turbine logo"/>
</p>


# Features

* TCP, TLS and UDP load-balancing
* TLS sni inspection for routing (without terminating TLS)
* TLS termination with KTLS
* "zero-copy" using splice syscall (TCP/TLS)
* per-client UDP session tracking with idle timeout
* support proxy protocol v2 (TCP/TLS)
* auto reload config and certificate
* linux only


config example at https://github.com/erebe/turbine_lb/blob/main/config.yaml
