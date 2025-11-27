
![Repository Views](https://komarev.com/ghpvc/?username=qompassai-vongola)

# Vongola: A Securely performant reverse proxy server for your Deep Tech needs


# About

Qompass Vongola is your protective self-hosting "shell"—a proxy built in Rust, designed to keep your web services shielded while efficiently routing all requests. Just like a clam closes its shell to secure its contents, Vongola ensures that all  SSL, HTTP, and DNS traffic is handled with maximum safety and performance, protecting your infrastructure from the bad actors lurking in the deep waters of deep tech. 

Vongola uses [Pingora](https://github.com/cloudflare/pingora) as its core networking library.


# Features

Of the many features Vongola offers is the ability to load balance to your infrastructure or any IP that supports your host configurations. Other features of Vongola also include:

- Automatic Docker and Docker Swarm service discovery through labels
- Built-in most common middlewares such as OAuth, Rate Limiting, CDN Caching and others
- The ability of running it as a single binary in your system
- Automatic SSL through Let's Encrypt and redirection from HTTP to HTTPS
- Configuration through **HCL** with support for functions (get environment variables, etc)
- Powerful plugin system for adding new middlewares and other features using **WebAssembly (WASM)**

# Quick start

1. Download the latest release from [https://github.com/qompassai/vongola/releases](https://github.com/qompassai/vongola/releases)
2. Create a configuration file named `vongola.hcl`
3. Add the following content to the file:

```hcl
lets_encrypt {
  enabled = true
  email = "my@email.com"
}

paths {
  # Where to save certificates?
  lets_encrypt = "./"
}

# A list of routes Vongola should handle
routes = [
  {
    # You might need to edit your /etc/hosts file here.
    host = "mysite.localhost",

    # Will create a certificate for mysite.localhost
    ssl_certificate =  {
      self_signed_on_failure = true
    }

    # Where to point mysite.localhost to
    upstreams = [{
      ip = "docs.vongola.info"
      port = 443

      headers = {
        add = [{ name = "Host", value = "docs.vongola.info" }]
      }
    }]
  }
]
```
4. Run `vongola -c /path-where-vongola.hcl-is-located`

