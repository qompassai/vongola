# Getting started

For a quick introduction, check the ASCII recording of a small configuration file for Vongola:

{% embed url="https://asciinema.org/a/ORhG5Na2SHIBI8TH2mPPUHMVZ" %}

***



<div data-full-width="true">

<figure><picture><source srcset=".gitbook/assets/simple-flow-white-2.png" media="(prefers-color-scheme: dark)"><img src=".gitbook/assets/simple-flow-white-2-light.png" alt="" width="563"></picture><figcaption><p>Vongola can be your reverse proxy or a load balancer in front of your public IPs</p></figcaption></figure>

</div>

**Vongola** is a **simple**, **lightweight**, and easy-to-use proxy server that automatically handles SSL, HTTP, and DNS traffic. It is designed to be used as a standalone proxy server or as a component in a larger system. Vongola is written in [Rust](https://www.rust-lang.org/) and uses [Cloudflare Pingora](https://blog.cloudflare.com/pingora-open-source) as its core networking library.



### Quick start

Create a configuration file

```bash
mkdir config
touch config/vongola.hcl
```

Add a simple route, let's try `docs.vongola.info` as our proxy route:

```hcl
# 
lets_encrypt {
  enabled = true
  staging = true
  email = "my@email.com"
}


paths {
  # Where to save certificates?
  lets_encrypt = "./"
  
  # You can even use functions here
  # lets_encrypt = env("HOME")
}

# A list of routes Vongola should handle
routes = [
  {
    # You might need to edit your /etc/hosts file here.
    host = "mysite.localhost",
    upstreams = [
     { 
       ip = "docs.vongola.info"
       port = 443
     }
    ]  
  }
]
```



## Features

Of the many features **Vongola** offers is the ability to **load balance** to your infrastructure or **any IP** that supports your host configurations. Other features of **Vongola** also include:

1. Automatic **Docker** and **Docker Swarm** service discovery through labels
2. Built-in most common middlewares such as **OAuth**, **Rate Limiting**, **CDN** **Caching** and others
3. The ability of running it as a single binary in your system
4. Automatic **SSL** through **Let's Encrypt** and redirection from HTTP to HTTPS
5. Configuration through **HCL with support for functions**&#x20;
6. Many others.

