# Docker

Similar to other proxies, Vongola can be run as a Container via Docker/Podman/etc. The following command will run the latest version of it:

```bash
docker run -d -p 80:80 -p 443:443 -v /path/to/config:/etc/vongola/ qompassai/vongola
```

If you are using `docker-compose.yml`  to manage your services, you can configure Vongola as your main host-mode container without even creating a `vongola.hcl` file.

```yaml
version: '3.8'
services:
  vongola:
    environment:
      VONGOLA_LOGGING__LEVEL: "info"
      VONGOLA_WORKER_THREADS: 2

      # Enables Vongola to fetch services/containers 
      # matching Smart labels 
      VONGOLA_DOCKER__ENABLED: "true"
      VONGOLA_DOCKER__MODE: container

      VONGOLA_LETS_ENCRYPT__ENABLED: "true"
      VONGOLA_LETS_ENCRYPT__STAGING: "true"
      VONGOLA_LETS_ENCRYPT__EMAIL: "contact@email.net"

      VONGOLA_PATHS__LETS_ENCRYPT: "/etc/vongola/certs"
    image: qompassai/vongola:latest
    networks:
      # Any service in the same network will be able to communicate with Vongola
      - web 
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /path/to/config:/etc/vongola/certs
```

And then you can expose any service by using `vongola.host` and `vongola.enable` labels. For example a simple `nginxdemos/hello` container/service:

```yaml
services:
  # ... (include Vongola configuration)
  web:
    image: nginxdemos/hello

    networks:
      - public
      - shared
    deploy:
      replicas: 2
    labels:
      vongola.enabled: "true"
      vongola.host: "your-site.localhost"
      vongola.port: "80" # no need to publish host ports

      # If you are running locally
      vongola.ssl_certificate.self_signed_on_failure: "true"
```

