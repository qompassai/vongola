# Environment variables

Vongola can be configured using environment variables and **they will have higher priority over the config file**.&#x20;

They are mapped to the configuration file keys, always start with `VONGOLA_` and can be used to override the default values. For nested keys, use the `__` character.

### Example:

For the key `service_name`, the environment variable `VONGOLA_SERVICE_NAME` can used
For the key `worker_threads`, the environment variable `VONGOLA_WORKER_THREADS` can be used
For the key `logging.level`, the environment variable `VONGOLA_LOGGING__LEVEL` can be used (note the `__` separator due to the nested key)

For keys that accept a list of values, e.g. `routes`, the environment variable `VONGOLA_ROUTES` can be used with a string value like this:

```bash
export VONGOLA_ROUTES='[{host="example.com", upstreams=[{ip="10.0.1.24", port=3001}]'
```


### Full list

Below you can find a full list of the configuration keys and their corresponding environment variables.

| Key | Environment variable | Description |
| :--- | :--- | :--- |
| `service_name` | `VONGOLA_SERVICE_NAME` | The name of the service |
| `worker_threads` | `VONGOLA_WORKER_THREADS` | The number of worker threads |
| `daemon` | `VONGOLA_DAEMON` | Whether the service should run as a daemon |
| `logging.level` | `VONGOLA_LOGGING__LEVEL` | The log level |
| `logging.format` | `VONGOLA_LOGGING__FORMAT` | The log format |
| `logging.path` | `VONGOLA_LOGGING__PATH` | The path where we should write logs files |
| `logging.rotation` | `VONGOLA_LOGGING__ROTATION` | The rotation policy of the log files |
| `lets_encrypt.enabled` | `VONGOLA_LETS_ENCRYPT__ENABLED` | Whether lets encrypt should be enabled |
| `lets_encrypt.email` | `VONGOLA_LETS_ENCRYPT__EMAIL` | The email address used for lets encrypt |
| `lets_encrypt.staging` | `VONGOLA_LETS_ENCRYPT__STAGING` | Whether lets encrypt should be used in staging mode |
| `paths.lets_encrypt` | `VONGOLA_PATHS__LETS_ENCRYPT` | The path where we should write the lets encrypt certificates |
| `docker.enabled` | `VONGOLA_DOCKER__ENABLED` | Whether the docker service should be enabled |
| `docker.interval_secs` | `VONGOLA_DOCKER__INTERVAL_SECS` | The interval (in seconds) to check for label updates |
| `docker.endpoint` | `VONGOLA_DOCKER__ENDPOINT` | The docker endpoint to connect to the docker socket/api |
