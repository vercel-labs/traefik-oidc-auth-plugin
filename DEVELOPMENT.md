# Development guide

## Unit tests

This project includes extensive unit tests, which you can run with:

```sh
go test -v -race ./...
```

## Testing with Traefik

Testing with Traefik requires running the plugin in ["local mode"](https://github.com/traefik/plugindemo?tab=readme-ov-file#local-mode).

You can use these instructions as an example for setting up a local environment:

Requirements:

- [supervisord](https://supervisord.org/)
  - On Linux, this is available on most distributions' repositories
  - On macOS, it can be installed from Homebrew: `brew install supervisord`
  - Note: we use supervisord as a foreground process; do not start it as a system service

Set up guide:

1. Create a `scratch` folder:

   ```sh
   mkdir scratch
   ```

2. Download the latest releases of [traefik](https://github.com/traefik/traefik/releases) and [traefik/whoami](https://github.com/traefik/whoami/releases) and place the pre-compiled binaries in the `scratch` folder.
   - On macOS, you may need to run `xattr -rc` for the unsigned binaries to run.
3. Create the file `scratch/traefik.yaml` with Traefik's startup configuration (i.e. "static configuration"):

   ```yaml
   # scratch/traefik.yaml
   experimental:
     localPlugins:
       vercelAuth:
         moduleName: github.com/vercel-labs/traefik-oidc-auth-plugin
   providers:
     file:
       filename: "dynamic-conf.yaml"
   log:
     level: "DEBUG"
   accessLog: {}
   entryPoints:
     traefik:
       address: ":8081"
     http:
       address: ":80"
     https:
       address: ":443"
       http:
         tls: {}
   api:
     insecure: true
     dashboard: true
   ```

4. Create the file `scratch/dynamic-conf.yaml` with the routing configuration, populating the required configuration fields:

   ```yaml
   # scratch/dynamic-conf.yaml
   http:
     routers:
       whoami:
         rule: "host(`whoami.localhost`)"
         service: "whoami"
         entryPoints:
           - "http"
         middlewares:
           - "vercelAuth"

     services:
      whoami:
         loadBalancer:
           servers:
             - url: "http://127.0.0.1:4545"

     middlewares:
       vercelAuth:
         plugin:
           vercelAuth:
             # Set these
             issuer: "..."
             teamSlug: "..."
             projectName: ".."
             environment: "production"
   ```

5. Create the file `scratch/supervisord.conf` with the configuration for supervisord for running the binaries:

   ```conf
   [supervisord]
   directory = .
   nodaemon = true
   logfile = logs/supervisord.log
   logfile_maxbytes = 0
   identifier = supervisor

   [supervisorctl]
   serverurl = unix://supervisor.sock
   prompt = supervisor

   [unix_http_server]
   file = supervisor.sock

   [rpcinterface:supervisor]
   supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

   [program:traefik]
   command = ./traefik --accesslog true --configFile config.yaml
   stdout_logfile = logs/traefik.log
   stdout_logfile_maxbytes = 0
   stderr_logfile = logs/traefik.log
   stderr_logfile_maxbytes = 0

   [program:whoami]
   command = ./whoami --port 4545
   stdout_logfile = logs/whoami.log
   stdout_logfile_maxbytes = 0
   stderr_logfile = logs/whoami.log
   stderr_logfile_maxbytes = 0
   ```

6. Create the `scratch/start.sh` script that starts the solution:

   ```sh
   #!/bin/bash
   set -e

   mkdir -p logs
   rm logs/*.log || true

   supervisord -n -c supervisord.conf
   ```

7. Finally, run these commands to complete the setup, inside the `scratch` folder:

   ```sh
   # In the scratch folder
   chmod +x start.sh
   (mkdir -p plugins-local/src/github.com/vercel-labs && cd plugins-local/src/github.com/vercel-labs && ln -s ../../../../../ traefik-oidc-auth-plugin)
   ```

You can then start Traefik and the "whoami" service with:

```sh
# In the scratch folder
./start.sh
```

Try invoking [`http://whoami.localhost`](http://whoami.localhost) to see the authorization middleware in effect.

Logs are saved in the `scratch/logs` folder.
