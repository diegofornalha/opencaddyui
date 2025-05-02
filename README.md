# Caddy Web UI

A web interface for managing Caddy reverse proxies using the admin API.
This is a little weird coming from me since I like working in a terminal. 
But sometimes I want to test something quick, maybe on my phone, and want to be
able to access caddy through aweb UI.

## Assumption
This assumes that you have Caddy already installed. The default assumes Caddy is installed on 
localhost, this is configuratble via .env file. 

## A little background context
My current caddyfile (I use a flat file) looks like this:

```
##################################################################
# Globals
##################################################################
{
        acme_dns cloudflare {env.CLOUDFLARE_AUTH_TOKEN}
        admin localhost:2019
}

(common) {
        header /* {
                -Server
                -X-Powered-By
                +X-Content-Type-Options nosniff
                +Strict-Transport-Security "max-age=63072000 includeSubDomains preload"
        }
}

(cors) {
        @cors_preflight{args[0]} method OPTIONS
        @cors{args[0]} header Origin {args[0]}
        # "{args[0]}" is an input value used when calling the snippet

        handle @cors_preflight{args[0]} {
                header {
                        Access-Control-Allow-Origin "{args[0]}"
                        Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE"
                        Access-Control-Allow-Headers *
                        Access-Control-Max-Age "3600"
                        defer
                }
                respond "" 204
        }
        handle @cors{args[0]} {
                header {
                        Access-Control-Allow-Origin "{args[0]}"
                        Access-Control-Expose-Headers *
                        defer
                }
        }
}


(log) {
        log {
                output file /var/log/caddy/{args[0]}_access.log {
                        roll_size 100mb
                        roll_keep 10
                        roll_keep_for 2160h
                }
        }
}
##################################################################
# Hosts
##################################################################
nextcloud.xyz.com {
        import common
        import cors xyz.com
        reverse_proxy 10.0.0.10:1111
        import log nextcloud
}
mail.xyz.com {
        import common
        import cors xyz.com
        reverse_proxy 10.0.0.11:2525
        import log mail
}
```

So, adding/removing hosts is not that bad. 

## Features

Caddy API uses JSON. We're parsing the posting JSON data to the ADMIN API endpoint. We have
calls to add/remove/edit hosts and rollback whole set of changes.

Users can:

- View all reverse proxies
- Edit individual hosts
- Add new host
- Configuration versioning for rollbacks
- User authentication

## Setup

1. Make sure you have Docker and Docker Compose installed
2. Clone this repository
3. Copy .env.example to `.env` and edit it with your configuration (copy from `config.ini`)
4. Build and run with Docker Compose:

```bash
docker-compose up -d --build
```

Now, your caddy web UI should be available at localhost:5000. 


## Screenshots
![Screenshot From 2025-05-01 23-23-33](https://github.com/user-attachments/assets/aae4885b-8467-401f-af60-1325a8309e5f)
![Screenshot From 2025-05-01 23-23-17](https://github.com/user-attachments/assets/9a744f6b-4441-463c-a1fb-75c165e6c6e3)
![Screenshot From 2025-05-01 23-23-07](https://github.com/user-attachments/assets/03207d3f-f7e9-4000-b205-c4c566f276cd)
