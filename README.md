# Caddy Web UI

A web interface for managing Caddy reverse proxies using the admin API.

## Features

- View all reverse proxies
- Edit individual hosts
- Configuration versioning
- User authentication

## Setup

1. Make sure you have Docker and Docker Compose installed
2. Clone this repository
3. Create a `.env` file with your configuration (copy from `config.ini`)
4. Build and run with Docker Compose:

```bash
docker-compose up -d --build
```
