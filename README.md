# Docker Implementation of Ethscriptions Indexer

This project is a Docker-based implementation of the Ethscriptions Indexer, streamlined for easy setup and deployment. It's a fork and not the official open source Ethscriptions indexer but aims to replicate its functionality in a Docker environment. This setup includes everything needed to get up and running with minimal configuration.

## Prerequisites

Before you begin, ensure Docker and Docker Compose are installed on your system.

## Getting Started

Follow these steps to get your Ethscriptions Indexer running:

### 1. Clone the Repository

First, clone this repository to your local machine:

```bash
git clone https://github.com/chopperdaddy/facet-ethscriptions-indexer
cd facet-ethscriptions-indexer
```

### 2. Environment Configuration

Copy the sample `.env.sample` file to `.env` and edit it to suit your environment:

```bash
cp .env.sample .env
```

Be sure to replace `your_username` and `your_password` with your PostgreSQL credentials and adjust any other necessary settings.

### 3. Build and Run with Docker Compose

Use Docker Compose to build and start your containers:

```bash
docker-compose up --build
```

This command builds the Docker images and starts the containers defined in `docker-compose.yml`. If it's your first time running or if there are changes in your Dockerfile or entrypoint script, Docker Compose ensures that your Docker image is rebuilt.

### 4. Accessing the Application

With the services running, your Ethscriptions Indexer is now accessible. The API can be reached at `http://localhost:4000/`.

## Contributing

Contributions to this Docker-based fork are welcome. Whether it's bug reports, feature suggestions, or code contributions, please feel free to get involved.

---

Ensure you replace `<your-fork>` with the actual username and repository name where your fork is hosted. This README assumes you have a `.env.sample` file for users to copy from; if your sample environment file is named differently, adjust the instructions accordingly.