# Docker Implementation of Ethscriptions Indexer

This project is a Docker-based implementation of the Ethscriptions Indexer, streamlined for easy setup and deployment. It's a fork and not the official open source Ethscriptions indexer but aims to replicate its functionality in a Docker environment. This setup includes everything needed to get up and running with minimal configuration.

## Prerequisites

Before you begin, ensure Docker and Docker Compose are installed on your system.

## Getting Started

Follow these steps to get your Ethscriptions Indexer running:

### 1. Clone the Repository

First, clone this repository to your local machine:

```bash
git clone https://github.com/chopperdaddy/docker-ethscriptions-indexer
cd docker-ethscriptions-indexer
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

### 5. API Endpoints

### Blocks

- **List Blocks**: `GET /blocks`
  - Retrieve a paginated list of blockchain blocks.
- **Get Block Details**: `GET /blocks/:id`
  - Fetch details for a specific block by its number.
- **Get Newer Blocks**: `GET /blocks/newer_blocks`
  - Retrieve blocks newer than a specified block number.

### Ethscription Transfers

- **List Transfers**: `GET /ethscription_transfers`
  - Query transfers of ethscriptions based on filters like `from_address`, `to_address`, `transaction_hash`, `to_or_from`, `ethscription_token_tick`, and `ethscription_token_protocol`.

### Ethscriptions

- **List Ethscriptions**: `GET /ethscriptions`
  - List ethscriptions with optional filters such as `current_owner`, `creator`, `previous_owner`, etc.
- **Get Ethscription Details**: `GET /ethscriptions/:id`
  - Fetch details of a specific ethscription by ID or transaction hash.
- **Get Ethscription Data**: `GET /ethscriptions/data/:id`
  - Access specific data for an ethscription.
- **Get Newer Ethscriptions**: `GET /ethscriptions/newer_ethscriptions`
  - Retrieve ethscriptions newer than a specific block number.

### Status

- **Get Indexer Status**: `GET /status/indexer_status`
  - Provides the current status of the indexer, including the latest block number processed.

### Tokens

- **List Tokens**: `GET /tokens`
  - Retrieve a list of tokens with optional filtering.
- **Get Token Details**: `GET /tokens/:protocol/:tick`
  - Fetch details for a specific token.
- **Get Historical State**: `GET /tokens/:protocol/:tick/historical_state`
  - Retrieve the historical state of a token as of a specified block.
- **Validate Token Items**: `POST /tokens/:protocol/:tick/validate_token_items`
  - Validate transaction hashes against token items of a specific token.

## Filtering and Pagination

Endpoints supporting list operations allow for filtering based on query parameters that match the resource attributes. Use pagination parameters (`page` and `limit`) to navigate through large datasets.

## Contributing

Contributions to this Docker-based fork are welcome. Whether it's bug reports, feature suggestions, or code contributions, please feel free to get involved.