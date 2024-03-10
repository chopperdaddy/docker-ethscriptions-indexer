#!/bin/bash
set -e

# Remove a potentially pre-existing server.pid for Rails.
rm -f /apps/tmp/pids/server.pid

# Check if the database exists, and if not, create it and migrate
echo "Database setup"
bundle exec rake db:create
bundle exec rake db:migrate

# Then exec the container's main process (what's set as CMD in the Dockerfile).
exec "$@"
