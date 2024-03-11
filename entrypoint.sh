#!/bin/bash
set -e

# Remove a potentially pre-existing server.pid for Rails.
rm -f /apps/tmp/pids/server.pid

# Only run migrations for the specified service
if [ "$RUN_MIGRATIONS" = "true" ]; then
  echo "Database setup"
  bundle exec rake db:create
  bundle exec rake db:migrate
else
  echo "Skipping database setup (migrations)"
fi

# Then exec the container's main process (what's set as CMD in the Dockerfile).
exec "$@"
