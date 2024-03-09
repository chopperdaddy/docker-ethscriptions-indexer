# Use the official Ruby image from the Docker Hub
FROM ruby:3.2.2

# Install dependencies
RUN apt-get update -qq && apt-get install -y nodejs postgresql-client

# Set the working directory inside the container
WORKDIR /apps

# Copy the Gemfile and Gemfile.lock into the container
COPY Gemfile /apps/Gemfile
COPY Gemfile.lock /apps/Gemfile.lock

# Install the gems
RUN bundle install

# Copy the current directory contents into the container at /apps
COPY . /apps

# Add a script to be executed every time the container starts.
COPY entrypoint.sh /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]
EXPOSE 4000

# Start the main process.
CMD ["rails", "server", "-b", "0.0.0.0"]
