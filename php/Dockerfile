ARG PHP_VERSION=8
ARG ALPINE_VERSION=3.12
ARG APP_ENV=dev

FROM php:${PHP_VERSION}-fpm-alpine${ALPINE_VERSION}

ENV APP_HOME /var/www/html

# /!\ warning : alpine 3.13 could not be fetch
# AMQP for php8.x installation
# RUN docker-php-source extract \
#     && apk -Uu add git rabbitmq-c-dev \
#     && git -c http.sslVerify=false clone --branch master --depth 1 https://github.com/php-amqp/php-amqp.git /usr/src/php/ext/amqp \
#     && cd /usr/src/php/ext/amqp && git submodule update --init \
#     && docker-php-ext-install amqp

# RUN ls -al /usr/local/lib/php/extensions/
# RUN docker-php-source delete

# Install packages
RUN apk add --no-cache \
        $PHPIZE_DEPS \
        coreutils \
        freetype-dev \
        icu-dev \
        libjpeg-turbo-dev \
        libpng-dev \
        libtool \
        libwebp-dev \
        libzip-dev \
        zlib-dev \
        libxml2-dev \
        curl
        # mariadb-dev \
        # libxml2 \
        # libssh-dev \
        # rabbitmq-c rabbitmq-c-dev \
        # nginx \
        # supervisor \
        # acl \
        # openssl

RUN pecl install apcu; \
    pecl clear-cache
#     pecl install xdebug-3.0.0; \

# PHP extensions install
RUN docker-php-ext-configure gd; \
    docker-php-ext-configure zip; \
    docker-php-ext-install -j$(nproc) \
        exif \
        gd \
        intl \
        zip \
        simplexml \
        bcmath \
        sockets \
        pdo \
        pdo_mysql
        # pgsql \
        # pdo_pgsql

RUN docker-php-ext-enable \
    apcu \
    opcache
    # xdebug

# run dir
# RUN mkdir -p /run

# Configure PHP-fpm
COPY php/php.ini /usr/local/etc/php/php.ini
COPY php/php-cli.ini /usr/local/etc/php/php-cli.ini

# Configure supervisord
# RUN mkdir -p /var/log/supervisor
# COPY docker/supervisord/api_backend.conf /etc/supervisor/conf.d/api_backend.conf
# COPY docker/supervisord/api_backend_supervisord.conf /etc/supervisor/conf.d/api_backend_supervisord.conf
# COPY docker/php/cron /var/spool/cron/crontabs/root
# RUN chmod 0600 /var/spool/cron/crontabs/root

# Setup document root
RUN mkdir -p $APP_HOME

# Make sure files/folders needed by the processes are accessable when they run under the nobody user
# RUN chown -R nobody.nobody /var/www/html && \
#   chown -R nobody.nobody /run && \
#   chown -R nobody.nobody /var/lib/nginx && \
#   chown -R nobody.nobody /var/log/nginx

# Add application
WORKDIR $APP_HOME

# install composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
RUN chmod +x /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER 1

# Configure entrypoint
# COPY docker/php/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
# RUN chmod +x /usr/local/bin/docker-entrypoint

# Switch to use a non-root user from here on
USER www-data

# prevent the reinstallation of vendors at every changes in the source code
# COPY --chown=www-data ./composer.json $APP_HOME/composer.json
# COPY --chown=www-data ./composer.lock $APP_HOME/composer.lock
# RUN composer install --prefer-dist --no-autoloader --no-scripts --no-progress; \
#     composer clear-cache

# Framework specifique Laravel / Symfony
# copy only specifically what we need
# COPY --chown=www-data ./.env $APP_HOME/.env
# COPY --chown=www-data ./bin $APP_HOME/bin
# COPY --chown=www-data ./config $APP_HOME/config
COPY --chown=www-data ./public $APP_HOME/public
# COPY --chown=www-data ./src $APP_HOME/src
# COPY --chown=www-data ./templates $APP_HOME/templates
# COPY --chown=www-data ./translations $APP_HOME/translations

# RUN composer dump-autoload --classmap-authoritative;
# RUN mkdir -p var/cache var/log; \
    # APP_SECRET='' composer run-script post-install-cmd; \
    # chmod +x bin/console; sync;

# VOLUME $APP_HOME/var

USER root
