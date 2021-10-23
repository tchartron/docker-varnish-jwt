ARG PHP_VERSION=8
ARG ALPINE_VERSION=3.12

FROM php:${PHP_VERSION}-fpm-alpine${ALPINE_VERSION}

ENV APP_HOME /var/www


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
        opcache \
        pdo_mysql

RUN docker-php-ext-enable \
    apcu
    # xdebug

# run dir
# RUN mkdir -p /run

# Configure PHP-fpm
COPY php/php.ini /usr/local/etc/php/php.ini
COPY php/php-cli.ini /usr/local/etc/php/php-cli.ini

# Setup document root
RUN mkdir -p $APP_HOME

WORKDIR $APP_HOME

# install composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
RUN chmod +x /usr/bin/composer
#ENV COMPOSER_ALLOW_SUPERUSER 1

# Configure entrypoint
# COPY docker/php/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
# RUN chmod +x /usr/local/bin/docker-entrypoint

# Switch to use a non-root user
USER www-data

# Framework specifique Laravel / Symfony
COPY --chown=www-data ./public $APP_HOME/public

# VOLUME $APP_HOME/var

#USER root
