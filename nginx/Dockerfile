FROM nginx:stable-alpine

ENV APP_HOME /var/www

# Configure nginx
RUN rm /etc/nginx/conf.d/default.conf
# RUN ln -s /usr/bin/php8 /usr/bin/php
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/conf.d/default.conf /etc/nginx/conf.d/

#Copy test app
RUN mkdir -p $APP_HOME
WORKDIR $APP_HOME
COPY --chown=www-data ./public $APP_HOME/public
