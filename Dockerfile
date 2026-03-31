FROM php:8.3-apache

RUN a2enmod rewrite

RUN docker-php-ext-enable sodium

COPY docker/vhost.conf /etc/apache2/sites-available/000-default.conf
COPY docker/.htaccess  /var/www/html/.htaccess
COPY src/              /var/www/html/
COPY entrypoint.sh     /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/data"]
EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
