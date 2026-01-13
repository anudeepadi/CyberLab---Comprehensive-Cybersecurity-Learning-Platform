# DVWA - Damn Vulnerable Web Application
# ARM64-native build

FROM php:8.1-apache

LABEL maintainer="CyberLab"
LABEL description="DVWA - Damn Vulnerable Web Application (ARM64 native)"
LABEL lab.category="web"
LABEL lab.difficulty="beginner"

# Install dependencies
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    mariadb-server \
    mariadb-client \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure and install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd mysqli pdo pdo_mysql

# Enable Apache modules
RUN a2enmod rewrite

# Clone DVWA
RUN git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa

# Configure DVWA - copy config template (env vars will override defaults)
RUN cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php

# Set permissions
RUN chown -R www-data:www-data /var/www/html/dvwa \
    && chmod -R 755 /var/www/html/dvwa \
    && chmod -R 777 /var/www/html/dvwa/hackable/uploads \
    && chmod 777 /var/www/html/dvwa/config

# Configure PHP for DVWA requirements
RUN echo "allow_url_include = On" >> /usr/local/etc/php/conf.d/dvwa.ini \
    && echo "allow_url_fopen = On" >> /usr/local/etc/php/conf.d/dvwa.ini \
    && echo "display_errors = Off" >> /usr/local/etc/php/conf.d/dvwa.ini

# Set document root to DVWA
ENV APACHE_DOCUMENT_ROOT /var/www/html/dvwa
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Create startup script
RUN echo '#!/bin/bash\n\
service mariadb start\n\
sleep 3\n\
mysql -e "CREATE DATABASE IF NOT EXISTS dvwa;"\n\
mysql -e "CREATE USER IF NOT EXISTS '"'"'dvwa'"'"'@'"'"'localhost'"'"' IDENTIFIED BY '"'"'p@ssw0rd'"'"';"\n\
mysql -e "CREATE USER IF NOT EXISTS '"'"'dvwa'"'"'@'"'"'127.0.0.1'"'"' IDENTIFIED BY '"'"'p@ssw0rd'"'"';"\n\
mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO '"'"'dvwa'"'"'@'"'"'localhost'"'"';"\n\
mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO '"'"'dvwa'"'"'@'"'"'127.0.0.1'"'"';"\n\
mysql -e "FLUSH PRIVILEGES;"\n\
apache2-foreground' > /start.sh && chmod +x /start.sh

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s \
  CMD curl -f http://localhost/ || exit 1

CMD ["/start.sh"]
