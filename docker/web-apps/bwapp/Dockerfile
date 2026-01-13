# bWAPP - Buggy Web Application
# ARM64-native build with 100+ web vulnerabilities

FROM php:7.4-apache

LABEL maintainer="CyberLab"
LABEL description="bWAPP - A free and open source deliberately insecure web application (ARM64 native)"
LABEL lab.category="web"
LABEL lab.difficulty="beginner"

# Install dependencies
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    mariadb-server \
    mariadb-client \
    unzip \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure and install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd mysqli pdo pdo_mysql

# Enable Apache modules
RUN a2enmod rewrite

# Download and setup bWAPP
WORKDIR /var/www/html
RUN wget -q https://sourceforge.net/projects/bwapp/files/latest/download -O bwapp.zip \
    && unzip -q bwapp.zip \
    && rm bwapp.zip \
    && mv bWAPP bwapp || true

# Configure bWAPP database settings
RUN if [ -f /var/www/html/bwapp/admin/settings.php ]; then \
        sed -i 's/$db_server = "localhost"/$db_server = "localhost"/' /var/www/html/bwapp/admin/settings.php; \
        sed -i 's/$db_username = "root"/$db_username = "root"/' /var/www/html/bwapp/admin/settings.php; \
        sed -i 's/$db_password = ""/$db_password = ""/' /var/www/html/bwapp/admin/settings.php; \
    fi

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Create index.php redirect in root
RUN echo '<?php header("Location: /bwapp/"); ?>' > /var/www/html/index.php

# Configure PHP settings for bWAPP
RUN echo "allow_url_include = On" >> /usr/local/etc/php/conf.d/bwapp.ini \
    && echo "allow_url_fopen = On" >> /usr/local/etc/php/conf.d/bwapp.ini \
    && echo "magic_quotes_gpc = Off" >> /usr/local/etc/php/conf.d/bwapp.ini 2>/dev/null || true

# Create startup script
RUN echo '#!/bin/bash\n\
service mariadb start\n\
sleep 3\n\
mysql -e "CREATE DATABASE IF NOT EXISTS bwapp;"\n\
mysql -e "GRANT ALL PRIVILEGES ON *.* TO '"'"'root'"'"'@'"'"'localhost'"'"';"\n\
mysql -e "FLUSH PRIVILEGES;"\n\
apache2-foreground' > /start.sh && chmod +x /start.sh

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s \
  CMD curl -f http://localhost/bwapp/ || exit 1

CMD ["/start.sh"]
