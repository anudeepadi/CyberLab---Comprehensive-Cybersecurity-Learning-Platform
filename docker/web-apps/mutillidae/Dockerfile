# OWASP Mutillidae II
# ARM64-native build - Deliberately vulnerable web application

FROM php:7.4-apache

LABEL maintainer="CyberLab"
LABEL description="OWASP Mutillidae II - Deliberately vulnerable web application (ARM64 native)"
LABEL lab.category="web"
LABEL lab.difficulty="intermediate"

# Install dependencies
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libxml2-dev \
    libcurl4-openssl-dev \
    libonig-dev \
    mariadb-server \
    mariadb-client \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure and install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd mysqli pdo pdo_mysql xml curl mbstring

# Enable Apache modules
RUN a2enmod rewrite

# Clone Mutillidae from official OWASP repository
WORKDIR /var/www/html
RUN git clone https://github.com/webpwnized/mutillidae.git

# Set permissions
RUN chown -R www-data:www-data /var/www/html/mutillidae \
    && chmod -R 755 /var/www/html/mutillidae

# Configure PHP settings
RUN echo "allow_url_include = On" >> /usr/local/etc/php/conf.d/mutillidae.ini \
    && echo "allow_url_fopen = On" >> /usr/local/etc/php/conf.d/mutillidae.ini \
    && echo "display_errors = On" >> /usr/local/etc/php/conf.d/mutillidae.ini

# Configure database connection for Mutillidae (new src/ structure)
RUN if [ -f /var/www/html/mutillidae/src/includes/database-config.inc ]; then \
        sed -i 's/static public \$mMySQLDatabaseHost = "127.0.0.1"/static public \$mMySQLDatabaseHost = "localhost"/' /var/www/html/mutillidae/src/includes/database-config.inc; \
        sed -i 's/static public \$mMySQLDatabaseUsername = "root"/static public \$mMySQLDatabaseUsername = "root"/' /var/www/html/mutillidae/src/includes/database-config.inc; \
        sed -i 's/static public \$mMySQLDatabasePassword = "mutillidae"/static public \$mMySQLDatabasePassword = ""/' /var/www/html/mutillidae/src/includes/database-config.inc; \
    fi

# Create startup script
RUN echo '#!/bin/bash\n\
service mariadb start\n\
sleep 3\n\
mysql -e "CREATE DATABASE IF NOT EXISTS mutillidae;"\n\
mysql -e "CREATE DATABASE IF NOT EXISTS nowasp;"\n\
mysql -e "GRANT ALL PRIVILEGES ON *.* TO '"'"'root'"'"'@'"'"'localhost'"'"';"\n\
mysql -e "FLUSH PRIVILEGES;"\n\
apache2-foreground' > /start.sh && chmod +x /start.sh

# Set document root to src directory (new Mutillidae structure)
ENV APACHE_DOCUMENT_ROOT /var/www/html/mutillidae/src
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s \
  CMD curl -f http://localhost/ || exit 1

CMD ["/start.sh"]
