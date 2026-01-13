# Vulnerable MySQL Database
# Weak credentials, plaintext passwords, injectable queries

# Using MariaDB 10.5 for ARM64 compatibility (MySQL 5.7 not available on ARM)
FROM mariadb:10.5

LABEL maintainer="CyberLab"
LABEL description="MariaDB with intentional vulnerabilities for SQL injection practice"
LABEL lab.category="database"
LABEL lab.difficulty="intermediate"

# Copy initialization script
COPY init.sql /docker-entrypoint-initdb.d/

# Expose MySQL port
EXPOSE 3306

# Environment variables for initial setup
ENV MYSQL_ROOT_PASSWORD=root
ENV MYSQL_DATABASE=vulnerable_db
