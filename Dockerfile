FROM php:8.2-apache

# Install required dependencies for PHP extensions (e.g., GD for image handling, PDO, and MySQL)
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libzip-dev \
    unzip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install pdo pdo_mysql gd zip

# Enable Apache mod_rewrite (optional, if you need URL rewriting)
RUN a2enmod rewrite

# Install Composer globally
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Set the correct permissions for the web directory
RUN chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html

# Ensure the uploads folder exists and set permissions
RUN mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html/uploads \
    && chmod -R 755 /var/www/html/uploads

# Expose port 80 for Apache
EXPOSE 80