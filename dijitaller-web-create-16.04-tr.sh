#!/bin/bash
echo "Merhaba
Birazdan yeni site ayarları ve dosyları oluşturulacak
Bu sistem Dijitaller-web-installer ile çalışmaktadır. 
"
echo

read -p "Hesap açtınızmı (y/n)?" choice
case "$choice" in 
  y|Y ) echo "Kuruluma devam ediliyor";;
  n|N ) echo "kurlumdan çıkılıyor" &exit ;;
  * ) echo "Bilinmeyen. hesap açtıysanız Y , Hesap açmadıysanız N ";;
esac

echo "Sitenizin adresi nedir ?"
echo "örnek www.dijitaller.com"
echo
read -r dwebsiteadresi

echo "Mail adresiniz nedir ?"
echo "örnek deneme@mail.com"
echo
read -r dwebmailadresi

echo "Mail adresi parolanız nedir ?"
echo
read -r dwebmailparola

echo "
Site adresiniz $dwebsiteadresi
Mail adresiniz $dwebmailadresi
Mail parolanız $dwebmailparola
"

mkdir -p /etc/dijitaller/web/$dwebsiteadresi/
mkdir -p /web/$dwebsiteadresi/
echo "mail ayarlanıyor"

echo "
account $dwebsiteadresi
tls on
tls_certcheck off
auth on
host smtp.yandex.com.tr
port 587
user $dwebmailadresi
from $dwebmailadresi
password $dwebmailparola
" > /etc/dijitaller/web/$dwebsiteadresi/mail.conf
chmod 600 /etc/dijitaller/web/$dwebsiteadresi/mail.conf
chown -R www-data:www-data /etc/dijitaller/web/$dwebsiteadresi/mail.conf

mkdir /etc/dijitaller/tmp
cd /etc/dijitaller/tmp
rm -rf *
wget https://raw.githubusercontent.com/AhmetOZER/web-server-auto-installer/master/php/php-fpm-default.conf --no-check-certificate

echo "Php-Fpm ayarlanıyor"
mkdir -p /etc/dijitaller/web/php-fpm/
sed 's/siteismi-dweb/'$dwebsiteadresi''/g php-fpm-default.conf > /etc/dijitaller/web/php-fpm/$dwebsiteadresi.conf
echo php_admin_value[sendmail_path] = "/usr/bin/msmtp -C /etc/dijitaller/web/$dwebsiteadresi/mail.conf --logfile /var/log/msmtp.log -a $dwebsiteadresi -t" >> /etc/dijitaller/web/php-fpm/$dwebsiteadresi.conf

echo "SSL sertifikası üretiliyor"

sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/dijitaller/web/$dwebsiteadresi/nginx-selfsigned.key -out /etc/dijitaller/web/$dwebsiteadresi/nginx-selfsigned.crt -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=$dwebsiteadresi" >> web-install.log 2>&1

echo "Nginx ayarı oluşturuluyor"
cd

mkdir /etc/dijitaller/tmp
cd /etc/dijitaller/tmp
rm -rf *

echo '
# http olan istekleri https yönlendiriyor
server {
    listen 80;
    listen [::]:80;
    server_name nginxsiteadresi;
    return 301 https://$host$request_uri;
}
# https sunucu
server {
    listen 443 ssl http2;
    listen [::]:443 http2 ssl;
    client_max_body_size 200M;
    root /web/nginxsiteadresi ;
    index index.html index.htm index.php;
    server_name nginxsiteadresi;
    charset utf-8;
ssl_certificate /etc/dijitaller/web/nginxsiteadresi/nginx-selfsigned.crt;
ssl_certificate_key /etc/dijitaller/web/nginxsiteadresi/nginx-selfsigned.key;     
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
ssl_ecdh_curve secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
#ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
#add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;

ssl_dhparam /etc/ssl/certs/dhparam.pem;



	location ~ \.php$ {
 try_files $uri =404;
    fastcgi_pass unix:/var/run/php/php7.0-fpm-nginxsiteadresi.sock;
				fastcgi_index index.php;
    include fastcgi.conf;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
				###   PHP cache   ###
				fastcgi_buffer_size 128m;
				fastcgi_buffers 256 16m;
				fastcgi_busy_buffers_size 256m;
				fastcgi_temp_file_write_size 256m;
				#add_header X-Cache $upstream_cache_status;
				fastcgi_cache CACHE;
				#####
				#fastcgi_cache_valid cache kaç saniye süreceğini belirtir ben 30 sn dedim ileride herhangi bir sözlükten akın gelsede zarar görmemek için 
				#####
				fastcgi_cache_valid 30s;
				fastcgi_cache_bypass $skip_cache;
				fastcgi_no_cache $skip_cache;
				limit_req zone=one burst=2;
                 }	


location ~ /.well-known {
                allow all;
        }
		
				location ~ /\readme.html {
        deny all;
    }
	
    location / {
            try_files $uri $uri/ /index.php?$args;
    }
 
    error_page 404 /index.php;


    # Deny .htaccess file access
    location ~ /\.ht {
        deny all;
    }
    

	if ($request_method = POST) {
		set $skip_cache 1;
	}   
	if ($query_string != "") {
		set $skip_cache 1;
	}   

	# Dont cache uris containing the following segments
	if ($request_uri ~* "/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml") {
		set $skip_cache 1;
	}   

	# Dont use the cache for logged in users or recent commenters
	if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") {
		set $skip_cache 1;
	}


	location ~* ^.+\.(ogg|ogv|svg|svgz|eot|otf|woff|mp4|ttf|rss|atom|jpg|jpeg|gif|png|ico|zip|tgz|gz|rar|bz2|doc|xls|exe|ppt|tar|mid|midi|wav|bmp|rtf)$ {
		access_log off;	log_not_found off; expires max;
	}

location = /favicon.ico {
	log_not_found off;
	access_log off;
}

location = /robots.txt {
	allow all;
	log_not_found off;
	access_log off;
}

location ~ /\. {
	deny all;
}

location ~* /(?:uploads|files)/.*\.php$ {
	deny all;
}
########################################

location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
	expires 24h;
	log_not_found off;
}

#avoid php readfile()
location ^~ /blogs.dir {
        internal;
        alias /web/nginxsiteadresi/wp-content/blogs.dir ;
        access_log off; log_not_found off;      expires max;
}

if (!-e $request_filename) {
	rewrite /wp-admin$ $scheme://$host$uri/ permanent;
	rewrite ^/[_0-9a-zA-Z-]+(/wp-.*) $1 last;
	rewrite ^/[_0-9a-zA-Z-]+(/.*\.php)$ $1 last;
}

location ~ \.php$ {
	try_files $uri =404;
	fastcgi_split_path_info ^(.+\.php)(/.+)$;
	include fastcgi_params;
	fastcgi_index index.php;
	fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
################### son {} işaretinin bulunduğu yer ###
}
'>> site.conf
sed 's/nginxsiteadresi/'$dwebsiteadresi'/g' site.conf >> /etc/dijitaller/web/$dwebsiteadresi/nginx.conf
rm site.conf

/usr/bin/dijitaller-web-wwwpermission

service nginx restart
service php7.0-fpm restart

echo "
Site adresiniz https://$dwebsiteadresi
Site ayarlarının konumu /etc/dijitaller/web/$dwebsiteadresi
Site dosyalarını barındıracağınız yer /web/$dwebsiteadresi/
Site dosyalarınızı yükeldikten sonra dijitaller-web-wwwpermission
komutunu çalıştırarak dosya izinlerini ayarlayın.
Mailin çalışması için yandex üzerinde giriş yapın ve sözleşmeyi onaylayın
"
