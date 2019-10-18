# about

Скрипт для проверки срока действия сертификата.

# howto

## show ssl info
```
$ python ssl_info.py show-ssl-info www.google.ru
...
 'notAfter': 'Dec 26 17:19:19 2019 GMT',
 'notBefore': u'Oct  3 17:19:19 2019 GMT',
...
 'subjectAltName': (('DNS', '*.google.com.ru'),
                    ('DNS', '*.google.ru'),
                    ('DNS', 'google.com.ru'),
                    ('DNS', 'google.ru')),
...
```

## check certificate expiry date
```
$ python ssl_info.py check-cert -l www.google.ru
www.google.ru:  subjectAltName: ['*.google.com.ru', '*.google.ru', 'google.com.ru', 'google.ru'] will expire in 69 days and 1 hours (2019-12-26 17:19:19) (server_name: www.google.ru)
```

