# test_auth

Часть сервиса аутентификации


### Prerequisites
- Docker, Docker Compose
- or Golang 1.24 + postgresql


### Getting started

* Добавить репозиторий к себе
* Создать .env файл в директории с проектом и заполнить информацией из .env.example


### Usage

Запустить сервис можно с помощью `make compose-up` (или `docker-compose up -d --build`)
или `make run` (при наличии go1.24 и локально развернутого postgresql)  
Тесты доступны по команде `make tests`

Документация доступна по адресу `http://localhost:8000/swagger/index.html`


### Примеры запросов

#### Аутентификация
`request`
```shell
curl -X 'POST' \
  'http://localhost:8000/api/v1/auth/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: GOOGLE' \
  -H 'X-Real-Ip: 192.168.0.0' \
  -d '{"id": "myid"}'
```

`response`
```json
{
  "access": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDc2OTI0MjgsImlhdCI6MTc0NzY5MDYyOCwianRpIjoiNjE0ZjUzZDAtNGEwZS00MDNkLWFmZDgtMjQxMWY2YzhjYjIwIiwidXNlcl9pZCI6Im15aWQifQ.nuQ5me-hbCaaak1F1Jet1pCxOeydrn5iONd-8BBArRCOyp4Z-rhYLYR3l4KKsXCwZMVoXw8Q7ZeDbgUfF3gaFg",
  "refresh": "meOgxS7IQc_P08adJSdQbjJdyYwlHIV5_Fkb4ZOldYo"
}
```

#### Refresh
`request`
```shell
curl -X 'POST' \
  'http://localhost:8000/api/v1/auth/refresh' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: GOOGLE' \
  -H 'X-Real-Ip: 192.168.0.0' \
  -d '{"access":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDc2OTI0MjgsImlhdCI6MTc0NzY5MDYyOCwianRpIjoiNjE0ZjUzZDAtNGEwZS00MDNkLWFmZDgtMjQxMWY2YzhjYjIwIiwidXNlcl9pZCI6Im15aWQifQ.nuQ5me-hbCaaak1F1Jet1pCxOeydrn5iONd-8BBArRCOyp4Z-rhYLYR3l4KKsXCwZMVoXw8Q7ZeDbgUfF3gaFg","refresh":"meOgxS7IQc_P08adJSdQbjJdyYwlHIV5_Fkb4ZOldYo"}'
```


#### Получение GUID
`request`
```shell
curl -X 'GET' \
  'http://localhost:8000/api/v1/auth/me' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDc2OTI0MzksImlhdCI6MTc0NzY5MDYzOSwianRpIjoiZGUyZGU2MGQtYTg0My00MGFjLWEzNDgtMDJhZDIzNTU3Y2M2IiwidXNlcl9pZCI6Im15aWQifQ.55mbzssn6Oo3bntw-HC6a6yKeodBar1qPxvc0e1NlfmhcCNCv1GqE6iF3S0mS_CXQ7qsrQU_JduuiVBaL7EyAg'
```

`response`
```json
{
  "user_id": "myid"
}
```

#### Деавторизация
`request`
```shell
curl -X 'GET' \
  'http://localhost:8000/api/v1/auth/logout' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDc2OTI0MzksImlhdCI6MTc0NzY5MDYzOSwianRpIjoiZGUyZGU2MGQtYTg0My00MGFjLWEzNDgtMDJhZDIzNTU3Y2M2IiwidXNlcl9pZCI6Im15aWQifQ.55mbzssn6Oo3bntw-HC6a6yKeodBar1qPxvc0e1NlfmhcCNCv1GqE6iF3S0mS_CXQ7qsrQU_JduuiVBaL7EyAg'
```

`response`
`200`
