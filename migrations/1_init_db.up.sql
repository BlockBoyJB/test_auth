create table if not exists users
(
    id            bigserial primary key,
    user_id       varchar unique not null,
    email         varchar unique not null,
    password      varchar        not null,
    refresh_token varchar default ''
);