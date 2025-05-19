create table if not exists auth
(
    id         bigserial primary key,
    user_id    varchar               not null,
    user_agent varchar               not null,
    ip         varchar               not null,
    token      varchar               not null, -- base64 + bcrypt refresh token
    jti        varchar unique        not null, -- reference for access token
    revoked    boolean default false not null,
    expires_at timestamp             not null
);
