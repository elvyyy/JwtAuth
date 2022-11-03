create table if not exists "users" (
    id bigserial primary key,
    username varchar(100) unique not null,
    email varchar(255) not null,
    password bytea not null
)