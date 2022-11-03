create table if not exists "roles" (
    id bigserial primary key,
    name varchar(30) unique not null
)