create table if not exists "users_to_roles" (
    user_id bigserial not null,
    role_id bigserial not null,
    primary key (user_id, role_id),
    foreign key (role_id) references roles (id),
    foreign key (user_id) references users (id)
)