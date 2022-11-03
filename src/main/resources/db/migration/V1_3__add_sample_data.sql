insert into users(id, username, email, password) values (1, 'vlad', 'vlad@gmail.com', '$2a$12$1fNqoKQNlYQV7Y8sEMekROm49Iep02bY6UMYTFipEevTwJQ7NraKu');
insert into users(id, username, email, password) values (2, 'ilya', 'ilya@gmail.com', '$2a$12$kKFl5uYSj/1uhLQRRnmnX.jNa2NX7FDHoCyU.k0.UI8hJraX3SZLa');
insert into roles(id, name) values (1, 'USER'), (2, 'ADMIN');
insert into users_to_roles(user_id, role_id) values (1, 1), (1, 2), (2, 1);