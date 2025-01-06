-- Пароль у всех пользоваетелй 'pass1234'
INSERT INTO project_user (id, email, password, role)
VALUES (nextval('project_user_id_seq'), 'example@mail.com', '$2a$10$XBUYbW67T47V0DZk9x1jkO6fUVs7ayYWXp7TVy.RQNBAKjBCi8VaG', 'ROLE_ADMIN'),
       (nextval('project_user_id_seq'), 'test@mail.com', '$2a$10$XBUYbW67T47V0DZk9x1jkO6fUVs7ayYWXp7TVy.RQNBAKjBCi8VaG', 'ROLE_ADMIN'),
       (nextval('project_user_id_seq'), 'ex@mail.com', '$2a$10$XBUYbW67T47V0DZk9x1jkO6fUVs7ayYWXp7TVy.RQNBAKjBCi8VaG', 'ROLE_USER'),
       (nextval('project_user_id_seq'), 'test1@mail.com', '$2a$10$XBUYbW67T47V0DZk9x1jkO6fUVs7ayYWXp7TVy.RQNBAKjBCi8VaG', 'ROLE_USER');
