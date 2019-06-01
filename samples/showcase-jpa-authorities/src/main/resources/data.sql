INSERT INTO User(subject) VALUES ('user');
INSERT INTO User(subject) VALUES ('admin');
INSERT INTO User_Authority(user_subject, authority) VALUES ('user', 'ROLE_USER');
INSERT INTO User_Authority(user_subject, authority) VALUES ('admin', 'ROLE_USER');
INSERT INTO User_Authority(user_subject, authority) VALUES ('admin', 'showcase:AUTHORIZED_PERSONEL');