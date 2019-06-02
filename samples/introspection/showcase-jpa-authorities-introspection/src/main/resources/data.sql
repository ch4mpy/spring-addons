INSERT INTO User(subject) VALUES ('user');
INSERT INTO User(subject) VALUES ('jpa');
INSERT INTO User_Authority(user_subject, authority) VALUES ('user', 'ROLE_USER');
INSERT INTO User_Authority(user_subject, authority) VALUES ('jpa', 'ROLE_USER');
INSERT INTO User_Authority(user_subject, authority) VALUES ('jpa', 'AUTHORIZED_PERSONEL');