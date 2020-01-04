-- tables
-- Table: applications
CREATE TABLE applications (
    id integer NOT NULL CONSTRAINT applications_pk PRIMARY KEY,
    hash blob NOT NULL
);

-- Table: key_pair
CREATE TABLE key_pair (
    id integer NOT NULL CONSTRAINT key_pair_pk PRIMARY KEY,
    encrypted_private_key blob NOT NULL,
    public_key blob NOT NULL
);

-- Table: licenses
CREATE TABLE licenses (
    id integer NOT NULL CONSTRAINT licenses_pk PRIMARY KEY,
    expiration_date date NOT NULL,
    application_id integer NOT NULL,
    user_id integer NOT NULL,
    CONSTRAINT licenses_applications FOREIGN KEY (application_id)
    REFERENCES applications (id),
    CONSTRAINT licenses_users FOREIGN KEY (user_id)
    REFERENCES users (id)
);

-- Table: machine_identifiers
CREATE TABLE machine_identifiers (
    id integer NOT NULL CONSTRAINT machine_identifiers_pk PRIMARY KEY,
    licenses_id integer NOT NULL,
    hash blob NOT NULL,
    CONSTRAINT machine_identifiers_licenses FOREIGN KEY (licenses_id)
    REFERENCES licenses (id)
);

-- Table: users
CREATE TABLE users (
    id integer NOT NULL CONSTRAINT users_pk PRIMARY KEY,
    public_key blob NOT NULL,
    certificate blob NOT NULL
);