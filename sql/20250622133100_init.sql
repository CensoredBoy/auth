-- +goose Up
-- +goose StatementBegin


CREATE TABLE users (
                       id SERIAL PRIMARY KEY,
                       name VARCHAR(255) NOT NULL,
                       password VARCHAR(255) NOT NULL
);

CREATE TABLE roles (
                       id SERIAL PRIMARY KEY,
                       name VARCHAR(255),
                       description VARCHAR(512),
                       is_active BOOLEAN DEFAULT true,
                       created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                       updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                       owner_id INTEGER,
                       FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE permissions (
                             id SERIAL PRIMARY KEY,
                             name VARCHAR(255) NOT NULL,
                             description VARCHAR(512),
                             created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                             updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                             read BOOLEAN DEFAULT false,
                             write BOOLEAN DEFAULT false
);

CREATE TABLE organizations (
                               id SERIAL PRIMARY KEY,
                               project_name VARCHAR(255) NOT NULL,
                               owner_id INTEGER NOT NULL,
                               FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE teams (
                       id SERIAL PRIMARY KEY,
                       team_name VARCHAR(255) NOT NULL,
                       owner_id INTEGER NOT NULL,
                       folder VARCHAR(255),
                       organization_id INTEGER NOT NULL,
                       FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                       FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE users_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE roles_permission_organisation (
    role_id INTEGER NOT NULL,
    organisation_id INTEGER NOT NULL,
    permission_id INTEGER UNIQUE NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (organisation_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
CREATE TABLE roles_permission_team (
   role_id INTEGER NOT NULL,
   team_id INTEGER NOT NULL,
   permission_id INTEGER UNIQUE NOT NULL,
   FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
   FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
   FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE applications (
                              id SERIAL PRIMARY KEY,
                              name VARCHAR(255) NOT NULL,
                              description VARCHAR(512),
                            team_id INTEGER NOT NULL,
                              FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL

);

CREATE TABLE versions (
                                      id SERIAL PRIMARY KEY,
                                      application_id INTEGER NOT NULL,
                                      version VARCHAR(50) NOT NULL,
                                      FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

CREATE TABLE scans (
                       id SERIAL PRIMARY KEY,
                       scan_date DATE NOT NULL DEFAULT CURRENT_DATE,
                       version_id INTEGER NOT NULL,
                       FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE CASCADE
);

CREATE TABLE scan_info (
                           id SERIAL PRIMARY KEY,
                           scan_id INTEGER NOT NULL,
                           FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE scan_rules (
                            id SERIAL PRIMARY KEY,
                            application_id INTEGER NOT NULL,
                            team_id INTEGER NOT NULL,
                            organization_id INTEGER NOT NULL,
                            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
                            FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_organizations_project_name ON organizations(project_name);
CREATE INDEX idx_teams_team_name ON teams(team_name);
CREATE INDEX idx_users_name ON users(name);
CREATE INDEX idx_applications_name ON applications(name);
CREATE INDEX idx_scan_rules_composite ON scan_rules(application_id, team_id, organization_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS scan_rules;
DROP TABLE IF EXISTS scan_info;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS versions;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users_roles;
-- +goose StatementEnd
