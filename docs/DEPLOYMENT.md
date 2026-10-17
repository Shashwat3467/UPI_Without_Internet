# Deployment

Use a host with Docker Compose. Copy .env.example to .env, set DATABASE_PASSWORD, then run `docker compose up --build -d`. Check `curl http://localhost:8080/actuator/health` returns UP.

Compose binds the application to localhost. To host it, configure an HTTPS reverse proxy with authentication for the whole demo. The application exposes simulated payment creation and has no user authentication. Choose the hosting account and domain before publishing.

PostgreSQL and private keys use separate persistent volumes. Back up both together. Verify a restore into a separate environment. `docker compose down` preserves volumes; `down -v` destroys them.

For a managed PostgreSQL server set SPRING_PROFILES_ACTIVE=postgres, DATABASE_URL (JDBC format), DATABASE_USER, DATABASE_PASSWORD, and KEY_DIRECTORY. Mount persistent key storage writable by UID 10001. The image runs as a non-root user. On Windows restrict the key directory with an appropriate ACL.

To update, back up both volumes and run `docker compose up --build -d`. Flyway applies migrations on startup. Add new migrations rather than editing an already-applied version. Review dependency and image updates before hosting.

The included CI runs H2 and PostgreSQL tests and builds the image. Its execution requires pushing to GitHub. No hosted deployment has been performed by these files alone.
